#define _GNU_SOURCE
#include "dns_client.h"
#include "upstream_service.h"
#include "egress_contract.h"
#include "smartdns/dns_conf.h"
#include "smartdns/util.h"
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>

struct egress_record { char interface[16], session[65]; unsigned index, families; };
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static struct egress_record records[127];
static unsigned count;
static uint64_t epoch = 1, next_read, deadline;
static char last_path[DNS_MAX_PATH];
/* All refreshes hold lock, including reads from transport callbacks. Keep the
 * bounded parsing workspace off those nested client-thread stacks. */
static struct egress_record fresh[127];
static char bytes[32769];

#ifdef TEST
uint64_t (*_dns_egress_test_now)(void);
#endif
uint64_t _dns_egress_now(void)
{
#ifdef TEST
    if(_dns_egress_test_now)return _dns_egress_test_now();
#endif
    struct timespec now;
    if(clock_gettime(CLOCK_MONOTONIC,&now))return 0;
    return (uint64_t)now.tv_sec*UINT64_C(1000)+(uint64_t)now.tv_nsec/UINT64_C(1000000);
}
/* Bounded local read. Missing, expired, foreign-owned and malformed contracts
 * revoke admission; no automatic fallback to another interface or policy. */
static void refresh_locked(void)
{
    uint64_t now = _dns_egress_now();
    const char *path = dns_conf.upstream_egress_contract;
    if (!strcmp(last_path, path) && now < next_read && (!count || now < deadline)) return;
    next_read = now + 250;
    safe_strncpy(last_path, path, sizeof(last_path));
    memset(fresh, 0, sizeof(fresh));
    unsigned n = 0;
    if (!path[0]) goto publish;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) goto publish;
    struct stat st;
    ssize_t size = -1;
    if (!fstat(fd, &st) && S_ISREG(st.st_mode) && st.st_uid == 0 && !(st.st_mode & 022) &&
        st.st_size > 0 && st.st_size < (off_t)sizeof(bytes))
        size = read(fd, bytes, sizeof(bytes) - 1);
    close(fd);
    if (size <= 0 || size != st.st_size || memchr(bytes, 0, size)) goto publish;
    bytes[size] = 0;
    char *save = NULL, *line = strtok_r(bytes, "\n", &save);
    char magic[32], boot[40], actual_boot[40] = {0}, extra;
    unsigned mark;
    unsigned long long expires;
    if (!line || sscanf(line, "%31s %x %llu %39s %c", magic, &mark, &expires, boot, &extra) != 4 ||
        strcmp(magic, "smartdns-egress-v1") || mark != DNS_EGRESS_MARK || expires <= now || expires - now > 30000)
        goto publish;
    FILE *boot_file = fopen("/proc/sys/kernel/random/boot_id", "re");
    if (!boot_file) goto publish;
    int valid_boot = fgets(actual_boot, sizeof(actual_boot), boot_file) != NULL;
    fclose(boot_file);
    actual_boot[strcspn(actual_boot, "\n")] = 0;
    if (!valid_boot || strcmp(boot, actual_boot)) goto publish;
    deadline = expires;
    while ((line = strtok_r(NULL, "\n", &save))) {
        if (n == 127 || sscanf(line, "%15s %u %64s %u %c", fresh[n].interface,
            &fresh[n].index, fresh[n].session, &fresh[n].families, &extra) != 4 ||
            !fresh[n].index || !fresh[n].families || fresh[n].families > 3 || strlen(fresh[n].session) != 64)
            goto invalid;
        for (unsigned i = 0; fresh[n].session[i]; i++) if (!isxdigit((unsigned char)fresh[n].session[i])) goto invalid;
        for (unsigned i = 0; fresh[n].interface[i]; i++)
            if (!isalnum((unsigned char)fresh[n].interface[i]) && !strchr("_.:-", fresh[n].interface[i])) goto invalid;
        for (unsigned i = 0; i < n; i++)
            if (!strcmp(fresh[i].interface, fresh[n].interface) || fresh[i].index == fresh[n].index) goto invalid;
        n++;
    }
    goto publish;
invalid:
    n = 0;
publish:
    /* Renewal changes the deadline, not endpoint identity. */
    if (count != n || memcmp(records, fresh, n * sizeof(*records))) {
        memset(records, 0, sizeof(records)); memcpy(records, fresh, n * sizeof(*records));
        count = n; epoch++;
    }
}
uint64_t _dns_egress_epoch(void)
{
    pthread_mutex_lock(&lock); refresh_locked(); uint64_t value = epoch;
    pthread_mutex_unlock(&lock); return value;
}
void _dns_egress_invalidate(void)
{
    pthread_mutex_lock(&lock); next_read = 0; pthread_mutex_unlock(&lock);
}
static int lookup(const char *interface, int family, long long configured_mark,
    unsigned *mark, char session[65], unsigned *index)
{
    session[0] = 0;
    *mark = configured_mark < 0 ? 0 : (unsigned)configured_mark;
    if (!dns_conf.upstream_egress_contract[0] || !interface[0]) return 0;
    if (*mark && *mark != DNS_EGRESS_MARK) { errno = EINVAL; return -1; }
    pthread_mutex_lock(&lock); refresh_locked();
    int found = 0;
    for (unsigned i = 0; i < count; i++) {
        if (strcmp(interface, records[i].interface) || !(records[i].families & (family == AF_UNSPEC ? 3 : family == AF_INET6 ? 2 : 1))) continue;
        if (if_nametoindex(interface) != records[i].index) continue;
        safe_strncpy(session, records[i].session, 65); *mark = DNS_EGRESS_MARK; if(index) *index=records[i].index; found = 1; break;
    }
    pthread_mutex_unlock(&lock);
    if (!found) { errno = ENETDOWN; return -1; }
    return 1;
}
int _dns_egress_lease(const char *interface,int family,long long configured_mark,unsigned *mark,char session[65])
{ return lookup(interface,family,configured_mark,mark,session,NULL); }
static int managed(const struct dns_server_info *server)
{
    /* Adoption is an upstream WAN policy, never inferred from LAN/mDNS binding. */
    return dns_conf.upstream_egress_contract[0] && server->type != DNS_SERVER_MDNS &&
        server->service && server->service->egress_contract && server->flags.ifname[0];
}
#ifdef TEST
void (*_dns_egress_before_bind)(void);
#endif
#ifndef SO_BINDTOIFINDEX
#define SO_BINDTOIFINDEX 62
#endif
static int reject(struct dns_server_info *server)
{
    server->egress_revoked=1;server->service_normal_close=1;
    return -1;
}
int _dns_socket_prepare(struct dns_server_info *server,int fd)
{
    unsigned mark=server->so_mark<0?0:(unsigned)server->so_mark,index=0;
    char session[65]={0};
    int contract=managed(server)?lookup(server->flags.ifname,server->ai_family,server->so_mark,&mark,session,&index):0;
    if(contract<0)return reject(server);
    if(contract && server->egress_session[0] && strcmp(server->egress_session,session)){errno=ESTALE;return reject(server);}
#ifdef TEST
    if(_dns_egress_before_bind)_dns_egress_before_bind();
#endif
    if(contract){
        if(setsockopt(fd,SOL_SOCKET,SO_BINDTOIFINDEX,&index,sizeof(index)))return reject(server);
    }else if(server->flags.ifname[0] && setsockopt(fd,SOL_SOCKET,SO_BINDTODEVICE,server->flags.ifname,strlen(server->flags.ifname)+1))return -1;
    if((contract || server->so_mark>=0) && setsockopt(fd,SOL_SOCKET,SO_MARK,&mark,sizeof(mark)))return contract?reject(server):-1;
    if(contract){
        unsigned actual=0,again_index=0,again_mark=0;socklen_t size=sizeof(actual);char again[65];
        if(getsockopt(fd,SOL_SOCKET,SO_BINDTOIFINDEX,&actual,&size) || actual!=index ||
            lookup(server->flags.ifname,server->ai_family,server->so_mark,&again_mark,again,&again_index)<1 ||
            again_index!=index || strcmp(again,session)){errno=ESTALE;return reject(server);}
        size=sizeof(actual);
        if(getsockopt(fd,SOL_SOCKET,SO_MARK,&actual,&size) || actual!=mark){errno=EACCES;return reject(server);}
        safe_strncpy(server->egress_session,session,sizeof(server->egress_session));
    }
    server->egress_revoked=0;return 0;
}
int _dns_egress_socket_current(struct dns_server_info *server)
{
    if(!managed(server))return 1;
    unsigned mark;char session[65];
    pthread_mutex_lock(&server->lock);
    int current=lookup(server->flags.ifname,server->ai_family,server->so_mark,&mark,session,NULL)>0 &&
        server->egress_session[0] && !strcmp(session,server->egress_session);
    pthread_mutex_unlock(&server->lock);return current;
}
int _dns_egress_io_allowed(struct dns_server_info *server)
{
    if(!managed(server))return 1;
    pthread_mutex_lock(&server->lock);
    int allowed=!server->egress_revoked && _dns_egress_socket_current(server);
    if(!allowed){server->egress_revoked=1;server->service_normal_close=1;errno=ENETDOWN;}
    pthread_mutex_unlock(&server->lock);return allowed;
}
