/* Bounded ANY configuration: no implicit record-type enumeration. */
#include "any.h"
#include "dns_conf_group.h"
#include "smartdns/dns_any.h"
#include "smartdns/tlog.h"
#include <string.h>
#include <stddef.h>
#include <strings.h>

int _config_any_mode(void *data, int argc, char *argv[])
{
	struct dns_conf_group *group = _config_current_rule_group();
	if (group == NULL || argc != 2) return -1;
	if (strcmp(argv[1], "passthrough") == 0) group->any.aggregate = 0;
	else if (strcmp(argv[1], "aggregate") == 0) group->any.aggregate = 1;
	else return -1;
	return 0;
}

int _config_any_types(void *data, int argc, char *argv[])
{
	struct dns_conf_group *group = _config_current_rule_group();
	unsigned short types[DNS_ANY_MAX_TYPES] = {0};
	char value[128], *cursor, *token;
	int count = 0;
	if (group == NULL || argc != 2 || strlen(argv[1]) >= sizeof(value)) return -1;
	strcpy(value, argv[1]);
	cursor = value;
	while ((token = strsep(&cursor, ",")) != NULL) {
		int type = dns_any_type_from_name(token);
		if (type < 0 || count >= DNS_ANY_MAX_TYPES) return -1;
		for (int i = 0; i < count; i++) if (types[i] == type) return -1;
		types[count++] = type;
	}
	if (count == 0) return -1;
	memcpy(group->any.types, types, sizeof(types));
	group->any.type_count = count;
	return 0;
}

int _config_any_verify(void)
{
	struct dns_conf_group *group;
	unsigned long bucket;
	hash_for_each(dns_conf_rule.group, bucket, group, node) {
		if (group->any.aggregate && group->any.type_count == 0) {
			tlog(TLOG_ERROR, "any-response-mode aggregate requires any-aggregate-types in group %s", group->group_name);
			return -1;
		}
	}
	return 0;
}

int _config_any_number(void *data, int argc, char *argv[])
{
	struct dns_conf_group *group = _config_current_rule_group();
	unsigned int value = 0;
	int maximum;
	if (!group || argc != 2 || !argv[1][0]) return -1;
	size_t offset = (size_t)data;
	if (offset == offsetof(struct dns_conf_group, any.concurrency)) maximum = 8;
	else if (offset == offsetof(struct dns_conf_group, any.max_attempts)) maximum = 64;
	else if (offset == offsetof(struct dns_conf_group, any.timeout_ms)) maximum = 950;
	else return -1;
	for (const char *p = argv[1]; *p; p++) {
		if (*p < '0' || *p > '9' || value > (unsigned int)maximum / 10) return -1;
		value = value * 10 + (*p - '0');
		if (value > (unsigned int)maximum) return -1;
	}
	if (!value) return -1;
	*(int *)((char *)group + offset) = value;
	return 0;
}

int _config_any_partial(void *data, int argc, char *argv[])
{
	struct dns_conf_group *group = _config_current_rule_group();
	if (!group || argc != 2) return -1;
	if (!strcasecmp(argv[1], "yes")) group->any.partial = 1;
	else if (!strcasecmp(argv[1], "no")) group->any.partial = 0;
	else return -1;
	return 0;
}
