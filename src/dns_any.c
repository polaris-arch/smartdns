/* Copyright (C) 2026. GPL-3.0-or-later. */
#include "smartdns/dns_any.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static unsigned int get16(const unsigned char *p) { return ((unsigned int)p[0] << 8) | p[1]; }
static uint32_t get32(const unsigned char *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}
static void put16(unsigned char *p, unsigned int v) { p[0] = v >> 8; p[1] = v; }
static void put32(unsigned char *p, uint32_t v)
{
	p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v;
}

/* Off advances over the encoded name, including only the first compression pointer.
 * Hop and expanded-name bounds reject loops and expansion bombs. */
static int read_name(const unsigned char *data, int len, int *off, char *name)
{
	int pos = *off, end = -1, used = 0, hops = 0;
	while (pos < len && ++hops <= 128) {
		unsigned int n = data[pos++];
		if ((n & 0xc0) == 0xc0) {
			if (pos >= len) return -1;
			int target = ((n & 0x3f) << 8) | data[pos++];
			if (end < 0) end = pos;
			/* RFC compression refers to an earlier occurrence. Disallow forward
			 * pointers so truncation/normalization cannot introduce dependencies. */
			if (target >= pos - 2 || target < 12) return -1;
			pos = target;
			continue;
		}
		if (n & 0xc0) return -1;
		if (n == 0) {
			if (end < 0) end = pos;
			if (name) name[used] = 0;
			*off = end;
			return 0;
		}
		if (pos + (int)n > len || used + (int)n + (used != 0) > 253) return -1;
		if (used && name) name[used] = '.';
		used += used != 0;
		for (unsigned int i = 0; i < n; i++) {
			unsigned char c = data[pos++];
			if (name && (c <= 32 || c >= 127 || c == '.')) return -1;
			if (name) name[used] = c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c;
			used++;
		}
	}
	return -1;
}

static int write_name(unsigned char *out, int cap, const char *name)
{
	int used = 0;
	const char *p = name;
	while (*p) {
		const char *dot = strchr(p, '.');
		size_t n = dot ? (size_t)(dot - p) : strlen(p);
		if (n == 0 || n > 63 || used + (int)n + 2 > cap) return -1;
		out[used++] = n;
		memcpy(out + used, p, n); used += n;
		if (!dot) break;
		p = dot + 1;
	}
	if (used >= cap || used >= 255) return -1;
	out[used++] = 0;
	return used;
}

static int question(const unsigned char *data, int len, const char *domain, int qtype, int *off)
{
	char name[DNS_MAX_CNAME_LEN];
	if (len < 12 || len > DNS_IN_PACKSIZE || get16(data + 4) != 1 ||
		(data[2] & 0xf8) != 0x80 || (data[3] & 0x40)) return -1;
	*off = 12;
	if (read_name(data, len, off, name) != 0 || *off + 4 > len) return -1;
	if (strcasecmp(name, domain) || get16(data + *off) != (unsigned)qtype || get16(data + *off + 2) != DNS_C_IN) return -1;
	*off += 4;
	return 0;
}

/* RFC 7830 padding, RFC 7873 cookies and RFC 7828 keepalive describe this
 * transaction/transport, not the selected DNS view. Never copy them into the
 * synthesized answer. Keep ECS, DNSSEC and unknown extension semantics closed. */
int dns_any_hop_options(const unsigned char *data, int len, int response)
{
	if (len < 0 || len > DNS_IN_PACKSIZE || (!data && len)) return -1;
	for (int off = 0; off < len;) {
		if (len - off < 4) return -1;
		unsigned int code = get16(data + off), size = get16(data + off + 2);
		off += 4;
		if (size > (unsigned int)(len - off)) return -1;
		if (code == DNS_OPT_T_COOKIE) {
			if ((size != 8 || response) && (size < 16 || size > 40)) return -1;
		} else if (code == DNS_OPT_T_TCP_KEEPALIVE) {
			if (size != 2 && (size != 0 || response)) return -1;
		} else if (code != DNS_OPT_T_PADDING) return -1;
		off += size;
	}
	return 0;
}

int dns_any_plain_addresses(const char *domain, int qtype, const unsigned char *wire, int len,
						   unsigned char addresses[DNS_ANY_MAX_RECORDS][DNS_RR_AAAA_LEN])
{
	int off;
	char owner[DNS_MAX_CNAME_LEN];
	if ((qtype != DNS_T_A && qtype != DNS_T_AAAA) || question(wire, len, domain, qtype, &off) ||
		(wire[2] & 2) || (wire[3] & 0x7f)) return -1; /* no TC/Z/AD/CD/error */
	int count = get16(wire + 6), extra = get16(wire + 10);
	int size = qtype == DNS_T_A ? DNS_RR_A_LEN : DNS_RR_AAAA_LEN;
	if (count < 1 || count > DNS_ANY_MAX_RECORDS || get16(wire + 8) || extra > 1) return -1;
	for (int i = 0; i < count; i++) {
		if (read_name(wire, len, &off, owner) || strcasecmp(owner, domain) || off + 10 + size > len ||
			get16(wire + off) != (unsigned int)qtype || get16(wire + off + 2) != DNS_C_IN ||
			get16(wire + off + 8) != (unsigned int)size ||
			!get32(wire + off + 4) || get32(wire + off + 4) > INT_MAX) return -1;
		off += 10;
		memset(addresses[i], 0, DNS_RR_AAAA_LEN);
		memcpy(addresses[i], wire + off, size);
		off += size;
	}
	if (extra) {
		/* Plain empty OPT only. All other additional/authority data remains
		 * valid for ordinary processing but cannot attest this narrow cache. */
		if (read_name(wire, len, &off, owner) || owner[0] || off + 10 > len ||
			get16(wire + off) != DNS_T_OPT || get16(wire + off + 2) < DNS_DEFAULT_PACKET_SIZE ||
			get32(wire + off + 4) || get16(wire + off + 8)) return -1;
		off += 10;
	}
	return off == len ? count : -1;
}

int dns_any_type_from_name(const char *name)
{
	static const struct { const char *name; int type; } supported[] = {
		{"A", DNS_T_A}, {"AAAA", DNS_T_AAAA}, {"NS", DNS_T_NS}, {"CNAME", DNS_T_CNAME},
		{"SOA", DNS_T_SOA}, {"PTR", DNS_T_PTR}, {"MX", DNS_T_MX}, {"TXT", DNS_T_TXT},
		{"SRV", DNS_T_SRV}, {"CAA", DNS_T_CAA}
	};
	for (unsigned int i = 0; i < sizeof(supported) / sizeof(supported[0]); i++) {
		if (strcasecmp(name, supported[i].name) == 0) return supported[i].type;
	}
	return -1;
}

int dns_any_wire_age(unsigned char *data, int len, uint32_t age, uint32_t *minimum)
{
	int off = 12, ordinary = 0, soa_seen = 0;
	uint32_t lowest = UINT32_MAX;
	if (len < 12 || len > DNS_IN_PACKSIZE) return -1;
	for (unsigned int i = 0; i < get16(data + 4); i++) {
		if (read_name(data, len, &off, NULL) != 0 || off + 4 > len) return -1;
		off += 4;
	}
	unsigned int records = get16(data + 6) + get16(data + 8) + get16(data + 10);
	if (records > (unsigned int)len / 11) return -1;
	for (unsigned int i = 0; i < records; i++) {
		if (read_name(data, len, &off, NULL) != 0 || off + 10 > len) return -1;
		int type = get16(data + off), size = get16(data + off + 8);
		uint32_t ttl = get32(data + off + 4);
		if (off + 10 + size > len) return -1;
		if (type != DNS_T_OPT) {
			uint32_t left = ttl > INT_MAX || ttl <= age ? 0 : ttl - age;
			if (age) put32(data + off + 4, left);
			if (left < lowest) lowest = left;
			ordinary++;
			/* Negative lifetimes are additionally capped by SOA.MINIMUM. */
			if (type == DNS_T_SOA && (i >= get16(data + 6) || (data[3] & 15) == DNS_RC_NXDOMAIN)) {
				int p = off + 10;
				if (read_name(data, len, &p, NULL) != 0 || read_name(data, len, &p, NULL) != 0 || p + 20 != off + 10 + size) return -1;
				uint32_t neg = get32(data + p + 16);
				neg = neg > INT_MAX || neg <= age ? 0 : neg - age;
				if (neg < lowest) lowest = neg;
				/* Carry the reduced negative lifetime in the wire TTL so a later
				 * cache insertion cannot restart the original SOA.MINIMUM. */
				if (age && neg < left) put32(data + off + 4, neg);
				soa_seen = 1;
			}
		}
		off += 10 + size;
	}
	if (off != len) return -1;
	if (get16(data + 6) == 0 && !soa_seen) lowest = 0;
	if (minimum) *minimum = ordinary ? lowest : 0;
	return 0;
}

int dns_any_empty_response(const char *domain, int rcode, int tc, unsigned char *out, int capacity)
{
	if (capacity < 17) return -1;
	memset(out, 0, 12);
	out[2] = 0x81 | (tc ? 2 : 0); out[3] = 0x80 | (rcode & 15);
	put16(out + 4, 1);
	int n = write_name(out + 12, capacity - 16, domain);
	if (n < 0) return -1;
	put16(out + 12 + n, DNS_T_ANY); put16(out + 14 + n, DNS_C_IN);
	return 16 + n;
}

struct any_rr {
	char owner[DNS_MAX_CNAME_LEN];
	unsigned short type, size;
	uint32_t ttl;
	unsigned char data[1024];
};
struct any_records {
	struct any_rr rr[DNS_ANY_MAX_RECORDS];
	int count;
};

static int copy_name(const unsigned char *data, int len, int *off, unsigned char *out, int cap)
{
	char name[DNS_MAX_CNAME_LEN];
	if (read_name(data, len, off, name) != 0) return -1;
	return write_name(out, cap, name);
}

static int parse_rr(const unsigned char *data, int len, int *off, uint32_t age, struct any_rr *rr)
{
	if (read_name(data, len, off, rr->owner) != 0 || *off + 10 > len) return -1;
	rr->type = get16(data + *off);
	if (get16(data + *off + 2) != DNS_C_IN) return -1;
	uint32_t ttl = get32(data + *off + 4);
	rr->ttl = ttl > INT_MAX || ttl <= age ? 0 : ttl - age;
	int size = get16(data + *off + 8), start = *off + 10, p = start, n = 0, prefix = 0;
	if (start + size > len || size > (int)sizeof(rr->data)) return -1;
	switch (rr->type) {
	case DNS_T_A: if (size != 4) return -1; break;
	case DNS_T_AAAA: if (size != 16) return -1; break;
	case DNS_T_TXT:
		while (p < start + size) { int l = data[p++]; if (p + l > start + size) return -1; p += l; }
		if (!size) return -1;
		break;
	case DNS_T_CAA: if (size < 2 || data[start + 1] + 2 > size) return -1; break;
	case DNS_T_MX: prefix = 2; goto name_data;
	case DNS_T_SRV: prefix = 6; goto name_data;
	case DNS_T_NS: case DNS_T_PTR: case DNS_T_CNAME:
name_data:
		if (size < prefix + 1) return -1;
		memcpy(rr->data, data + start, prefix); p += prefix;
		n = copy_name(data, len, &p, rr->data + prefix, sizeof(rr->data) - prefix);
		if (n < 0 || p != start + size) return -1;
		rr->size = prefix + n; *off = p; return 0;
	case DNS_T_SOA: {
		int n1 = copy_name(data, len, &p, rr->data, sizeof(rr->data));
		if (n1 < 0) return -1;
		int n2 = copy_name(data, len, &p, rr->data + n1, sizeof(rr->data) - n1);
		if (n2 < 0 || p + 20 != start + size || n1 + n2 + 20 > (int)sizeof(rr->data)) return -1;
		memcpy(rr->data + n1 + n2, data + p, 20);
		rr->size = n1 + n2 + 20; *off = p + 20; return 0;
	}
	default: return -1;
	}
	memcpy(rr->data, data + start, size); rr->size = size; *off = start + size;
	return 0;
}

static int add_rr(struct any_records *dest, const struct any_rr *rr)
{
	for (int i = 0; i < dest->count; i++) {
		struct any_rr *old = &dest->rr[i];
		if (strcmp(old->owner, rr->owner)) continue;
		if ((old->type == DNS_T_CNAME) != (rr->type == DNS_T_CNAME)) return -1;
		if (old->type != rr->type) continue;
		if (old->size == rr->size && !memcmp(old->data, rr->data, rr->size)) {
			if (rr->ttl < old->ttl) old->ttl = rr->ttl;
			return 0;
		}
		if (rr->type == DNS_T_CNAME || rr->type == DNS_T_SOA) return -1;
	}
	if (dest->count >= DNS_ANY_MAX_RECORDS) return -1;
	dest->rr[dest->count++] = *rr;
	return 0;
}

static int rr_target(const struct any_rr *rr, char *name)
{
	/* Normalized names contain no compression pointers. Offset 0 is intentional. */
	int off = 0;
	return read_name(rr->data, rr->size, &off, name);
}

static int validate_chain(const struct any_records *records, const char *domain, int qtype,
						  char chain[DNS_ANY_MAX_ALIAS + 1][DNS_MAX_CNAME_LEN], int *depth, int *positive)
{
	strncpy(chain[0], domain, DNS_MAX_CNAME_LEN - 1);
	*depth = 0; *positive = 0;
	for (;;) {
		const struct any_rr *alias = NULL;
		for (int i = 0; i < records->count; i++) {
			const struct any_rr *rr = &records->rr[i];
			if (rr->type == DNS_T_CNAME && !strcmp(rr->owner, chain[*depth])) { alias = rr; break; }
		}
		if (!alias) break;
		if (*depth >= DNS_ANY_MAX_ALIAS || rr_target(alias, chain[*depth + 1]) != 0) return -1;
		for (int i = 0; i <= *depth; i++) if (!strcmp(chain[i], chain[*depth + 1])) return -1;
		(*depth)++;
	}
	for (int i = 0; i < records->count; i++) {
		const struct any_rr *rr = &records->rr[i];
		if (rr->type == DNS_T_CNAME) {
			int found = 0;
			for (int j = 0; j < *depth; j++) if (!strcmp(rr->owner, chain[j])) found = 1;
			if (!found) return -1;
			if (qtype == DNS_T_CNAME && !strcmp(rr->owner, domain)) *positive = 1;
		} else {
			if (rr->type != qtype || strcmp(rr->owner, chain[*depth])) return -1;
			*positive = 1;
		}
	}
	return 0;
}

static int zone_contains(const char *zone, const char *name)
{
	size_t z = strlen(zone), n = strlen(name);
	return z == 0 || (n >= z && !strcmp(name + n - z, zone) && (n == z || name[n - z - 1] == '.'));
}

static int output_rr(unsigned char *out, int capacity, int *off, const struct any_rr *rr)
{
	int n = write_name(out + *off, capacity - *off, rr->owner);
	if (n < 0 || *off + n + 10 + rr->size > capacity) return -1;
	*off += n;
	put16(out + *off, rr->type); put16(out + *off + 2, DNS_C_IN);
	put32(out + *off + 4, rr->ttl); put16(out + *off + 8, rr->size);
	memcpy(out + *off + 10, rr->data, rr->size); *off += 10 + rr->size;
	return 0;
}

int dns_any_merge(const char *domain, const struct dns_any_input *input, int count, int partial,
				  unsigned char *out, int capacity)
{
	struct any_records *merged = calloc(1, sizeof(*merged)), *child = calloc(1, sizeof(*child));
	struct any_rr soa = {0};
	char expected[DNS_ANY_MAX_ALIAS + 1][DNS_MAX_CNAME_LEN] = {{0}};
	int expected_depth = -1, positive_count = 0, negatives = 0, nxdomain = 0, failures = 0;
	int ret = -1;
	if (!merged || !child || count < 1 || count > 8 || capacity > DNS_IN_PACKSIZE) goto out;
	for (int i = 0; i < count; i++) {
		const struct dns_any_input *in = &input[i];
		int off, has_soa = 0, positive = 0, depth = 0, invalid = 0, opt_seen = 0;
		struct any_rr child_soa = {0};
		char chain[DNS_ANY_MAX_ALIAS + 1][DNS_MAX_CNAME_LEN] = {{0}};
		child->count = 0;
		if (!in->data || question(in->data, in->len, domain, in->qtype, &off) || (in->data[2] & 2)) { failures++; continue; }
		int rcode = in->data[3] & 15;
		if (rcode != DNS_RC_NOERROR && rcode != DNS_RC_NXDOMAIN) { failures++; continue; }
		int answers = get16(in->data + 6), authority = get16(in->data + 8), extra = get16(in->data + 10);
		if (answers > DNS_ANY_MAX_RECORDS || authority + extra > DNS_ANY_MAX_RECORDS) { failures++; continue; }
		for (int j = 0; j < answers; j++) {
			struct any_rr rr;
			if (parse_rr(in->data, in->len, &off, in->age, &rr) || (rr.type != in->qtype && rr.type != DNS_T_CNAME)) { invalid = 1; break; }
			if (add_rr(child, &rr)) goto out;
		}
		if (invalid) { failures++; continue; }
		for (int j = 0; j < authority + extra; j++) {
			int start = off;
			char owner[DNS_MAX_CNAME_LEN];
			if (read_name(in->data, in->len, &off, owner) || off + 10 > in->len) { invalid = 1; break; }
			int type = get16(in->data + off), size = get16(in->data + off + 8);
			if (off + 10 + size > in->len) { invalid = 1; break; }
			if (type == DNS_T_OPT && (j < authority || opt_seen++ || owner[0] ||
				get32(in->data + off + 4) != 0 ||
				dns_any_hop_options(in->data + off + 10, size, 1))) { invalid = 1; break; }
			if (j < authority && type == DNS_T_SOA) {
				off = start;
				if (has_soa || parse_rr(in->data, in->len, &off, in->age, &child_soa)) { invalid = 1; break; }
				uint32_t negative = get32(child_soa.data + child_soa.size - 4);
				negative = negative > INT_MAX || negative <= in->age ? 0 : negative - in->age;
				if (negative < child_soa.ttl) child_soa.ttl = negative;
				has_soa = 1;
			} else off += 10 + size;
		}
		if (invalid || off != in->len) { failures++; continue; }
		if (validate_chain(child, domain, in->qtype, chain, &depth, &positive)) goto out;
		/* A successful child must contain its answer or a real SOA-backed negative.
		 * An incomplete CNAME chain is never followed outside the parent budget. */
		if (!positive && !has_soa) { failures++; continue; }
		if (!positive && !zone_contains(child_soa.owner, chain[depth])) goto out;
		if (rcode == DNS_RC_NXDOMAIN && positive) goto out;
		if (expected_depth < 0) { expected_depth = depth; memcpy(expected, chain, sizeof(expected)); }
		else {
			if (expected_depth != depth) goto out;
			for (int j = 0; j <= depth; j++) if (strcmp(expected[j], chain[j])) goto out;
		}
		if (rcode == DNS_RC_NXDOMAIN) nxdomain++;
		if (positive) positive_count++;
		else {
			negatives++;
			if (soa.size && (strcmp(soa.owner, child_soa.owner) || soa.size != child_soa.size || memcmp(soa.data, child_soa.data, soa.size))) goto out;
			if (!soa.size) soa = child_soa;
			else if (child_soa.ttl < soa.ttl) soa.ttl = child_soa.ttl;
		}
		for (int j = 0; j < child->count; j++) if (add_rr(merged, &child->rr[j])) goto out;
	}
	if (nxdomain && (positive_count || negatives != nxdomain)) goto out;
	if ((!partial && failures) || (!positive_count && (failures || !negatives))) goto out;
	ret = dns_any_empty_response(domain, nxdomain ? DNS_RC_NXDOMAIN : DNS_RC_NOERROR, 0, out, capacity);
	if (ret < 0) goto out;
	for (int i = 0; i < merged->count; i++) if (output_rr(out, capacity, &ret, &merged->rr[i])) { ret = -1; goto out; }
	put16(out + 6, merged->count);
	if (!positive_count && soa.size) {
		if (output_rr(out, capacity, &ret, &soa)) { ret = -1; goto out; }
		put16(out + 8, 1);
	}
out:
	free(merged); free(child);
	return ret;
}
