# Logical upstream IP pools

IP pooling is opt-in. Without `-upstream-ip-pool`, ordinary upstream selection and
server-group fanout retain their existing behavior. A pool is one logical upstream
in its groups and one row in the native upstream dashboard; its addresses are not
separate providers. Never use pooling to multiply a provider's quota.

## Configuration

Explicit addresses (deduplicated, first occurrence order):

```
server-https https://dns.example/dns-query -upstream-ip-pool -host-ip 192.0.2.10,192.0.2.11
```

Automatic A/AAAA discovery uses a separately configured bootstrap group:

```
server 192.0.2.53 -bootstrap-dns
server-https https://dns.example/dns-query -upstream-ip-pool -max-upstream-backends 6
```

These documentation addresses are placeholders, not working resolvers. The domain,
TLS verification name, SNI, HTTP Host and path remain the configured authority.
Private/ULA and loopback upstreams are permitted; an address matching this
SmartDNS instance's listener address, port and underlying transport is rejected.
Unspecified and multicast targets are not valid backends. Automatic bootstrap
queries cannot fall back to the service being discovered or inherit user ECS.
Every bootstrap declaration must resolve to a numeric destination directly in the
configuration; unresolved hostname, proxy, mDNS and pool bootstrap declarations
are rejected before startup. A silent bootstrap is retried through other members
of that same explicit group within the fixed deadline, never default/fallback.
Proxy-based pools and bootstrap pool declarations are not supported in this version.

`-max-upstream-backends` is 1–64, default 4. The selected count is the actual usable
address count bounded by this cap, never an implicit two or padded four. Static
lists can contain up to 64 literals; excess candidates remain available but do
not create extra active endpoints. Automatic discovery retains unchanged members
and fills open slots in canonical, family-interleaved order. A family response
exceeding its bounded discovery capacity is rejected rather than silently trusted
as a complete truncated RRset.

`-max-upstream-connections` optionally imposes a separate, lower physical socket
cap (1–backend cap). When omitted the limit tracks selected members. Connecting
and draining sockets consume slots; idle sockets may be replaced to serve another
member, but active requests and partial frames are never evicted for rotation.
A membership shrink stops new admission immediately; already admitted old sockets
can briefly drain within the previous bounded allocation, without granting new
connection capacity. Backend count does not mean concurrent DNS query count.

Existing `-max-query-rate`, `-query-burst`, `-max-concurrent-queries` apply to the
whole service, not each IP. No rate is invented when rate limiting is absent.
`-quota-group` is optional and only needed to share provider quota/cooldown across
separately configured logical services. HTTP 429/503 cooldown and its single
recovery probe remain shared; endpoint transport failure only backs off that
endpoint. Round robin advances on actual positive request writes, not on an
attempt to connect, a random choice, or a race.

## Discovery lifecycle

DNS TTL controls refreshing and admission. Unchanged addresses keep their
connections and identities. Removed/negative addresses stop new admission
immediately and old work drains for a bounded interval. A trustworthy negative
response does not extend the previous positive lifetime. TTL zero does not create
cached members. Transient discovery failures alone may retain previous members
for at most 60 seconds beyond positive expiry; empty/negative/invalid answers are
not treated as transient success. No permanent public/private scope lock is
introduced, so legitimate VPN/split-DNS changes continue to work.

## Older round-robin syntax

There is no second legacy runtime scheduler. Loading compatible explicit
`-upstream-round-robin` declarations normalizes them to one service and warns.
The original domain authority, protocol/port, security/ECS/bind configuration,
exact routing-group set, quota/rate/burst and effective connection cap must agree.
The old omitted connection cap remains an explicit two during normalization;
normalization does not increase resource limits or invent a rate. Nonzero old
per-endpoint concurrency, ambiguous authorities, different group intersections,
proxies, bootstrap declarations and conflicting settings require an explicit
single-line migration. Validation fails before runtime configuration is committed.
Do not merge unrelated services merely because they share a quota-group name.

## Observability and capability

`smartdns -v` advertises `features: smartdns-upstream-service-pool-v1`. Editors must
check this exact capability before enabling or writing pool options; a version
string alone is insufficient. Old binaries remain usable for ordinary upstreams.

The native `/api/upstream-server` response retains its old fields, but a pool row
uses service counters. It also exposes `service_id`, `config_identity`, pool and
backend metadata. The opaque stable ID hashes authority, security/routing identity,
not current IP membership or resource limits. Identical duplicate logical
identities are rejected; distinct routing identities are not silently merged.
Security secrets are not returned in config identity. Endpoint diagnostics are an
API, not a newly introduced frontend expansion widget.

For pools, `query = success + failure + skip + in_flight`. Query counts logical
work considered by this service; attempt counts positive request writes. A valid
accepted NOERROR/NXDOMAIN response is success; no-send terminal work is skip.
Service latency measures first send to accepted response, including retries.
Attempt RTT samples exclude ambiguous retransmissions (including reused UDP SID);
missing samples are not zero latency. Ordinary non-pool rows retain their labelled
legacy metric semantics rather than being synthesized into service statistics.

See [the detailed design](upstream-service-pool-design.md) for state/ownership and
acceptance requirements. Performance claims require isolated CI measurements;
correctness fixture durations are not benchmarks.

The packaged native dashboard includes a source-owned compatibility patch against
pinned upstream webui source. The current upstream page shows
authority and the real endpoint IP list in the same single service row. No legacy overview-card patch is retained: that card is not mounted by the
pinned dashboard route, and no widget is added just to satisfy the test. The REST `ip` field remains a
physical address (empty for multi-address pools), never a domain/ID label.
Builds reject mismatched source/patches and cannot reuse an unverified old dashboard.
See `package/webui/README.md` for the matched OpenWrt/build contract.

Freshness JSON uses `freshness_status` plus nullable `freshness_remaining_ms`:
static pools are `non_expiring`/null; automatic membership with a known expiry is
`finite`/milliseconds (0 after expiry); cold or empty discovery is `unknown`/null;
ordinary upstreams are `not_applicable`/null. Negative-answer retry TTL is not
reported as positive backend freshness. No huge infinity integer is exposed.
