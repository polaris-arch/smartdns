# SmartDNS logical upstream service / backend pool — design candidate v14

Status: implementation freeze candidate; prior model reviewed, core v3 independently reviewed; v14 Rust/API/native-dashboard delta awaiting independent dots review. Not release approval.
Author executor: dots cloud workspace, not the user's local Codex computer.
Source inspected: workspace HEAD f8b3563477a72a3d38c5ec8c05db8267df4ad658; tree
5dda182293c37e4a49df92f37f037cdf485d2a5d, identical to supplied released mainline
32d31237bf4502817ebb66845a984f8dcc4c7227. Preserve existing untracked test/rr-offline.bin.
No production changes or automatic activation. Latest user revision supersedes
previous live-state notes: user has rolled back their configuration. Do not restore
the two RR declarations. User explicitly authorizes the bounded network-center
parser/generator/editor/statistics adaptation and requires old coarse RR scheduling
to retire: one service runtime, not permanent old/new parallel RR engines.

## 1. Decision and invariant

A configured upstream is a **service**, not a set of public server declarations.
A service owns its authority, transport semantics, configured routing groups,
policy, discovery lifecycle and cumulative counters. Its bounded endpoints own
addresses, health, sockets and transport streams. DNS group fanout selects services;
a pool service selects exactly one backend per attempt. One query never races two
backends of that service. Other providers retain their original fanout.

The service exists with zero endpoints (discovering/unavailable) and survives all
address changes. It is not a special endpoint kept alive as a fake representative.
An IP change must not reset its rate bucket, cooldown epoch, recovery probe, counters
or service identifier. A logical query retry does not become a new service query.

## 2. Configuration, compatibility, bounded selection

Proposed syntax (names subject to independent review):

```
# Existing behavior is unchanged without the new opt-in.
server-https https://resolver.example/dns-query

# DNS-discovered pool; one service row. No quota-group required.
server-https https://resolver.example/dns-query -upstream-ip-pool \
    -max-query-rate 10 -query-burst 2

# Operator-authoritative, static pool; no DNS discovery/refresh or union.
server-https https://resolver.example/dns-query -upstream-ip-pool \
    -host-ip 192.0.2.10,192.0.2.11,2001:db8::10

# Optional total physical connection cap, not number of backend IPs.
server-https https://resolver.example/dns-query -upstream-ip-pool \
    -host-ip 192.0.2.10,192.0.2.11,192.0.2.12 -max-upstream-connections 2
```

Documentation-only example addresses. Existing rate/burst values are examples,
not provider defaults. No new implicit provider rate. No fixed backend count or
implicit two-connection default in the new mode. Latest user revision: backend cap
is configurable, default 4, not hardwired 4. `-max-upstream-backends N` accepts
1..64 (proposed safety ceiling, independently reviewed); effective endpoint count is
min(eligible unique inputs, N). There is no extra enable toggle beyond the pool
switch. With physical cap unspecified its ceiling follows selected membership
count (0..N); each endpoint has at most one transport. Existing advanced
`-max-upstream-connections M` in new pool mode accepts 1..64 and must be <=N; old-syntax compatibility parser accepts 1..4/default 2 before normalization;
there is no legacy RR runtime. It may reduce simultaneous connections but
never creates extra connections per IP. Membership shrink can leave draining old
connections above the new *target*, but total live/connecting/draining never exceeds
its previously admitted ceiling or configured M/N; no new slot until below target. Endpoint slots and connecting/connected socket counts are
separately reported.

`-upstream-ip-pool` is explicit and off by default. New mode supports the six
unicast transports (UDP/TCP/TLS/HTTPS/QUIC/HTTP3), never mDNS. Domain authority is
mandatory in this initial pool interface: explicit IP-only upstreams remain legacy.
SNI, certificate verification name, HTTP Host/path, ALPN, ECS, marks, interface,
fallback and answer flags belong to the service, never inferred from selected IP.

`-host-ip` is a comma-delimited list of bare numeric IPv4/IPv6 literals, no ports,
brackets, hostnames, empty elements or scoped addresses. Normalize mapped IPv6 to
IPv4 and deduplicate by binary address/family. Order of unique explicit inputs is
stable RR order. Parse at most 64 unique explicit addresses (more is a configuration error).
When input exceeds configured backend cap, select first N unique addresses in user
order and report configured/selected/overflow counts plus a startup warning; never
silently truncate. The unused static addresses remain candidates for explicit cap
changes, not hidden failover additions beyond the cap. Without opt-in one literal retains current behavior; lists are
errors (not a feature auto-enable). Repeated `-host-ip` in new mode is an error to
avoid silent last-write-wins; legacy repeated behavior is preserved. Explicit
private/unicast loopback addresses are operator-authorized; multicast/unspecified
are always invalid. Explicit addresses do not silently fall back to discovered ones.

For discovered results >configured cap: filter first, retain all existing accepted members that
remain present, then fill vacancies in canonical binary order interleaving IPv4 and
IPv6 (IPv4 first on initial equal choice). Retention takes precedence over family
balance. Never select by fastest response, DNS RR order, randomness or hash race.
Expose discovered/eligible/selected/overflow counts. This makes resolver RRset
reordering a no-op. Family unusability is determined by explicit transport/interface
capability, not client-query qtype or a transient IPv6 ping. A bound interface applies
to every endpoint; incompatible literal family is config error if known statically,
otherwise endpoint-local connect failure/backoff. No new family option is needed
in this batch: explicit lists can constrain family; auto mode requests A and AAAA.

New pool + proxy is rejected with a clear error in v1. Existing proxy behavior is
unchanged. Remote-resolution proxy and local endpoint selection are not equivalent;
support must wait for a separately verified numeric-target proxy contract. New
pool cannot also be bootstrap DNS or use legacy `-upstream-round-robin`; mixed modes
are rejected rather than sharing ambiguous cursor state.

Optional quota-group shares provider quota across explicit services, but is not the
service identifier. All members must agree on rate/burst. Cross-service shared
cooldown/one-probe still applies. Service RR cursors and stats stay separate; policy
registry must no longer confuse an explicit quota group with a service object.
An ungrouped pool receives its own policy directly, not an externally collidable
synthetic quota-group string. Legacy RR declarations have only the bounded syntax-migration layer in §6; the
old quota-group-as-service scheduler/cursor/statistics implementation is removed.
Non-RR legacy declarations may share a quota policy with a pool if all shared quota
fields agree; concurrent limits remain service-specific and explicitly reported.

## 3. Concrete ownership and scheduling architecture

New `dns_upstream_service` (refcounted) holds immutable config identity, ordered
membership generation, group links, shared-policy reference, actual-send cursor,
one uncommitted-turn lease, discovery state, service active-attempt count and stats.
Existing `dns_server_info` becomes an endpoint with an optional service pointer;
ordinary non-RR endpoints keep their old fanout path. Legacy RR syntax is
normalized before runtime or rejected; it never constructs an old RR scheduler. Do not duplicate SSL/HTTP/QUIC transport code.
Group members become tagged legacy-endpoint/service references. Queries snapshot
and pin group targets under global list lock, then release it before all network IO.
Budget fanout cardinality counts each pool once, never each IP, across selected
and fallback group snapshot. Snapshot once at query creation: discovery additions
and backend failover never enlarge that query's fixed parent send budget.

Service ID is a deterministic opaque digest of normalized authority+port+transport+
path and full semantic configuration (including group membership), excluding
addresses, DNS TTLs and mutable state. Identical declarations deduplicate or fail
explicitly; do not create independent rate allowances accidentally. An explicit
`quota-group` remains an additional shared quota identity, never display grouping
by bare domain alone (different paths/proxies/transports need not be one service).
Reload/restart resets counters in the existing process-lifetime manner; ID stability
across a membership-only change is mandatory. No persistent-counter promise.

Keep policy recovery and lock fixes already released. Extend existing hooks rather
than rewrite them. Lock hierarchy remains endpoint -> query -> policy for transport
admission. Service membership/turn lock is never held while taking endpoint/query
locks, performing callbacks, DNS resolution, or IO. Selection snapshots and reserves
a generation-tagged turn under service lock, drops lock, then admits transport;
commit/abort finalization updates the lease under service lock only after other locks
release. The lease first has a SELECTING state: cancellation marks it but cannot release it
until selection publishes its endpoint/generation. A leaf turn mutex protects owner
identity and state together; it never acquires endpoint/query/policy/service locks.
The lease then has states RESERVED -> WRITING -> COMMIT_PENDING ->
COMMITTED, with retryable IO loop WRITING -> WRITE_WAIT -> WRITING; terminal paths
are RESERVED -> ABORTED or WRITING/WRITE_WAIT -> ABORT_PENDING -> ABORTED (subject
to owner revocation and writer-return rules below). Writer CAS
RESERVED->WRITING occurs before entering the request-write call. Cancel/refresh can
CAS RESERVED->ABORTED before writing, but once WRITING they only set cancel_requested:
they cannot release/reassign the turn or free its writer/observation references.
After write returns, a positive result unconditionally publishes COMMIT_PENDING
(with accepted time/endpoint ID) even if query cancellation already retired active
attempt state. WANT_READ/WANT_WRITE/EAGAIN or transport-defined retryable zero
publishes WRITE_WAIT and RETAINS the lease, buffered owner and observation; only a
readiness notification may CAS WRITE_WAIT->WRITING to retry. No busy wake, no second
turn while waiting. Cancel/deadline in WRITE_WAIT atomically blocks that owner from
all later request writes, retires its unsent buffer via transport-safe teardown,
then finalizes ABORT_PENDING. Terminal write errors follow the same owner-revocation
path before releasing the turn. A buffered H2/H3/TCP owner can never resume after its
lease is aborted; a retry must create/rebind an admitted attempt with a new lease.
Observation terminal accounting is deferred while WRITING/COMMIT_PENDING (and until
abort teardown is safe), so cancel cannot count skip before a positive write later
requires failure. A matched response arriving in that window is retained as a pending
outcome and finalized after the accepted-write count, never double-counted. A nonblocking deferred finalize
runs after outer endpoint/query locks release, committing count/cursor once or
releasing an unsent turn. No new turn is issued in either pending state. A positive
write followed by cancellation is counted as sent then terminal canceled, never
lost or retroactively aborted. The pinned writer token outlives membership removal;
membership generation changes do not invalidate an already accepted write. A stale
lease token cannot release or commit a newer lease. Subsequent partial writes after
first acceptance do not reacquire the service turn (they use attempt ownership).
The CAS permits no blocking IO or unbounded writer lifetime: existing nonblocking
transport call must return, and shutdown waits for writer ref/finalization rather
than clearing the lease beneath it. Refcounts keep detached
endpoints and services alive until callbacks/streams finish.

### Actual-send RR, not accepted-dispatch RR

Current `_dns_policy_rr_begin` explicitly advances on admission. Remove that
scheduler and replace all enabled RR operation with the service turn lease.
The old option is a migration syntax only, never a second runtime mode. At most one pool turn is uncommitted at a time,
without holding a mutex during async handshake or writing. Multiple already-started
streams continue concurrently. On first positive transport acceptance of request
bytes (`_dns_attempt_mark_sent` integration hook), commit cursor once and release
lease; connection handshake and H2/H3 control frames do not count. TLS/QUIC acceptance
means positive SSL request write, not proof bytes reached the network. UDP commits
on successful datagram send. Partial writes commit exactly once; WANT_WRITE/zero,
allocation, connect, cancellation and prewrite error do not move committed cursor.
Wire token/send-budget reservation keeps existing conservative accounting; a failed
reserved write is not refunded to manufacture quota. Attempts counter tracks first
positive request acceptance, while reserved/failed-before-wire have diagnostics.

Unsent selected endpoint must finish setup within min(existing connection timeout,
query remaining deadline); endpoint-local failure starts bounded backoff and releases
turn. Next scan skips that endpoint; no rollback of committed cursor is possible.
One uncommitted turn may cause bounded head-of-line delay on cold connections. This
is an explicit tradeoff for deterministic send order, not hidden racing. Startup
may establish sockets lazily as turns arrive; no speculative multi-query races.
Healthy ready endpoints in a stable eligible set have actual-send count difference
<=1 over a full round; endpoint recovery joins future turns without catch-up credit.
No fairness guarantee for unavailable endpoints. Existing deadline and retry budget
remain upper bounds; reconnect does not extend them.

429/503/Retry-After blocks all endpoints through existing service/provider policy.
Exactly one recovering request owns the existing epoch-tagged probe before setup;
new endpoints never create a new epoch, tokens, or probe. An old response cannot
clear a newer cooldown. Endpoint transport/TLS failure backs off only that endpoint
unless existing policy explicitly classifies a service response as backpressure.
Per-endpoint retry delay: 1,2,4,8,16,32,60 seconds capped; reset after valid response,
not merely connect. One connect in flight per endpoint, one reserved physical slot
before socket/QUIC allocation, no retry on every 100ms maintenance tick. Failures do
not cause all clients to connect simultaneously. Timers monotonic and saturating.
`max-concurrent-queries` in new mode caps service attempts (not multiplied by IPs).

### Scheduling without a new busy scan

No new global 100ms service/endpoint walker. Existing query deadline/cancellation
maintenance stays, but a waiting pool observation checks the service turn state
and next-eligible timestamp in O(1) and never repeatedly scans membership. A service
keeps one coalesced pending-wakeup flag and earliest timer (tokens/cooldown/connect
backoff/discovery/turn deadline). Lease release, connection-ready, membership publish
and token/probe deadline wake only that service's oldest eligible waiting work item.
Waiting observation references are intrusive links in the existing query/observation
lifetime, not cloned requests, packets or a new generic work-queue framework. Removal
on cancel is O(1); a pinned query is released when its hint is removed. When a selected
query cannot progress, advance the waiter hint boundedly rather than polling all
queries/addresses. Quota shared across services notifies its registered services via
one deadline change; each coalesces its own wake. Endpoint selection snapshots only
when an actual turn can be reserved, into the bounded service membership storage;
no per-100ms heap snapshot allocation and no O(waiting_queries * backend_cap) retry
walk. Existing 100ms transport maintenance remains for established IO correctness,
not multiplied by new discovery polling. Deterministic counters must prove blocked
queries do not increment endpoint-selection/connect counters each tick. This is an
avoided-work design target, not a measured CPU regression fix.

## 4. Discovery: complete answers, TTL, safety, draining

Do not reuse the current fastest-IP `dns_result.ip` callback as if it were RRset
storage: it has no TTL and is subject to frontend response selection. Add internal
bootstrap RRset collection over raw `dns_client_query` packet callbacks against the
explicit `bootstrap-dns` group, preserving validated A/AAAA records and CNAME TTLs.
No calls through default resolver rules, speed-check selection, synthesized answers,
local hosts, ECS injection or pool itself. In auto mode require a nonempty bootstrap
set and validate every declaration before commit: numeric destination (including
an explicitly resolved host-ip), non-pool, non-proxy and non-mDNS. One numeric entry
cannot mask an unresolved hostname that legacy pending resolution could later add.
No implicit getaddrinfo fallback in pool auto mode. Within this validated group,
each bootstrap query rotates its single-send target on bounded retries, so a silent
UDP head does not permanently starve another resolver. The fixed query budget and
absolute deadline do not grow; default/fallback groups never participate. A pool cannot bootstrap itself, even via aliases. CNAME following
uses this same explicit group, max 8 links with visited-name cycle detection;
accept addresses only for validated terminal owner names, never arbitrary additional
records. DNS transaction/source validation remains existing client responsibility.
Bound candidate memory to 64 records per family per refresh; overflow is explicit
error for that family, not partial DNS order-biased selection. Parse streamed records
without unbounded temporary storage.

Automatic discovery preserves existing SmartDNS address-scope compatibility:
legitimate RFC1918/ULA/internal domains, loopback or a different local service port
are allowed. Do not add a public-only default or pin the first public/private scope:
VPN and split-DNS membership changes are legitimate. Reject unspecified, multicast,
broadcast and unusable scoped/link-local literals; a discovered target that points
to this SmartDNS instance's listening address+port+underlying transport is rejected
precisely, not every local IP. Match actual bound listener sockaddrs, not a second
interpretation of bind text: this covers :PORT, hostname bind and IPv4-mapped IPv6.
IPv6 wildcard coverage follows the socket's actual IPV6_V6ONLY setting; accepted
client sockets are not listeners. Wildcard listeners require a local-address check;
resolved nonlocal addresses using the same port are not self-loops. Numeric bootstrap
targets must pass the same no-self-listener check for auto pools. No new recursive
lookup through the pool/default/fallback is permitted. TLS verification/pins retain
the configured authority, SNI and HTTP Host across IP changes; explicit insecure
TLS flags remain visibly insecure, never silently strengthened or weakened. Existing
DNS response/source/transaction and CNAME chain validation remain mandatory. DNSSEC
validation and stricter optional public-to-private rebinding policy are not newly
promised or added as compatibility-breaking blockers in this batch.


One refresh generation contains A and AAAA subresults with statuses POSITIVE,
AUTHORITATIVE_EMPTY, TRANSIENT_FAILURE or POLICY_REJECTED. Per-family prior state
is preserved for transient failure. A trustworthy NODATA immediately stops new
admissions for that family, not at negative-TTL expiry: negative TTL controls only
when to requery. Trustworthy NXDOMAIN of the original owner immediately invalidates
both families; NXDOMAIN at a CNAME terminal invalidates both only when both chains
resolve to that same terminal, otherwise invalidates that chain/family. If a refresh
generation has contradictory positive and NXDOMAIN results for the same owner,
reject the whole generation as inconsistent, do not refresh prior validity, and
retry; no TTL or grace extension is earned from the contradiction. Never interpret
SERVFAIL/REFUSED/timeout as NODATA. Trustworthy negative means a source/transaction
validated configured-bootstrap response with matching question, relevant enclosing
SOA and valid owner/CNAME chain, not a new DNSSEC claim. Its negative TTL is min(SOA
TTL, SOA.MINIMUM). A NOERROR empty response without such proof is transient failure.
POLICY_REJECTED clears that family's newly invalid addresses immediately; no stale
use of an address now known forbidden. Families merge only into generation state;
late callbacks from older generations are ignored after releasing refs.

TTL expiry derives from minimum relevant RR/CNAME TTL, with no upward clamping of
validity. Refresh at max(1s, 80% TTL), capped at 1h interval. TTL=0 records are not
eligible cached pool members in v1: discard for admission immediately, expose
zero_ttl diagnostic, retry no sooner than 1s, and leave waiting queries subject to
their original deadlines. Never save a zero-TTL address for an arbitrary next query
or claim NXDOMAIN from TTL=0. A previous member whose replacement RR has TTL=0 is
removed immediately with no stale grace. Mixed positive-TTL records remain eligible
only if the complete owner/CNAME chain has positive TTL. This explicit fail-closed
limitation is preferable to inventing a background-discovery consumption opportunity;
per-query noncached discovery is out of scope. Test zero-only and mixed sets. Refresh failures back off
1..60s with at most one generation in flight. Last-good addresses may serve only
until original TTL expiry + 60s bounded stale grace on **transient** failures;
status is stale and deadline exposed. Negative/policy reject never obtains grace.
After grace, service remains visible unavailable with zero new admissions while
refresh retries continue; no indefinite reuse and no process exit for one provider.

At refresh publish, retained addresses keep endpoint object, connection, health and
RR member identity. Removed endpoints become DRAINING, receive no new work, and
finish already-started streams until the existing query deadline, with additional
hard drain cap 5s. Unsent streams retire immediately and may retry within original
budget. Old responses retain service attribution. Close only through existing
reentrancy-safe deferred teardown. Replaced endpoints never increase total physical
slots beyond the configured ceiling, including draining connections. Keep at most
N active + N draining endpoint objects (metadata objects are not connections).
N and physical cap are immutable for a service lifetime in v1; configuration cap
changes require the existing stop/restart configuration lifecycle, not a new live
cap-resize API. Across repeated discovery generations, the single shared drain set
stays bounded by N, not N per generation. Invalidation takes effect immediately:
mark every removed/forbidden/negative/expired endpoint no-new-admission before any
wait for drain capacity. A removed member can remain a pinned draining object, never
selectable pending replacement. If drain slots are full, force no new admissions on
revoked active objects in place and retain only the latest bounded desired-address
metadata; this can temporarily reduce usable active membership but cannot send to
a withdrawn address. Materialize additions only as active/drain capacity and physical
slots permit; coalescing delays additions, never revocations. New answers cannot
reset an old drain deadline or multiply retained generations. Do not retain unbounded
membership generations. Counters retained on service, optional retired endpoint
counters folded into a bounded aggregate, not an unbounded history.

## 5. Statistics/API/UI contract

Authoritative counters live on the service; never sum disappearing endpoint rows.
Per query-service attachment create a small refcounted observation record reused
across endpoint retries, never across distinct ANY child questions. ANY children
share their existing parent send budget, NOT their service observation or counters.
`query_count` = logical upstream-query work items offered to this service once;
each ANY child DNS question is a separate upstream work item, with parent ID exposed
only for diagnostics. `attempt_count` = actual first accepted request write per
attempt; `success_count` = work item whose matched, validated DNS response has NOERROR or
NXDOMAIN and whose result callback accepts it with ACTION_OK; `failure_count` = terminal work item without valid response after actual
attempt; `skip_count` = terminal work item with no actual request write (deadline,
cancel, quota/no endpoints). In-flight work is separate, not prematurely failed.
`query_count = success + failure + skip + in_flight` is the required invariant.
SERVFAIL/REFUSED or other nonaccepted rcodes are not success; they may retry within
existing budget and ultimately fail. Callback DROP/RETRY/MAY_RETRY never finalizes
success; a later accepted response may. Duplicate replies and losing-provider
cancellation cannot double-count. A canceled
work item that had sent is failure with canceled reason; never an upstream transport
error metric. `service_response_latency` is first actual send to the accepted response, including
retry time, one sample per success; expose count/sum and compute weighted average,
never average endpoint means. It is NOT attempt RTT. Separate `attempt_rtt` uses
that accepted response's matched attempt-generation send timestamp ONLY when
unambiguous (a correlatable stream or datagram with no retransmission ambiguity).
UDP retries reuse the DNS SID and cannot prove which generation answered: expose
null/ambiguous for attempt RTT and exclude it from RTT sample count/sum. Do not
attribute an old UDP reply to the newest send timestamp. Service response latency
remains valid because it spans from the work item's first actual send. Also expose
service residence latency (offered to terminal) for queueing diagnosis separately.
Existing avg_time on new service rows maps to service_response_latency and its
semantics tag states this explicitly; never reuse endpoint last_send_tick.
Skip reasons and endpoint pre-wire setup errors are diagnostic counters, not new
queries on every scheduler tick. Provider backpressure events count once per valid
response; token denials are not counted as HTTP failures.

Keep existing public C endpoint APIs and struct dns_server_stats ABI semantics.
Add versioned copied snapshots, not pointers to mutable internals:
`dns_client_get_service_snapshot_v1(...)` with count/capacity retry and documented
ownership, plus `dns_client_get_service_endpoints_v1(service_id,...)` diagnostics.
Snapshots include legacy declarations as one service each and new pools as one row;
compatibility-normalized old RR declarations are already one new service.
Incompatible old declarations fail validation; never merge unrelated providers by
quota name in the snapshot or UI. Existing endpoint API remains available to older plugins. Compatibility-normalized
RR declarations use the new service snapshot and are not a second statistics model.

Bundled Rust UI adopts the new service snapshot and `/api/upstream-server` preserves
its wrapper and old field names/types, while one pool is one row. `host` is authority,
`ip` is the sole address if exactly one, otherwise empty string (not CSV masquerading
as an IP). Add `service_id`, `pool_enabled`, `endpoint_count`, `endpoint_ips`, status,
policy/cooldown, attempts/failures/skips, latency sample count, discovery freshness
and overflow. Existing `total_query_count/success` map to new service query outcomes
for all new-service pools including compatibility-normalized old RR; document
version/semantics explicitly (`stats_semantics=service-v1`). Only ordinary non-RR
legacy rows retain their previous field meanings. Security is worst active endpoint verification
state, unknown when none; do not label all-secure on one verified backend. Top-level
server count badges switch to logical services in updated UI, physical count separate.
Optional `/api/upstream-server/{service_id}/backends` exposes bounded per-IP diagnostics.
Old endpoint C consumers still work; newly deployed UI requires matching core version
and must check snapshot API capability, not silently misread an older ABI.

Network-center is independent project 73, `sway.chan/network-services-rs`.
Independent inspection located `src/center/smartdns/upstreams.rs:43-59`: currently
only group/bootstrap/exclude options are understood. An active row with a new
option becomes non-editable; a disabled marker row with unknown options errors.
Therefore core-only implementation is NOT the complete user-experience deliverable.
User has now authorized the bounded external parser/generator/editor/statistics
scope. A separate dots author owns an isolated network-center branch; this core
author provides the versioned contract below and integrates evidence, never overwrites
concurrent CDN work. No production/config edit follows from source authorization.
Minimum consumer changes: Minimum consumer work: one provider row -> one config line;
explicit pool toggle off by default; optional numeric IP list and advanced backend cap (default 4, adjustable); never synthesize
one line per IP or require quota-group; display domain as key and optional backend
expansion; tolerate new optional JSON fields and empty multi-IP `ip`. The external parser/renderer must recognize the pool flag, host-ip list, advanced
backend cap and existing physical connection override; disabled lines must accept
and preserve the same fields, while truly unknown options remain safely preserved
or clearly noneditable rather than crashing the full configuration view. Existing saved
configs must round-trip unchanged when toggle off. Upgrade parser before generator
starts writing new syntax; retain schema defaults for existing records. Do not
restore the two legacy doh.pub declarations: the latest user has rolled back
configuration, superseding previous live-state notes. Add parser/renderer
roundtrip fixtures for both disabled and active pool rows and edit/save/reopen UI
coverage. External implementation is authorized but incomplete; keep its end-to-end gate
pending until tested, never claim the user must permanently hand-edit native config. No concurrent broad CDN refactor.
Acceptance requires its generated line loaded by SmartDNS and runtime API asserting
one service row with observed real endpoint sends. Mock-only panel tests cannot pass
this requirement. If consumer repo unavailable, core may be reviewed but this end-
to-end acceptance stays BLOCKED, not falsely green.

## 6. Legacy RR retirement and bounded compatibility migration

Latest user instruction: remove/retire the coarse RR model when the new logic ships.
There is one service scheduler, cursor, membership and counter engine. Ordinary
non-RR DNS-group fanout is untouched; this is not a rewrite of unrelated transports.
Delete `_dns_policy_rr_begin` and its quota-as-service identity/flags/cursor state
when integrated tests cover the replacement. Preserve the independent quota/token/
cooldown/recovery-epoch logic and transport/frame correctness fixes.

Old `-upstream-round-robin -quota-group X` syntax may load only through an explicit,
logged compatibility normalization before any sockets or groups become runnable.
No on-disk config rewrite is performed. Each old quota RR set must have a recoverable
original domain authority shared by every member (not merely a recoverable domain
per member), same transport/port/path/TLS authority and verification/
Host/ALPN/proxy/interface/ECS/fallback/answer flags, identical routing group membership
sets, and equal rate/burst/physical cap. All member addresses must be numeric and
static; mDNS/proxy/heterogeneous ports/unknown original authority are rejected with
a precise line-numbered manual-migration error. Original authority is captured
before old host-ip replacement; it is not guessed from SNI or quota name.

Per-endpoint old `max-concurrent-queries != 0` is rejected for compatibility folding:
changing it into a service-wide cap silently changes quota/concurrency semantics.
Ask the operator through the error message to rewrite one new service and explicitly
choose its service cap. Distinct group intersections are likewise rejected, not
merged into a union. The old quota name is preserved only as shared quota identity;
it must not combine unrelated provider security identities. Conflicting old RR and
ordinary declarations sharing the same quota name are rejected for manual migration
rather than guessed. Duplicate old endpoint addresses deduplicate deterministically.

A compatible old set folds into one new service object with original address order,
max_backends=max(unique_count, old physical cap), and the old explicit/effective
physical cap (including old default 2) copied as an explicit normalized resource
limit. This preserves the old physical ceiling without making 2 the new default.
The safe 64 ceiling still applies. Rate/burst values are copied exactly, including
rate=0/unlimited; no provider allowance is invented. The loader logs once that old
RR syntax was normalized, shows the canonical replacement configuration, and states
that fairness now means actual positive sends and counters use service-v1 semantics.
The migration warning and generated replacement make the change visible rather
than silently preserving a second engine. No disk rewrite or live activation. The normalized object must still pass ALL new
service validation, including no bootstrap flag, no proxy, no mDNS and domain
authority requirements. Validate/normalize the complete configuration transaction
before committing runtime groups/services; any failure stops startup before any
configuration target can perform network IO. Compatibility is not a bypass around
new service validation.

New network-center writes only canonical single-service syntax. It recognizes and
displays migration-needed legacy RR rows without auto-saving transformations; its
explicit user save can emit a canonical line only when the same compatibility
checks succeed, or otherwise retain read-only text and precise migration diagnostics.
Existing disabled/plain rows round-trip unchanged. User's current rolled-back
production config is not altered by implementation or tests.

Compatibility tests assert old-compatible syntax -> exactly one new service and
new actual-send counters, old-incompatible syntax -> fail before network work with
no partial startup, and ordinary group fanout remains identical. No hidden legacy
RR cursor or quota-based UI grouping remains reachable.

## 7. Source impact map (verified current paths)

- `src/dns_conf/server.c`: parse new switch/list, retain authority currently overwritten
  by host-ip; strict validation and migration errors. `src/include/smartdns/dns_conf.h`
  and `src/include/smartdns/dns_client.h`: new config plumbing and additive API.
- `src/smartdns.c`: `_smartdns_prepare_server_flags`, `_smartdns_add_servers`: service
  creation once and service group links rather than repeated endpoint declarations.
- New `src/dns_client/upstream_service.[ch]`: ownership, identity, membership, snapshots,
  turn leases and observation lifecycle. New `upstream_discovery.[ch]`: raw bootstrap
  RRset collection, TTL and safety policy. Build source list must be verified in
  `src/Makefile`/root Makefile before addition.
- `src/dns_client/dns_client.h`, `group.[ch]`, `server_info.[ch]`, `dns_client.c`,
  `query.[ch]`: tagged targets, pinned snapshots, budget cardinality, callbacks and
  service lifetime; existing `pending_server.c` legacy behavior left intact.
- `src/dns_client/upstream_policy.[ch]`: separate quota identity from pool scheduler,
  service concurrency, hook first send/probe without undoing recovery fixes.
- `client_socket.c`, `conn_stream.[ch]`, `client_tcp.c`, `client_udp.c`,
  `client_http2.c`, `client_http3.c`, `client_http3_control.c`, `client_quic.c`:
  physical slot/draining, accepted-request commit integration. TLS/HTTPS wrappers
  audited for inherited hook behavior; do not add transport-specific duplicate policy.
- `src/include/smartdns/dns_stats.h`, `src/dns_stats.c`: additive service snapshot
  counters only if separate module cannot host them; leave old struct layout intact.
- `plugin/smartdns-ui/src/{smartdns.rs,data_upstream_server.rs,http_api_msg.rs,
  http_server_api.rs,data_server.rs}` plus actual web client consumers located during
  implementation; bindgen/build linkage and API roundtrip tests.
- `docs/upstream-backpressure.md`, new `docs/upstream-service-pool.md`, example config
  comments and migration documentation. External network-center parser path verified above; exact generator, API DTO and
  UI component paths remain to be traced before implementing its bounded scope.
- `test/cases/test-upstream-{round-robin,policy,observability}.cc`,
  `test/cases/test-bootstrap.cc`, new `test-upstream-service-pool.cc`, transport suites,
  `.github/scripts/check-native-results.py`, `.github/scripts/run-native-offline.sh`,
  `.github/workflows/c-cpp.yml`/`webui.yml` as required for non-skippable gates.

## 8. Gates and evidence, before publication

A. Independent design review: configuration/negative-answer ambiguity, lock graph,
resource ceilings, first-wire lease mechanism and statistics semantics explicitly
accepted or corrected. Author cannot sign own review.
B. Bounded cloud correctness only: parser roundtrips; 0/1/2/3/4, cap 1/4/8/64, input above cap and above safe parser bound; IPv6 spelling and
mapped dedup; off-mode; invalid lists/proxy/bootstrap combinations; identity stable;
quota cross-service no multiplication; group subset/fanout; all startup/shutdown paths.
C. Deterministic virtual-clock discovery tests: reordered sets, partial family failure,
TTL=0/CNAME chain TTL, authoritative empty, NXDOMAIN, stale deadline, invalid/self-listener
addresses, legitimate private/ULA and VPN scope changes, self-bootstrap, cycle, late callback, flood-sized RRset, oscillating members,
no retained object growth, no use after retire, total slots <=configured cap including handshakes and old draining slots.
D. Scheduler/transport tests: parallel queries, true positive-write order, WANT_WRITE,
partial write, setup failure, cancel, timeout, one-turn lease recovery, close callback
reentrancy, service concurrency, 429/503/recovery epoch across address replacement,
old-response isolation. Real TLS/H2/H3/DoQ loopback fixtures; raw accepted request log
must match counters and RR sequence, not mock admission callbacks. UDP/TCP included.
E. UI/generator-to-runtime: generated configuration boots real core, bootstrap fixture
returns 3 addresses, runtime snapshot/API shows 1 service/3 endpoints, backend logs
show RR sends and shared quota; refresh removes one but preserves aggregate counters.
Existing JSON consumers and old endpoint API regression checked. Save/reopen toggle
and list preserve intent. Network-center unavailable is an explicit open gate.
F. CI: existing system and QUIC distribution profiles, complete suites, mandatory
actual-case result gate, sanitizers and release packaging/ABI/UI builds. Missing
QUIC cases cannot be skips counted green. Performance/CPU/memory measurement only
existing isolated GitHub CI with network disabled and pinned baseline/candidate;
no cloud-workspace or local-user-machine stress/benchmarks. Correctness fixtures are
bounded, not performance claims. No unrelated optimization mixed into this feature.
G. Separate dots code reviews and exact-SHA all-green CI before authorized repository
submission. Then notify parent/local operator for pull/deploy; never self-deploy or
turn pool on in production. No release version bump/package claim at design stage.

## 9. Explicit non-goals

No autonomous activation, public provider probing, replacing reliable recovery,
rewriting DNS server frontend, weighted/latency/random balancing, hedged backend
racing, unlimited candidate/history queues, per-IP quota, dynamic remote proxy DNS,
SRV/HTTPS/SVCB discovery, DNSSEC validator, persisted runtime stats, address-driven
certificate weakening, arbitrary backend ports, or broad CDN/network-center redesign.


## v11 implementation reconciliation (for independent review)

- Preserve v10 legitimate private/ULA/VPN compatibility; no public-only or scope pin.
  Loopback fixtures use precise listener endpoint checks, never a global local-IP ban.
- Turn owner identity and state use a leaf arbitration mutex; SELECTING cannot be
  finalized by another thread. A lease pins its endpoint. Retirement during WRITING
  or COMMIT_PENDING defers provider recovery-lease release until positive-write
  accounting is finalized, and query observation pins survive that boundary.
- Service IDs use explicit canonical integer/string serialization rather than C
  struct padding. A load-local declaration discriminator lets different routing
  groups retain distinct services; identical final logical identities fail rather
  than silently merging their quotas. The discriminator is not hashed or exposed.
- RTT is conservative at the generic receive boundary: retransmissions with no
  proven generation association are excluded (not zero), even for streams where
  a future more precise hook could recover additional samples. Service latency
  remains first positive send to accepted response. Backend counters are actual
  positive-write attempts and terminal attempt outcomes, not discovery traffic.
- Endpoint transport failure backs off only that endpoint; service 429/503 cooldown
  is distinct from local endpoint availability and rate-token wait. Status does
  not mislabel rate waiting as provider cooldown.
- No CPU improvement is claimed. Removal of per-dispatch heap snapshots and moving
  attempt allocation outside the policy lock are structural changes, not measured
  production CPU attribution. No monitoring/WS/framework changes were introduced.
- A real incremental-build defect surfaced during bounded fixtures: archives with
  duplicate object basenames retained stale second members under `ar rcs`; archive
  targets now remove the old archive before constructing the full member list.
- At the v11 freeze 65 bounded C tests passed, including actual UDP auto-discovery,
  TTL withdrawal/stable service counters, real DoT connection reuse and real H2
  cross-IP 429 cooldown. This is NOT full CI, QUIC/H3/DoQ, Rust plugin build, native
  dashboard rendering or independent implementation approval.

## v12 independent implementation review corrections

- Pin the entire returned epoll event batch before any timer/callback can revoke
  registry membership. Release pins only after the whole batch; a per-event get
  after earlier callbacks cannot repair a dangling pointer. Revoked idle endpoints
  are not dispatched; active draining owners remain valid until completion.
- A no-progress selection records a finite next-eligible wake or settles an
  exhausted/terminal observation. It must not abort/requeue itself forever through
  eventfd. UDP EAGAIN has no buffered owner: abort it with bounded delay, no positive
  send accounting, and no deadline extension. Connecting timeout backs off locally.
- The ready list contains only eligible waiting observations, not every in-flight
  query. A coalesced intrusive hint stack carries terminal/ready changes and pins
  its query until consumed; each flush handles at most 64 hints. Positive commits
  do not scan all in-flight observations. Leftover concrete hints may schedule the
  next bounded batch; an unchanged blocked observation cannot self-feed wakeups.
- Bootstrap fences cover explicit ECS_DNS/ECS_IP, global default ECS and final
  packet encoding, including CNAME following; ordinary ECS behavior is unchanged.
  Validate all bootstrap declarations before runtime; use actual listener socket
  identity for both bootstrap and discovered endpoint recursion checks.
- Canonical binary ordering is applied per family before family interleaving and
  filling new slots; retained valid members keep their identity/cursor. DNS RR
  order does not decide which new address wins a configured cap.
- Added bounded real-IO regression coverage for these corrections, including
  silent-head bootstrap failover and no default/fallback traffic. Full cloud
  source rebuild and 80 focused tests passed, including real UDP/DoT/H2/H3/DoQ.
  This is not full CI, Rust/plugin build, native dashboard render or release approval.

## v13 review corrections: registration and discovery fairness

- Publishing an observation in the query list does not make it dispatchable or
  settleable until service counters and the ready link have been registered.
  A release/acquire `registered` gate permits cancellation to mark it meanwhile,
  without taking query -> service locks; the registering publisher emits the final
  terminal hint if cancellation happened in this window. No hint can settle an
  unregistered observation or release its lifetime pin early. A barrier fixture
  pauses exactly between publication/registration and cancels/flushes concurrently.
- Bootstrap fairness persists per discovery instance and per A/AAAA family across
  query generations (including CNAME launches). Each new raw query receives that
  family's advancing start index via an internal bootstrap-only option. This is
  not a global RR cursor shared by providers: synchronized providers cannot trap
  a particular authority in a modulo subset of bootstrap members. Generic raw
  bootstrap queries without this internal hint use a group-wide fresh-query start.
  Each individual query retains its existing absolute deadline and send budget;
  a large blackhole prefix can take multiple bounded refreshes to reach a healthy
  member. Five actual listeners with four reading-but-silent heads test eventual
  discovery, and fresh one-send queries test that restarting cannot always pick
  the head. Ordinary upstream fanout and service endpoint RR are unchanged.

### v14 — native dashboard consumer compatibility (22 Oct 2026)

The pinned webui's unmounted legacy overview source uses `ip` as a query-log
**client address** filter. That is not evidence of a mounted overview, but reinforces
why `ip` must not be repurposed as a service label. Owned packaging applies an
exact-source-verified patch only to the mounted upstream table and optional API
TypeScript metadata. The table shows authority and real `endpoint_ips`, retains
one row per service, and uses `service_id` for pool row identity. Ordinary rows
retain the original default-index identity and display. Navigation uses the
existing sidebar upstream page; no client-filter link or new overview is added.
No third repository or frontend framework is introduced. The packaging README
covers source integrity, cache rejection, OpenWrt parity and actual-component /
captured-REST browser verification, separate from C/Rust API authentication.

#### Pinned-route verification correction (22 Oct 2026)

Actual browser evidence showed that the fixed upstream `/dashboard` mounts only
metrics/charts; the legacy `UpStreamServersCard` has no importer. Its static
address/client-filter semantics above are real source semantics, but not a
currently reachable UI consumer. The original browser fixture therefore waited
for a nonexistent widget before making any upstream API request; it did not test
or fail the service table. Acceptance now follows the actual sidebar route to
`/dashboard/upstream-servers`, verifies four service/ordinary rows with real
captured API data, invokes its existing refresh control, then reloads that route.
No runtime component, service implementation or API contract is changed to make
the test pass. The unused overview patch and its pre/postimage entries are removed; the owned
patch now touches only the actual table and its optional TypeScript API fields.

### Snapshot freshness projection (v16, observation only)

The C snapshot carries explicit `freshness_kind`: UNKNOWN, FINITE,
NON_EXPIRING, NOT_APPLICABLE. `freshness_remaining_ms` is meaningful only for
FINITE; the other kinds export C zero and JSON null, never an internal ULONG_MAX.
JSON additionally reports `freshness_status`: `unknown`, `finite`, `non_expiring`,
`not_applicable`. Explicit static pools are non-expiring, even before startup.
Automatic pools with a known positive-membership expiry report finite remaining
milliseconds, including 0 when expired. Cold start and discovery snapshots with
no usable positive-membership TTL (including empty/negative answers) report
unknown/null; negative retry TTL is not a backend freshness TTL. Ordinary rows
report not_applicable/null. This is architecture-independent metadata, not a
change to any scheduler deadline, negative-cache timer or static validity.
Other snapshot time fields were checked: cooldown and endpoint retry are finite
deadlines, not infinity markers; connection counts/security/counters do not use
the discovery ULONG_MAX sentinel. Saturated finite policy deadlines retain their
existing meaning. No browser conversion or floating-point threshold is used.

The finite/unknown distinction is recorded when membership is published, not
guessed from an integer threshold: a legitimately saturated finite 32-bit expiry
remains finite. Empty discovery does not acquire a fake positive TTL.
