# Bounded ANY responses

QTYPE 255 is `DNS_T_ANY`. The internal `DNS_T_ALL = 65535` sentinel is unchanged.

The default is `any-response-mode passthrough`. A valid upstream ANY answer,
including HINFO or a single RRset, completes normally. Successful exact ANY
packets can be cached and equivalent requests can share one operation in the
plain, compatible context described below. There is no automatic record-type
expansion and no claim that ANY enumerates all records.

Default passthrough preserves ordinary upstream fanout. An early upstream error
(REFUSED, SERVFAIL, NOTIMP, etc.) is retained as one bounded fallback packet while
healthy siblings can still answer, including siblings waiting for admission.
A valid NOERROR/NXDOMAIN response wins immediately. If no valid response arrives,
the retained first error is delivered when the ordinary client operation ends or
its deadline expires; no error is cached. Default-mode operations own a cancelable
budget using the ordinary client's configured-group/fallback capacity and nominal
lifetime policy (currently 2 seconds), rather than aggregate's type/attempt caps.
They do not set the single-upstream flag.

## Explicit address completion (opt-in)

Enable with `any-response-mode address`; disable with
`any-response-mode passthrough`. The default remains passthrough. `aggregate`
remains the separate finite-type fallback mode described below. These are
SmartDNS text configuration settings; no control API is added.

Address mode directly resolves A and AAAA through the ordinary address pipeline;
it never sends an initial ANY probe and does not inspect HINFO strings. Both
families must complete coherently under the existing native policy. Two positive
results return both families; genuine upstream SOA-backed NODATA or an explicit
local family suppression may leave one family. These are distinct sources: only
the native local-address/SOA decision sites attest policy results. Errors,
timeouts, stale negatives, malformed/incomplete upstream data and unknown
absence are never promoted to policy suppression. Native whole-name blocks keep
NXDOMAIN, and explicit QTYPE-255 SOA policy retains precedence over aggregation.
Consistent upstream NXDOMAIN remains distinct from NODATA; conflicting aliases
or positive/NXDOMAIN results fail. This represents the configured resolver and
its selected native policy, not reachability or all zone records.

Query AD is accepted as a capability hint (RFC 6840 section 5.7), never as proof
of authentication. Generated AD/AA remain clear. Cookies, padding and TCP
keepalive may be ignored/handled per hop without changing the DNS view; they do
not attest safe legacy cache provenance. Other unknown contexts remain bounded
failures. See https://www.rfc-editor.org/rfc/rfc6840.html#section-5.7 .

The family set is always A+AAAA, concurrency is two, and partial results are
always disabled. Valid `any-aggregate-types`, `any-aggregate-concurrency`, and
`any-aggregate-partial` settings are retained for compatibility but have no
effect while address mode is selected. They take effect again when switching
back to aggregate. Invalid settings still fail ordinary configuration parsing.
The existing `any-aggregate-max-attempts` (default 16, range 1–64) and
`any-aggregate-timeout-ms` (default 950, range 1–950) bound the whole operation,
including both families and nested work. Each child does not receive a new
budget. Rule-group inheritance and explicit group overrides apply to all modes.

Address requests keep conservative equivalent-request coalescing separate from
native typed-cache reuse. Fresh positive A/AAAA entries can be reused only with
an exact process-local policy view, in addition to the native domain, family,
rule-group and bind-flag key. The view records the immutable effective rule-group
object, upstream route and bind routing-set contents; identical UDP/TCP target
lists match by value, while different targets cannot share a cache view. Client
rules have already resolved into that group
and those flags. AD capability hints and benign hop annotations do not create
different answer policies. ECS, DNSSEC/CD, DNS64 and unsupported wire contexts
remain ineligible. View IDs use exact equality, never a bitmask subset or a lossy
hash. At most 1024 views are retained without recycling; exhaustion disables reuse.

Only actual compatible upstream work can attest the finalized native selected
addresses. Ordinary A/AAAA queries and trusted internal background prefetches
use the same eligibility and source validation. Background prefetches resolve the same domain/group policy; listener routing-set
bindings keep the native no-prefetch flag. Prefetch DO/ECS options still
exclude attestation. Legacy/persisted entries have no process-local attestation;
legacy packet replacement and metadata-only replacement revoke it. Packet,
provenance and TTL metadata are snapshotted under one cache lock, and each RR is
aged only in a private copy. Negative and expired entries cannot prove upstream
absence. Ordinary pending leaders with unrelated budgets are never joined.

Complete upstream Answers are normalized before collecting a bounded proof set
of 64 addresses per compatible live request. Under force-no-CNAME, coherent
upstream alias paths are validated before flattening them. Every finalized
selected address must occur in a complete positive proof, including selections
combined from different upstreams. A truncated or Additional-only source cannot
attest its reconstructed addresses; an unrelated failed peer does not invalidate
addresses proven by another complete source. Overflow or allocation failure
only disables this reuse. Native speed selection and its finalized TTL policy
remain authoritative: warm multi-record entries retain every selected record,
while cold first-ping completion still does not wait for all upstreams.

Request and response OPT options share a bounded length validator. Well-formed
padding, cookies and keepalive are hop metadata and are stripped before merging;
response cookies must include a server cookie. A single root OPT is allowed only
in Additional, with supported version/flags. Malformed lengths, duplicate OPT,
ECS, DNSSEC and unknown extensions do not establish completion evidence. This
also accepts padded HTTPS DoH responses without weakening policy-view checks.

Internal typed children inherit immutable bind ipset/nftset configuration without
borrowing a client connection. Native routing-set effects therefore apply both
to domain/group rules and listener rules. Bind-set requests remain outside
conservative operation coalescing; compatible native cache reuse is independent.
The view dictionary is cleared before each resolver lifetime and its opaque token
sequence is never recycled, preventing references to retired bind configuration.
Cached CNAME packets are also refetched because the legacy cache may retain a
collapsed alias chain without the original complete-chain provenance.
There is no separate combined address-result cache. `cache-size 0` disables
completed caching while preserving in-flight coalescing. Address-owned children
suppress recursive cross-family preference checks, so a preferred-family policy
cannot masquerade as an absent family. Ordinary A/AAAA client requests retain
their existing behavior.

Native policy admission is separate from conservative cache/coalescing
eligibility. CNAME suppression, domain speed/dualstack flags, local addresses,
IPv4/IPv6 suppression, route groups, ipset/nftset and no-cache binds pass through
the ordinary typed pipeline. Non-plain requests do not join a plain operation; they may reuse a fresh native
entry only when the exact effective policy view matches. The native typed finalization retains
routing-set effects; the parent does not repeat them. Alias evidence is rebased
for configured local CNAMEs. Visible CNAME answers retain a coherent selected
path across both families. Explicit force-no-CNAME instead combines independently
validated native address selections at the original owner, including different
upstream alias paths. Local policy negatives are not mistaken for upstream
absence and do not constrain the other family's alias chain.

DO/CD, ECS, DNS64 and unsupported EDNS view semantics are still not synthesized;
those explicit address requests fail boundedly rather than forge DNSSEC or ECS
context. Passthrough and finite aggregate retain their existing transparent
fallback behavior. Capacity exhaustion remains a bounded opt-in failure.

Apply changed settings by restarting SmartDNS through the deployment's service
manager. A universal live-reload mechanism is not promised. The previously
merged revision `8fb86725b74e82a220947b21929e24407f5dad7f` does not recognize
`address`; use a build containing this implementation and its matching source
revision. A successful configuration parse alone is not runtime verification.

## Explicit finite fallback

Example (an operator-selected list, not a built-in default):

```
any-response-mode aggregate
any-aggregate-types A,AAAA,MX,TXT
any-aggregate-concurrency 2
any-aggregate-max-attempts 16
any-aggregate-timeout-ms 950
any-aggregate-partial yes
```

All settings are rule-group scoped and inherited like other rule-group settings.
Aggregate mode requires an explicit list of 1–8 distinct ordinary types. The
verified relocation/encoding set is A, AAAA, NS, CNAME, SOA, PTR, MX, TXT, SRV, CAA.
Other names, numeric values, meta/transfer types and duplicates are rejected.
There is no default type list. Numeric values are rejected outside these ranges:
concurrency 1–8 (default 2); total attempts 1–64 (default 16); timeout 1–950 ms
(default 950). Partial accepts only yes or no (default yes).

The operation checks its exact ANY cache, then sends one logical ANY probe.
Only REFUSED or NOTIMP starts the configured typed fallback. A successful minimal
answer is never expanded. Typed results from previous coherent aggregate work
can be reused only under the identical ANY context/configuration. The existing
A/AAAA packet cache and pending-query table are not used because their keys do not
prove validation/ECS equivalence.

With K cold configured types, the normal successful path costs one ANY probe plus
K typed questions. With M misses in the compatible private typed cache it costs
one probe plus M questions. Retries/fallback consume the same shared total attempt
budget; they never receive a new budget per type. Each aggregate query selects one
eligible configured upstream at a time rather than broadcasting every type.
There is no capability cache or speculative bypass of the ANY probe.

The absolute deadline starts before the probe and is clamped to the original
request's remaining 950 ms lifetime. Probe latency, admission cooldown, and typed
work all consume that lifetime. The existing event-loop cadence determines when a
completed/expired operation is delivered, but no new wire attempt is admitted
after its deadline. Children are scheduled from the server event loop, not
recursively from transport teardown callbacks. A slow refusal may leave no time
for fallback. No local CNAME follow-up questions are launched: an incomplete
upstream alias chain is an unusable child. Local CNAME/policy rewrite contexts
bypass this feature.

## Passthrough / finite-fallback response and cache semantics

- Fresh ANY preserves every upstream RR TTL. Cached packets independently age each
  ordinary TTL and preserve OPT flags. Cache lifetime is no longer than the
  shortest retained RR lifetime, additionally capped by SOA.MINIMUM for negatives.
  Fractional elapsed time is conservatively rounded up when emitting cached or
  combined data. TTL zero is never cached. No serve-stale, prefetch or configured
  TTL floor extends ANY data. DoH Age is applied before the server callback.
- Coherent CNAME chains are limited to eight links; loops, contradictory targets,
  terminal-name mismatches, and illegal same-owner CNAME/data combinations fail
  aggregation. Encoded names/RDATA are reconstructed for known types; raw DNS
  messages or compressed-pointer fragments are never concatenated.
- Synthesized AD and AA are clear. Positive-vs-NXDOMAIN conflict fails. NODATA is
  scoped to a configured child type and never inserted into the ordinary typed
  cache. All coherent SOA-backed negative children can produce a negative ANY
  answer. Failures or timeouts do not manufacture empty NOERROR.
- Partial=yes allows a coherent positive subset when another child fails. The DNS
  wire format does not advertise completeness or identify omitted/error types.
  Partial=no fails if any child is unusable. With no coherent positive answer,
  missing/error children cause SERVFAIL; genuine unanimous negatives stay distinct.
- The full encoded response is capped at 4096 bytes and 64 retained records.
  Oversized assembly fails; it does not silently discard data. A UDP answer larger
  than the request's advertised size (512 minimum, 4096 maximum) becomes a
  question-only TC answer at a whole-record boundary. Its complete coherent cache
  snapshot is retained so TCP retry within its TTL does not launch another fanout.
  TTL-zero data cannot provide that cache guarantee.

## Conservative context and resource boundaries

Passthrough and finite fallback only coordinate/share plain IN, RD=1 requests
without DO/CD/AD, ECS, unrecognized EDNS options/flags or unsupported policy.
Configured endpoint/fallback ECS and rule-group ECS also disable that optional
coordination. Native policy/CNAME work, DNS64 and no-cache requests keep their
ordinary transparent path in those modes. Original ANY DO/CD are propagated.

Address mode instead uses the native-policy admission described above, accepting
AD capability hints, benign per-hop options and the supported native policies.
It shares operations/imports native cache origins only for the strict plain
context; all other supported requests own independent operations and refetch.
This is required because the legacy key does not attest every client's policy.

Keys include canonical name, route, rule-group identity, bind flags, qtype, and the
entire configured aggregate policy/type list. Configuration restarts clear the
private table. There are at most 128 allocated operations (including canceled work awaiting callbacks), 32 waiters each, and 256
private cache entries (or a smaller configured cache-size). `cache-size 0`
disables completed-result caching, including typed child entries, while in-flight
coalescing remains enabled. Automatic cache sizing uses the resolved global size. A fixed 128-entry
source-address admission table caps each client at eight allocated operations and
32 pending waiters across operations. These bounds limit the optional coordinator,
not default passthrough service admission: when coordination capacity is full,
passthrough requests continue through the ordinary native request path. Explicit
aggregate and address modes retain bounded rejection because its fanout requires coordination. Source ports/ECS do not create new quota
identities; IPv4-mapped IPv6 shares the IPv4 identity. Owner quota remains charged
until late callbacks retire, preventing cancellation from resetting admission.
Entries are reclaimed when both counters reach zero. Aggregate capacity exhaustion
returns a bounded failure; it does not create unbounded waiting work. The first
operation's parent budget bounds every coalesced caller's dependency; there is no
cross-parent typed-query joining and no cancellation of unrelated work. Closing a
downstream connection removes only its waiters; losing the last waiter cancels
the shared budget in all modes and blocks deferred/retry sends. An individual
HTTP/2 RST_STREAM removes only that stream's waiter, leaving siblings and the
physical connection usable. Normal request END_STREAM does not cancel a waiter.
Reset detection runs after HTTP/2 polling even when there is no readable item for
the already-consumed request.
Ordinary A/AAAA neither allocate coordinator state nor issue extra queries.
Compatible cache-enabled native lookups retain only the separate bounded
address-proof set described above; cache-size 0 skips that allocation.

## Verification status

`AnyBounded.*` are pure wire helper fixtures; `AnyConfig.*` exercise strict
configuration parsing; `AnyOffline.*` use only local loopback mock DNS endpoints.
The corrected offline fixtures explicitly echo each request's question and check
response ID/question/rcode/RDATA; DO/CD cases also inspect outgoing upstream flags.
They include `DefaultFailureFirstCannotMaskHealthySibling`,
`DefaultFailureWaitsForDeferredHealthySibling`,
`DefaultRefusalCannotMaskMinimalHinfoSibling`,
`DefaultAllFailuresRetainTheFirstBoundedResponse`,
`DefaultLastWaiterCancellationStopsDeferredAdmission`,
`DefaultLastWaiterCancellationStopsRetry`, `Http2ResetOnlyCancelsItsWaiter`, and
`LastHttp2ResetCancelsFallbackButKeepsConnectionUsable`. The last two live in
`test/cases/test-http2.cc` and reuse its local TLS/H2 client. The exact required case names are maintained in the native result gate.
`AnyAddress.*` additionally checks both address families, strict negative/error
provenance, coherent CNAMEs, native positive-cache reuse, shared budgets and
in-flight coalescing using loopback fixtures. The comparative driver keeps
ordinary baseline/candidate ANY cases plus matched default A and AAAA cold/hot
and cache-zero duplicate/unique bursts. Typed cases require every answer, exact
cold/unique and zero hot sends, and bounded measured duplicate coalescing.
It separately reports candidate-only address workloads, including raw per-query
latency, CPU, process high-water RSS and actual typed send counts. These
measurements expose proof overhead; no performance equivalence is assumed.

They are authored regression cases, not evidence of execution until the combined
batch's build/test report is available. Independent review of the final diff,
actual-send accounting, race/cancellation handling and sanitizer results is still
required. No production-provider interoperability or performance claim is made.


Address completion retains at most eight coherent upstream evidence paths per
native typed child (32 KiB of wire evidence). Native speed selection can receive
different valid aliases from different upstreams or protocols; an unused path is
not a conflict. Visible CNAME output still requires a coherent selected path and
a coherent cross-family join. With explicit `force-no-CNAME yes`, each selected
native address is checked against the validated candidate paths and emitted at
the original owner, respecting the native alias-suppression policy. This can
combine independently selected A and AAAA canonical paths without exposing an
inconsistent CNAME. Alias TTL bounds remain conservative. Evidence-pool overflow,
unproven selected addresses and genuinely inconsistent negative results fail
closed; this does not expand the shared transport-attempt or alias-depth budgets.
