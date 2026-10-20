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
families must complete coherently. Two positive results return both families;
one positive plus genuine upstream SOA-backed NODATA returns a single family.
Timeout, transport failure, policy-generated SOA, malformed/incomplete data, or
an unsupported context cannot stand in for an absent family: the result is
SERVFAIL. Consistent NXDOMAIN remains distinct from NODATA; conflicting aliases
or positive/NXDOMAIN results fail. This represents DNS addresses supplied by the
configured resolver and supported rules, not reachability or all zone records.

The family set is always A+AAAA, concurrency is two, and partial results are
always disabled. Valid `any-aggregate-types`, `any-aggregate-concurrency`, and
`any-aggregate-partial` settings are retained for compatibility but have no
effect while address mode is selected. They take effect again when switching
back to aggregate. Invalid settings still fail ordinary configuration parsing.
The existing `any-aggregate-max-attempts` (default 16, range 1–64) and
`any-aggregate-timeout-ms` (default 950, range 1–950) bound the whole operation,
including both families and nested work. Each child does not receive a new
budget. Rule-group inheritance and explicit group overrides apply to all modes.

Address requests use bounded equivalent-request coalescing and validated fresh
positive entries from the ordinary A/AAAA cache whose in-memory origin was
recorded as a compatible plain upstream lookup. Legacy/persisted entries and
entries from ECS, DNSSEC/CD or unsupported policy contexts are refetched; packet
flags alone do not prove their original context. They do not reuse ordinary
pending-query leaders with unrelated budgets. Negative/expired native cache
entries are not proof of upstream absence and are not reused for completion.
The provenance flag is set only by an actual compatible upstream lookup;
packet, origin and TTL metadata are acquired together. Legacy and metadata-only
replacements revoke the flag. This does not change ordinary cache behavior.
Original upstream packets must also validate as complete positive Answers, and
every selected address in the cache packet must be a subset of those proven
Answers. A native reconstruction of truncated or Additional-only data cannot
gain trusted provenance. The proof set is bounded to 64 addresses per compatible
live request; overflow or allocation failure disables this reuse.
Proof is collected only for native requests in an address-enabled group with
caching enabled, including ordinary A/AAAA warmers in that group. The narrow
allocation-free validator accepts direct positive Answers without CNAME or
authority, with at most one empty root OPT. Positive packets with authority or
glue are refetched for address completion; ordinary resolution is unchanged.
The retained proof is at most 64 × 16 address bytes plus counters and a mutex;
validation uses a 64-address stack scratch set and bounded name storage, not
the general merger's temporary heap buffers.
Cached CNAME packets are also refetched because the legacy cache may retain a
collapsed alias chain without the original complete-chain provenance.
There is no separate combined address-result cache. `cache-size 0` disables
completed caching while preserving in-flight coalescing. Address-owned children
suppress recursive cross-family preference checks, so a preferred-family policy
cannot masquerade as an absent family. Ordinary A/AAAA client requests retain
their existing behavior.

The conservative context restrictions below also apply to address mode, but an
unsupported address request fails explicitly instead of falling through to an
upstream minimal ANY answer. In particular, ECS, DO/CD/AD, DNS64, local address
rewrites and unsupported policy contexts are not claimed as supported.
Address admission runs before early parent policy replies; forcing SOA for
QTYPE 255 or configuring a local address block cannot manufacture a completed
NOERROR address result.
Capacity exhaustion is a bounded failure in this opt-in mode.

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

Sharing/aggregation is limited to IN, RD=1, no client DO/CD/AD, no ECS, and no
unrecognized EDNS options/flags. Configured endpoint/fallback ECS and rule-group
ECS also disable it. Existing policy rewrites, IP rules, parent/CNAME processing,
DNS64, forced CNAME suppression, cache-disabled requests and unsupported contexts
use the normal transparent path in passthrough/aggregate modes; address mode
returns a bounded failure. Original ANY DO/CD are propagated even though
legacy non-ANY parsing treats AD/DO differently. Non-IN remains unsupported.
Some clients enable AD/cookies by default; such queries deliberately bypass this
first conservative implementation rather than sharing an unproven context.

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
