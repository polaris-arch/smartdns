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

## Response and cache semantics

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
use the normal transparent path. Original ANY DO/CD are propagated even though
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
aggregate mode retains bounded rejection because its fanout requires coordination. Source ports/ECS do not create new quota
identities; IPv4-mapped IPv6 shares the IPv4 identity. Owner quota remains charged
until late callbacks retire, preventing cancellation from resetting admission.
Entries are reclaimed when both counters reach zero. Aggregate capacity exhaustion
returns a bounded failure; it does not create unbounded waiting work. The first
operation's parent budget bounds every coalesced caller's dependency; there is no
cross-parent typed-query joining and no cancellation of unrelated work. Closing a
downstream connection removes only its waiters; losing the last waiter cancels
the shared budget in both modes and blocks deferred/retry sends. An individual
HTTP/2 RST_STREAM removes only that stream's waiter, leaving siblings and the
physical connection usable. Normal request END_STREAM does not cancel a waiter.
Reset detection runs after HTTP/2 polling even when there is no readable item for
the already-consumed request.
Ordinary A/AAAA neither allocate this state nor issue extra queries.

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
`test/cases/test-http2.cc` and reuse its local TLS/H2 client. There are 22 offline,
23 wire-helper, and 5 configuration cases in these suites.

They are authored regression cases, not evidence of execution until the combined
batch's build/test report is available. Independent review of the final diff,
actual-send accounting, race/cancellation handling and sanitizer results is still
required. No production-provider interoperability or performance claim is made.
