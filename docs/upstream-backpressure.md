# Upstream rate and backpressure policy

This change is based on upstream master dfc9ef4bd947891178924c06070fbccc3ea370ba. It replaces the fork's isolated HTTP/2 429/503 prohibition exception with bounded request ownership and scheduling. It does not rotate connections to evade provider accounting.

## Configuration

Each server line accepts:

| Option | Meaning | Default / range |
|---|---|---|
| `-max-query-rate N` | Token refill in DNS request starts per second | 0 disables proactive rate limiting; 0..1,000,000 |
| `-query-burst N` | Maximum immediately available tokens | 1 when a rate is enabled; 1..65,535; requires enabled rate |
| `-max-concurrent-queries N` | Endpoint-local active attempt admission, including queued handshakes | 0 disables proactive cap; 0..65,535 |
| `-quota-group NAME` | Explicitly share rate/burst/cooldown among configured endpoints/transports | No sharing by default |

Members of a quota group must agree on rate and burst; conflicting configuration fails instead of taking the last value. Inflight is endpoint-local, not silently shared. An unconfigured unrelated upstream is not charged to another upstream's quota group. A provider may have unpublished quotas; disabled proactive limits do not disable reaction to actual HTTP backpressure.

Example local policy, not an official Tencent quota or per-connection guarantee:

```
server-https https://doh.pub/dns-query -max-query-rate 10 -query-burst 1 -max-concurrent-queries 5
```

Use a quota group only when the administrator intentionally wants shared accounting, for example across equivalent encrypted transports of the same service. Tencent's published Public DNS guidance describes a per-domain 20QPS figure; issue #2457's author observed 429 at high request rate despite concurrency=5 and withdrew the concurrency-only diagnosis. These observations do not establish a universal per-IP, per-connection or cross-transport quota.

## Scheduling and ownership

- Admission happens before socket/stream allocation. A denied endpoint is skipped/deferred while other group members remain usable.
- Request-start tokens are consumed separately at first wire-start admission. A handshake or HTTP/2 peer-capacity queue cannot accumulate an unrestricted later burst. Partial writes continue the same attempt.
- HTTP/2 peer SETTINGS limits are retained independently. HTTP/1.1 uses ordered owners and one started request per connection; canceled sent requests remain identifiable until consumed or connection close.
- HTTP 429/503 establish a monotonic cooldown. Integer or HTTP-date Retry-After is a minimum; malformed/missing values use bounded exponential local backoff with jitter. No DNS cache TTL is derived from Retry-After. HTTP Age reduces DNS RR TTLs independently.
- Existing periodic scans wake deferred work without relying on writable socket edges. Reconnect and callback retries return through this same budgeted path.
- Each destination has at most four request starts (initial send plus three retries) per logical query. Ordinary total attempt capacity is four times the initial selected-plus-fallback group membership; it is not a fixed 16-entry cap. Ordinary absolute lifetime is derived from existing four 500ms retry constants. Making that lifetime absolute intentionally prevents callbacks/deferral from extending it indefinitely; it is not identical to every historical retry timing.
- A terminal transition and attempt retirement are idempotent. Admission queues, HTTP responses without DNS bodies, timeout, cancellation and transport close must not independently decrement the same attempt.

## Protocol prerequisites and validation status

DoQ now requires zero wire DNS ID, exactly one advertised-length response and FIN before success. HPACK uses all RFC 7541 Appendix B octets and rejects EOS/invalid padding. HTTP/3 has a bounded connection-control helper with SETTINGS, critical-stream ownership, GOAWAY and static-only QPACK rules. No dynamic QPACK or alternate transport stack is introduced. Large unknown request-stream frames still face the existing fixed response-buffer limit; streaming discard of arbitrary-size unknown request frames is not claimed.

Source and test authoring do not prove interoperability. The candidate requires independent lifetime/protocol review, native no-QUIC and QUIC-capable builds, loopback strict-peer fixtures and sanitizer runs. No public-provider load test is part of this change. Tencent DoQ/H3 service availability has not been established by the cited official documentation.

References: [issue #2457](https://github.com/pymumu/smartdns/issues/2457), [PR #2458](https://github.com/pymumu/smartdns/pull/2458), [HPACK PR #2446](https://github.com/pymumu/smartdns/pull/2446), [RFC 7541](https://www.rfc-editor.org/rfc/rfc7541), [RFC 9114](https://www.rfc-editor.org/rfc/rfc9114), [RFC 9204](https://www.rfc-editor.org/rfc/rfc9204), [RFC 9250](https://www.rfc-editor.org/rfc/rfc9250).

### Correction batch after independent review

Queued transport work keeps its query owner until positive write progress. A QUIC
control/stream-credit wait does not start the 500 ms response timer. Cancellation
and the absolute deadline also gate partial-write continuation. An uncertain SSL
write is never refunded; if it made no reported progress, its next write must pass
rate admission again. The logical send reservation is charged once, while each
uncertain retry consumes pacing capacity. HTTP/2 retains the encoder's current
write owner and uses the existing periodic scan when quota admission is blocked.

TCP/DoT/H1 pending writes retain a bounded 4096-byte send buffer plus metadata.
They do not allocate an unused 32 KiB receive buffer. H2 obtains that receive
buffer when encoding starts (including ALPN conversion); DoQ/H3 allocate it with
the stream. These are source-derived allocation bounds, not measured RSS or
latency results. Native regression and performance validation remain pending.

H3 GOAWAY retires excluded queued requests without treating a healthy draining
connection as failed. Request-stream SETTINGS/reserved frames, forbidden push,
and invalid QPACK select connection application errors. Malformed HTTP messages
remain stream-local. A QUIC response requires the actual OpenSSL FINISHED read
state; an abnormal zero return is not a successful FIN.

Backpressure warning output is bounded to one warning per configured policy
object per 30 seconds, carrying a cumulative backpressure-event count. Other
per-response diagnostic lines are DEBUG. Retry-After accepts all three HTTP-date
forms and rejects normalized invalid calendar dates; the resulting cooldown is
stored against the monotonic clock.

HTTP/2 deferred DATA ownership includes the stream's flow-controlled body and
pending END_STREAM, even when the connection has no encoded bytes waiting to
write. One request retains the encoder owner until both layers are empty. A
canceled/expired owner with only an unsent body is aborted before the next poll,
so a WINDOW_UPDATE cannot revive it; already encoded partial bytes require a
safe connection close. The BIO admission check remains the final guard against
cancellation racing a poll. Upstream cleanup uses abort/discard, while downstream
response code retains graceful flush-and-close. This intentionally serializes
request encoding while a prior request body is flow-control blocked; completed
requests may still await responses concurrently.

## Native validation entry and its limits

The existing `.github/workflows/c-cpp.yml` runs one complete, unfiltered GoogleTest suite in each of two distribution environments: Ubuntu 24.04 system OpenSSL (non-QUIC compile coverage), and Debian trixie OpenSSL 3.5 or newer with QUIC enabled. Both reuse the original `make all`, `make clean`, and `make -C test` paths. Required `StrictPeer`, H3, H2 ownership, ANY, and policy test names are checked in the XML result; a missing/skipped critical case is a failure, not successful protocol coverage. All other skips remain visible in the artifact logs. The existing local `Perf`/`Stress` cases remain in the suite at their existing defaults; no new load multiplier is set.

Only distribution dependency preparation has network access. Build and test execution use Docker `--network none`, without privileged mode, with IPv4/IPv6 loopback checked before starting. Existing bootstrap coverage resolves `example.com` through an explicit loopback mock. The old unreachable-address negative cases cannot send public traffic. If offline assumptions fail, CI fails rather than restoring public access or skipping cases. Results, linked-library information, compiler/package versions, image identity, and exact source SHA are uploaded for each environment. Native execution is bounded by the workflow job timeout; timeouts are failures.

The first candidate run uses the exact `dots/upstream-backpressure-any-20261019` push trigger. `workflow_dispatch` is retained, but GitHub's default-branch availability rule means it is not a guaranteed first-run entry for a workflow that exists only on a candidate branch. Do not dispatch a duplicate run after that push.

A green run demonstrates only the fixtures that actually ran. In particular, the existing DoQ strict case checks framing on the shared QUIC fixture connection, not production DoQ ALPN/provider interoperability. The H2 flow-owner live sibling case checks the complete upstream request, not a complete downstream DNS reply. The combined real ANY cancellation → upstream H2 zero window → WINDOW_UPDATE → healthy sibling complete DNS response case is now authored as `AnyOffline.UpstreamZeroWindowCancelThenUpdatePreservesCompleteSiblingDns`, using the existing loopback TLS mock peer. It observes real upstream HEADERS, SETTINGS acknowledgments, RST_STREAM(CANCEL), DATA and emitted WINDOW_UPDATE, and validates the complete sibling DNS answer on the same connection. This fixture has not yet been executed; the acceptance gap remains open until its native run succeeds. It currently covers a late WINDOW_UPDATE after cancellation has propagated, while the memory-BIO cases separately cover pre-cleanup cancellation and query pruning. No production testing hook is introduced. Concurrency sanitizer coverage and quantified resource/performance validation are also separate pending acceptance evidence.

### Runtime repair candidate after the first complete offline attempts

H2 request submission now only publishes a buffered owner and arms the existing
level-triggered writable event. Frame encoding, stream selection and write-owner
changes stay on the client event loop; a failed event publication withdraws both
queue references under the same publication lock. Existing periodic pumping,
flow-control and cancellation checks remain in place. This removes an identified
concurrent-encoder path, but does not establish that every observed heap failure
is fixed until the full native stress and sanitizer runs succeed.

Ordinary per-destination and total send caps use the existing `DNS_QUERY_RETRY`
constant (four), while explicitly supplied shared budgets, including ANY, retain
their own smaller limits. A marked fallback endpoint becomes eligible after the
first nominal 500 ms attempt interval; a separately configured fallback group is
selected for the final nominal round. The prior fallback test's one-second floor
was tied to an incidental idle-scan delay, not a one-second fallback policy. Its
replacement uses a live silent primary, checks primary-before-fallback ordering,
one fallback request, bounded primary sends and the actual 500 ms retry floor.
The no-response regression now requires exactly four sends for one question.

Stress UDP clients have a five-second receive bound so a dead resolver produces a
failed assertion instead of blocked thread joins. Startup results are asserted;
all configured queries and the original zero-failure requirement remain mandatory.
These changes and their added ownership/budget regressions are source-authored,
not native-validated. Full system/QUIC suites and the observed H2 stress cases must
complete successfully; no failure or missing result is converted to a skip.
