Bundled QUIC dependency
=======================

`dependencies/openssl.json` pins the OpenSSL 3.5 LTS archive, its size and SHA256,
and the common static configuration. `scripts/openssl-dependency.py` is shared
by the native QUIC profile and all release cross-compilers. A cache hit still
verifies the compiler/recipe/patch identity and every installed header/archive.
Linker maps identify the static archives actually consumed by the core/tests.

The lifecycle patch requires an absent API/accept owner, completed send ACK
obligations and an accounted receive final size before stream collection.
It also repairs control-frame loss regeneration without a send buffer, prevents
late loss from resurrecting an acknowledged reset, and returns unread byte
credit once before the tick's transmit pass. Generic connection teardown and
MAX_STREAMS accounting keep their separate ownership.

The existing QUIC CI job builds two bounded variants: patched and pristine 3.5.9.
Dependency regressions link their real static archives and exact private headers;
private consumers also use `-DNDEBUG` to match the release library's list layout.
Their own CHECK and GTest assertions remain enabled.
each pristine run must fail by a controlled test assertion, never a timeout or
sanitizer crash. The native suite tests real persistent H3/DoQ request batches,
cancellation, reset and reconnect, with typed stream counts read under the
connection lifetime ownership and the SDK engine mutex. Real payload fills an
earlier FIN gap, and a partial read followed by a decoded RESET checks buffer
references and once-only byte retirement. A tiny advertised window verifies
that one actual channel tick returns unread credit and unblocks a real peer.
Relinking identical native objects against pristine archives supplies its
negative control. The secondary slot is then reused for the unsanitized library
shared by both application variants in the offline comparison.

All builds and candidate executions run in CI. Ordinary system/non-QUIC coverage
is retained. The private test probe is never linked into a distributed binary.
Consumers building against a system OpenSSL (including external OpenWrt SDK
libraries) need a correspondingly repaired library; changing this repository's
bundled dependency does not replace those external installations.
