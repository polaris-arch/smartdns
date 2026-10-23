# Native dashboard service-pool compatibility

This repository owns a small **source patch**, not a fork or generated bundle, for
`pymumu/smartdns-webui` commit `1c06fee693434ec7c71f06010d3f87416baba9f0`.
`source.conf` records the immutable codeload URL and archive SHA-256. On
2026-10-22 the archive in the native-panel evidence directory and an independent
fresh download from that exact URL both hashed to
`7a698dd4826750869429e83d91ce99a4e474d0809588a7f4124ef86875be9b1f`.
This replaces the moving `main.zip` generic build and OpenWrt's older
`35cbf4a1940f5dd32670c69bd5cc02437ad073e7` webui pin.

The optional REST fields include `service_id`, `pool_enabled`, `endpoint_ips` and
`diagnostics`. The diagnostic disclosure keeps the existing success-rate formula
and shows coherent query totals, separate terminal contexts, last wait states,
last observed errors, event counts and the global client-thread CPU sample.
Each outcome dimension closes to its own failure/skip total; events may repeat
and must never be added to query counts. Fixed HTTP cooldown is 1000ms by default,
configurable from 1 to 10000ms; Retry-After is recorded as evidence only.
The mounted upstream table keeps one row per API service, shows its domain in
Host and actual endpoint IP list in IP, and uses the stable service ID as the
MaterialReactTable row identity. Ordinary rows retain the upstream's default
index identity and unchanged display. The fixed dashboard does not mount its
legacy overview component; this patch does not modify or add that component.

Upstream response times retain the deployed two-decimal display fix; invalid or negative values show N/A. The API keeps its original precision.

Both build hooks verify the archive before extraction, verify exact full-file
preimages, apply with no fuzz, and verify exact postimages. `prepare-source.sh`
requires a new destination and never trusts an existing output. Generic builds
always use a fresh temporary source and `npm ci`, then replace their old build
only after success; OpenWrt compilation discards its old extracted source,
prepares it afresh with the same script, then uses `npm ci`. There is no unverified `out/index.html`
shortcut. npm itself requires its normal host toolchain and registry/cache.

OpenWrt's webui download uses the exact HTTP archive and SHA-256, not a different
git-generated tarball. Its package core source must contain this patch and
preparation script; the historical core release pin is deliberately not changed
here (the release owner must select the reviewed core commit). An old core
archive without the preparation script fails rather than silently building the
unpatched dashboard. Full OpenWrt SDK compilation is a separate release gate.

Offline regression (does not download or build):

```sh
package/webui/test-prepare-source.sh /path/to/pinned-webui.tar.gz
```

It checks clean preparation, refusal to overwrite existing source, bad archive,
wrong preimage/patch/postimage rejection, and OpenWrt pin parity. Type checking,
production build, actual component/browser behavior with real service API JSON,
and final package contents remain independent gates; source inspection alone
cannot establish them. No API proxy, websocket changes, or collector changes
are included.

Actual browser validation (existing Playwright/browser installation, no install):

```sh
PLAYWRIGHT_MODULE=/path/to/playwright CHROMIUM_EXECUTABLE=/path/to/chrome \
  node package/webui/test-browser.cjs WEBUI_OUT CAPTURED_API_JSON REPORT_DIRECTORY
```

The JSON is produced by the real core/plugin REST integration test with
`SMARTDNS_SERVICE_API_EVIDENCE=/path/to/captured.json`; the fixture contains three
same-protocol pools (two share authority but differ in path) and one ordinary
numeric upstream. The script serves the actual built frontend, uses the real sidebar upstream route and checks one-row endpoint details,
the real toolbar refresh, and direct page reload, and records screenshots and errors.
Only auxiliary UI authentication/empty charts are scaffolded; this is not an
API-authentication test or performance measurement. Browser sandboxing stays on;
unsupported sandbox environments must report a blocked test, never disable it.

Pinned-route correction: the fixed upstream dashboard does **not** mount the
legacy `UpStreamServersCard`; it only mounts metrics/charts. The earlier browser
fixture incorrectly waited for a dead component and never requested upstream
data. The unused legacy overview patch and its source-image dependency have been
removed; no overview widget is added or claimed as runtime-validated. The real
`/dashboard/upstream-servers` table is the runtime acceptance target. No component
is mounted artificially and no React state is injected. Failure capture includes
HTML, screenshot, current URL/stage, requests/responses and console errors.

`--server-check` as a fourth argument exercises the same local HTTP server with
real exported HTML/RSC text/segments, unchanged captured API bytes, malformed URL
and traversal rejection, without loading Playwright or starting a browser. This
is a serving-contract test only, not a browser pass. Browser interception restricts
page HTTP/WS requests to the temporary origin; it is not an OS-level firewall or
a claim that Chrome's own background services never attempt network access.

`test-table-identity.cjs PREPARED_SOURCE ACTUAL_API_JSON REPORT` verifies the exact
postimage, extracts the actual table's `getRowId` option, and exercises the installed
TanStack row model before/after a data reorder. Repeated ordinary rows are compared
to TanStack's unchanged default-index behavior. This bounded dependency/source
check supplements, rather than replaces, the actual browser refresh acceptance.
