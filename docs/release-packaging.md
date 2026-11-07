# Polaris release packaging

The upstream reference is [`pymumu/smartdns`](https://github.com/pymumu/smartdns):
[release workflow](https://github.com/pymumu/smartdns/blob/master/.github/workflows/release.yml)
and [Release48.4 assets](https://github.com/pymumu/smartdns/releases/expanded_assets/Release48.4).
The workflow was compared with upstream commit
`65832a19c248f8a0f8714304d819e1da408b3835` (2026-11-07).

## Names and versions

- Preserve the filename/application build version `1.YYYY.MM.DD-HHMM`, generated
  consistently in `Asia/Singapore`. It is independent
  of the human-selected release tag; do not use a tag such as `Release48.4`
  as the package version.
- Debian package metadata uses `1:1.YYYY.MM.DD-HHMM+polaris.RUN.ATTEMPT`.
  Epoch 1 sorts above every ordinary epoch-0 repository version, including a
  later date or upstream release number. Same-minute workflow runs/retries sort
  by numeric run number/attempt. Debian architectures are explicit (e.g. amd64),
  rather than `all` for a package containing native code. Both fields are read
  from every actual DEB before and after distribution renaming.
- Package names, dependencies, archive layout, executable names and service
  names retain upstream compatibility. APK/IPK keep native upstream versions:
  a filename suffix cannot prevent feed upgrades. Use the platform's version
  lock when mixing those packages with an official feed. Do not claim Debian's
  epoch protection for APK or legacy IPK. Existing APT holds/preferences remain
  a separate device policy; this release does not remove them. Explicit forced
  downgrades or replacement outside the package manager are not version ordering.
- Add `-polaris` only to each uploaded filename, before the entire extension:
  `smartdns.1.2026.08.05-0921.x86_64-linux-all-polaris.tar.gz`,
  `luci-app-smartdns.1.2026.08.05-0921.all-luci-all-polaris.ipk`,
  and `smartdns-x86_64-polaris`.
- The `all` build matches upstream's 39 uploaded assets: 6 raw binaries,
  5 LuCI packages, 4 packages each for MIPS/MIPSEL, and 5 packages each for
  ARM/AArch64/x86/x86_64. GitHub additionally supplies its own source archives.
  Polaris retains the existing `SHA256SUMS` manifest.

## CI and publication

Upstream's ordinary native and WebUI jobs remain the baseline: build and test,
with publishing reserved for the release workflow. Polaris additionally retains
both non-QUIC and QUIC native profiles, complete release ASan/UBSan suites,
critical-case execution checks, locked source inputs and package identity checks.
The historical offline comparison remains a release gate because its real
HTTP/1.1 sustained-429 recovery case is not replaced by the HTTP/2 tests.
The explicit WebUI `full_validation`/OpenWrt SDK workflow is unchanged; it is
not part of ordinary push or release validation. A changed SDK source still
requires a matching source archive pin and its separate SDK acceptance.

Release packaging builds the architecture-independent static pages once instead
of invoking npm for each of the 14 UI packaging calls. All 18 full-distribution
UI packages must contain that exact static file inventory and bytes; the C/Rust
builds and per-architecture plugin checks still run independently. A job-local
manifest binds the pages to source/patch/lock inputs and the run/attempt/commit.
`SMARTDNS_WEBUI_MANIFEST` is an explicit same-job reuse input, not a persistent
cache. A changed input, missing/extra output, symlink or foreign run fails closed.
Without it, `package/build-pkg.sh` still builds fresh pinned pages as before.

Ordinary C/C++ CI builds and tests; it does not publish packages. Run
**Build and Release Artifacts** (`release.yml`) to run the full validation gate,
build packages and retain an Actions artifact before publishing:

- `build_only: true`: run all checks and retain packages/evidence in Actions
  without publishing or changing a tag or Release.
- `target: all` (default), `release_tag: ''`: refresh the prerelease with display
  name **`nightly-polaris`**, keeping the upstream tag name **`nightly`** and
  pinning it to the exact built commit. No `nightly-polaris` tag is created or
  modified. There is no added push or schedule trigger.
- `target: all`, `release_tag: ReleaseN[.N...]-polaris`: publish an already-created
  normal stable tag at the exact workflow commit. Both manual and release-event
  paths validate its name and commit. A version is never guessed from whichever
  upstream release happens to be latest. The former custom `-polaris.N`
  revision scheme is not used. Fork calendar tags such as
  `Release2026.10.27-polaris` identify Polaris releases independently of upstream
  release numbering; package timestamps still come from the actual build.
- A published GitHub release also invokes the workflow. Its existing tag must
  pass the same check; its prerelease flag is preserved.
- `target: x86_64` is an explicitly selected partial build (6 uploaded binaries/
  packages); use `all` for upstream-aligned full distribution.

Normal stable tags accept an integer release number and optional dotted numeric
components, e.g. `Release48-polaris` and `Release48.4-polaris`. Historical upstream
RC, Special and proxy-server tags are not implicitly treated as stable releases.
Those need a separately reviewed prerelease path if requested.

After successful native validation, the release checks require the exact
nonempty asset set before renaming anything. Missing APKs, unexpected files and
symlinks fail the workflow instead of silently publishing an incomplete set.
The rename changes no package bytes; the Debian metadata policy is applied by
the package builder beforehand. `SHA256SUMS` covers the final public names.
Release runs are serialized. Nightly cleanup accepts only confirmed HTTP 404
absence, stops on deletion/API errors, and only removes the `nightly` tag/release.
No other tag, including `nightly-polaris`, is deleted or updated.
Its tag is verified absent before publishing and verified at the exact built
commit afterward; a stale tag can never silently pass the release job.

Run the build-free contract checks with:

```sh
python3 .github/scripts/prepare-release-assets.py --self-test
```

System package archives use numeric UID/GID 0 for installed files, directories, and control scripts. Debian builds normalize ownership independently of the CI account; release validation rejects a DEB whose control or filesystem archive contains another owner. Linux and LuCI archives use the same root ownership convention as the OpenWrt and Optware packages.

APKv3 builds use private package directories and normalize a helper-owned snapshot with real root privileges (root or noninteractive sudo). The helper rejects invalid or linked input/output paths, leaves the original staging tree untouched, extracts the completed package as root into a private verification directory, and rejects any extracted file or directory whose numeric UID/GID is not 0. The private snapshot and verification files are removed on exit. This also covers statically linked apk-tools, where LD_PRELOAD fakeroot does not apply.
