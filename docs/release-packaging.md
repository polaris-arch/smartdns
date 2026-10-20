# Polaris release packaging

The upstream reference is [`pymumu/smartdns`](https://github.com/pymumu/smartdns):
[release workflow](https://github.com/pymumu/smartdns/blob/master/.github/workflows/release.yml)
and [Release48.4 assets](https://github.com/pymumu/smartdns/releases/expanded_assets/Release48.4).
The workflow was compared with upstream commit
`dfc9ef4bd947891178924c06070fbccc3ea370ba`.

## Names and versions

- Preserve the upstream build version `1.YYYY.MM.DD-HHMM`. It is independent
  of the human-selected release tag; do not use a tag such as `Release48.4`
  as the package version.
- Preserve package formats, CPU/platform identifiers, package metadata,
  dependencies, archive layout, installed executable names and service names.
  `package/` is unchanged by Polaris distribution naming.
- Add `-polaris` only to each uploaded filename, before the entire extension:
  `smartdns.1.2026.08.05-0921.x86_64-linux-all-polaris.tar.gz`,
  `luci-app-smartdns.1.2026.08.05-0921.all-luci-all-polaris.ipk`,
  and `smartdns-x86_64-polaris`.
- The `all` build matches upstream's 39 uploaded assets: 6 raw binaries,
  5 LuCI packages, 4 packages each for MIPS/MIPSEL, and 5 packages each for
  ARM/AArch64/x86/x86_64. GitHub additionally supplies its own source archives.
  Polaris retains the existing `SHA256SUMS` manifest.

## CI and publication

Ordinary C/C++ CI builds and tests; it does not publish packages. Run
**Build and Release Artifacts** (`release.yml`) to run the full validation gate,
build packages and retain an Actions artifact before publishing:

- `target: all` (default), `release_tag: ''`: refresh **`nightly-polaris`** as a
  prerelease pinned to the exact built commit. This never touches upstream-style
  `nightly`. There is no added push or schedule trigger.
- `target: all`, `release_tag: ReleaseN[.N...]-polaris`: publish an already-created
  normal stable tag at the exact workflow commit. Both manual and release-event
  paths validate its name and commit. A version is never guessed from whichever
  upstream release happens to be latest. The former custom `-polaris.N`
  revision scheme is not used.
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
The rename changes no package bytes. `SHA256SUMS` covers the final public names.
Release runs are serialized. Nightly cleanup accepts only confirmed HTTP 404
absence, stops on deletion/API errors, and only removes `nightly-polaris`.
Its tag is verified absent before publishing and verified at the exact built
commit afterward; a stale tag can never silently pass the release job.

Run the build-free contract checks with:

```sh
python3 .github/scripts/prepare-release-assets.py --self-test
```
