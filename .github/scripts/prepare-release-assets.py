#!/usr/bin/env python3
"""Check upstream's release asset set and add a distribution-only suffix.

The upstream timestamp version is deliberately independent of its ReleaseN tag.
Only outer filenames change; package bytes and installed names are never edited.
See docs/release-packaging.md for the upstream reference and release contract.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
from types import SimpleNamespace
import unittest


ARCHITECTURES = ("mips", "mipsel", "arm", "aarch64", "x86_64", "x86")
EXTENSIONS = (".tar.gz", ".ipk", ".apk", ".deb")
NIGHTLY_TAG = "nightly-polaris"


def gh_api(endpoint, method="GET", missing_ok=False, runner=subprocess.run):
    """Return JSON, accepting only an explicit 404 when absence is permitted."""
    result = runner(
        ["gh", "api", "--include", "--method", method, endpoint],
        text=True, capture_output=True, check=False,
    )
    response = result.stdout.replace("\r\n", "\n")
    status = re.match(r"HTTP/\S+ ([0-9]{3})(?:[ \n])", response)
    if status is None:
        raise ValueError(f"{method} {endpoint}: no HTTP status; refusing to continue")
    status = int(status.group(1))
    if status == 404 and missing_ok and method == "GET":
        return None
    expected_status = 204 if method == "DELETE" else 200
    if result.returncode != 0 or status != expected_status:
        raise ValueError(f"{method} {endpoint}: HTTP {status}; refusing to continue")
    if status == 204:
        return {}
    try:
        return json.loads(response.split("\n\n", 1)[1])
    except (IndexError, json.JSONDecodeError) as error:
        raise ValueError(f"{method} {endpoint}: malformed JSON response") from error


def repo_endpoint(repository):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("repository must be owner/name")
    return f"repos/{repository}"


def clean_nightly(repository, api=gh_api):
    """Refresh only the Polaris nightly, failing closed on any uncertain write."""
    base = repo_endpoint(repository)
    release = api(f"{base}/releases/tags/{NIGHTLY_TAG}", missing_ok=True)
    if release is not None:
        if release.get("tag_name") != NIGHTLY_TAG or not isinstance(release.get("id"), int):
            raise ValueError("unexpected nightly release identity")
        api(f"{base}/releases/{release['id']}", method="DELETE")
    # Release deletion alone does not delete its tag. Remove a stale tag even
    # when a previous interrupted run deleted only the release.
    ref_endpoint = f"{base}/git/ref/tags/{NIGHTLY_TAG}"
    ref = api(ref_endpoint, missing_ok=True)
    if ref is not None:
        if ref.get("ref") != f"refs/tags/{NIGHTLY_TAG}":
            raise ValueError("unexpected nightly tag identity")
        api(f"{base}/git/refs/tags/{NIGHTLY_TAG}", method="DELETE")
    if api(ref_endpoint, missing_ok=True) is not None:
        raise ValueError("nightly tag still exists after cleanup; refusing publication")
    print(f"Only {NIGHTLY_TAG} was refreshed; tag absence verified before publication.")


def verify_tag(repository, tag, commit, api=gh_api):
    if tag != NIGHTLY_TAG:
        check_tag(tag)
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("commit must be a full 40-character SHA")
    base = repo_endpoint(repository)
    ref = api(f"{base}/git/ref/tags/{tag}")
    if ref.get("ref") != f"refs/tags/{tag}":
        raise ValueError("unexpected published tag identity")
    obj = ref.get("object", {})
    seen = set()
    # Existing stable releases may use annotated tags; dereference to a commit.
    while obj.get("type") == "tag":
        sha = obj.get("sha", "")
        if not re.fullmatch(r"[0-9a-f]{40}", sha) or sha in seen:
            raise ValueError("invalid or cyclic annotated tag")
        seen.add(sha)
        obj = api(f"{base}/git/tags/{sha}").get("object", {})
    if obj.get("type") != "commit" or obj.get("sha") != commit:
        raise ValueError("published tag does not resolve to the exact built commit")
    print(f"Verified remote {tag} points to {commit}.")


def check_tag(tag):
    """Accept upstream's normal ReleaseN[.N...] tags with one Polaris suffix."""
    if not re.fullmatch(r"Release[0-9]+(?:\.[0-9]+)*-polaris", tag):
        raise ValueError(
            "stable tag must be an upstream-style ReleaseN[.N...]-polaris "
            "(for example Release48-polaris or Release48.4-polaris)"
        )


def expected_assets(version, target):
    if not re.fullmatch(r"1\.[0-9]{4}\.[0-9]{2}\.[0-9]{2}-[0-9]{4}", version):
        raise ValueError("package version must retain upstream's 1.YYYY.MM.DD-HHMM format")
    if target not in ("all", "x86_64"):
        raise ValueError(f"unsupported target: {target}")
    names = set()
    if target == "all":
        for package, platform, extensions in (
            ("luci-app-smartdns", "luci", (".ipk", ".apk")),
            ("luci-app-smartdns-lite", "luci-lite", (".ipk", ".apk")),
            ("luci-app-smartdns", "luci-compat", (".ipk",)),
        ):
            for extension in extensions:
                names.add(f"{package}.{version}.all-{platform}-all{extension}")
    for arch in ARCHITECTURES if target == "all" else ("x86_64",):
        names.add(f"smartdns-{arch}")
        for platform, extensions in (
            ("optware", (".ipk",)),
            ("openwrt", (".ipk", ".apk")),
            ("debian", (".deb",)),
            ("linux", (".tar.gz",) if arch not in ("mips", "mipsel") else ()),
        ):
            for extension in extensions:
                names.add(f"smartdns.{version}.{arch}-{platform}-all{extension}")
    return names


def distribution_name(name):
    for extension in EXTENSIONS:
        if name.endswith(extension):
            return f"{name[:-len(extension)]}-polaris{extension}"
    return f"{name}-polaris"


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def prepare(directory, version, target):
    expected = expected_assets(version, target)
    actual = {path.name for path in directory.iterdir()}
    if actual != expected:
        raise ValueError(
            f"upstream asset set mismatch; missing={sorted(expected - actual)}, "
            f"unexpected={sorted(actual - expected)}"
        )
    # Validate every file before changing any filenames: a partial/missing APK
    # build must fail instead of publishing an apparently successful release.
    for name in sorted(expected):
        path = directory / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
            raise ValueError(f"asset must be a nonempty regular file: {name}")
    for name in sorted(expected):
        (directory / name).rename(directory / distribution_name(name))
    # SHA256SUMS is metadata, not a package; keep the conventional manifest name.
    lines = [
        f"{sha256(directory / name)}  {name}\n"
        for name in sorted(distribution_name(name) for name in expected)
    ]
    (directory / "SHA256SUMS").write_text("".join(lines), encoding="utf-8")
    print(f"Verified and suffixed {len(expected)} upstream assets; wrote SHA256SUMS.")


class ContractTests(unittest.TestCase):
    version = "1.2026.08.05-0921"

    def test_upstream_counts_and_architectures(self):
        names = expected_assets(self.version, "all")
        self.assertEqual(len(names), 39)
        self.assertEqual(sum(name.startswith("luci-") for name in names), 5)
        for arch in ARCHITECTURES:
            self.assertIn(f"smartdns-{arch}", names)
        self.assertEqual(len(expected_assets(self.version, "x86_64")), 6)
        self.assertNotIn(f"smartdns.{self.version}.mips-linux-all.tar.gz", names)

    def test_suffix_before_compound_extension_and_luci(self):
        examples = {
            "smartdns-x86_64": "smartdns-x86_64-polaris",
            f"smartdns.{self.version}.x86_64-linux-all.tar.gz":
                f"smartdns.{self.version}.x86_64-linux-all-polaris.tar.gz",
            f"luci-app-smartdns-lite.{self.version}.all-luci-lite-all.apk":
                f"luci-app-smartdns-lite.{self.version}.all-luci-lite-all-polaris.apk",
        }
        for before, after in examples.items():
            self.assertEqual(distribution_name(before), after)
        for extension in EXTENSIONS:
            self.assertEqual(distribution_name(f"file{extension}"), f"file-polaris{extension}")

    def test_upstream_stable_tag_versions(self):
        for tag in ("Release48-polaris", "Release48.4-polaris", "Release48.4.1-polaris"):
            check_tag(tag)
        for tag in ("Release48.4", "Release48.4-polaris.1", "nightly",
                    "nightly-polaris", "v48.4-polaris", "Release48.4-polaris-polaris",
                    "Release48.4-polaris\n", "../Release48-polaris"):
            with self.assertRaises(ValueError, msg=tag):
                check_tag(tag)

    def test_bad_version_and_target(self):
        for version, target in (("48.4", "all"), (self.version + "-polaris", "all"),
                                (self.version, "arm")):
            with self.assertRaises(ValueError):
                expected_assets(version, target)

    def fixture(self, directory, target="all"):
        for name in expected_assets(self.version, target):
            (directory / name).write_bytes(f"unchanged package bytes: {name}\n".encode())

    def test_rename_preserves_every_byte_and_checksums(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            self.fixture(directory)
            before = {path.name: path.read_bytes() for path in directory.iterdir()}
            prepare(directory, self.version, "all")
            self.assertEqual(len(list(directory.iterdir())), 40)
            for name, contents in before.items():
                self.assertEqual((directory / distribution_name(name)).read_bytes(), contents)
            manifest = (directory / "SHA256SUMS").read_text().splitlines()
            self.assertEqual(len(manifest), 39)
            for line in manifest:
                digest, name = line.split("  ", 1)
                self.assertEqual(digest, sha256(directory / name))

    def test_x86_only_fixture(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            self.fixture(directory, "x86_64")
            prepare(directory, self.version, "x86_64")
            self.assertEqual(len(list(directory.iterdir())), 7)

    def test_missing_unexpected_empty_and_symlink_fail_before_rename(self):
        for problem in ("missing", "unexpected", "empty", "symlink", "directory"):
            with self.subTest(problem=problem), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                self.fixture(directory)
                victim = directory / "smartdns-mips"
                if problem == "missing":
                    victim.unlink()
                elif problem == "unexpected":
                    (directory / "unrelated.zip").write_bytes(b"unrelated")
                elif problem == "empty":
                    victim.write_bytes(b"")
                elif problem == "symlink":
                    victim.unlink()
                    victim.symlink_to("smartdns-mipsel")
                else:
                    victim.unlink()
                    victim.mkdir()
                with self.assertRaises(ValueError):
                    prepare(directory, self.version, "all")
                self.assertTrue((directory / "smartdns-x86_64").exists())
                self.assertFalse((directory / "SHA256SUMS").exists())

    def test_api_only_missing_get_is_benign(self):
        def response(status, body="{}"):
            return lambda *args, **kwargs: SimpleNamespace(
                stdout=f"HTTP/2.0 {status} Response\r\nContent-Type: application/json\r\n\r\n{body}",
                returncode=0 if status < 400 else 1,
            )
        self.assertEqual(gh_api("example", runner=response(200)), {})
        self.assertIsNone(gh_api("example", missing_ok=True, runner=response(404)))
        for status in (401, 403, 429, 500, 503):
            with self.assertRaises(ValueError):
                gh_api("example", missing_ok=True, runner=response(status))
        with self.assertRaises(ValueError):
            gh_api("example", method="DELETE", missing_ok=True, runner=response(404))
        with self.assertRaises(ValueError):
            gh_api("example", runner=lambda *args, **kwargs: SimpleNamespace(
                stdout="", returncode=1))

    def test_nightly_cleanup_is_scoped_and_handles_absence(self):
        for existing_release, existing_tag in ((True, True), (False, True), (False, False)):
            with self.subTest(release=existing_release, tag=existing_tag):
                calls = []
                tag_exists = existing_tag

                def api(endpoint, method="GET", missing_ok=False):
                    nonlocal tag_exists
                    calls.append((endpoint, method))
                    if endpoint.endswith(f"/releases/tags/{NIGHTLY_TAG}"):
                        return {"id": 12, "tag_name": NIGHTLY_TAG} if existing_release else None
                    if endpoint.endswith("/releases/12"):
                        self.assertEqual(method, "DELETE")
                        return {}
                    if method == "DELETE":
                        self.assertTrue(endpoint.endswith(f"/git/refs/tags/{NIGHTLY_TAG}"))
                        tag_exists = False
                        return {}
                    self.assertTrue(missing_ok)
                    return {"ref": f"refs/tags/{NIGHTLY_TAG}"} if tag_exists else None

                clean_nightly("owner/repo", api=api)
                self.assertFalse(tag_exists)
                self.assertEqual(sum(method == "DELETE" for _, method in calls),
                                 int(existing_release) + int(existing_tag))
                self.assertTrue(all(not endpoint.endswith("/nightly") for endpoint, _ in calls))

    def test_nightly_cleanup_stops_at_delete_failure(self):
        calls = []

        def api(endpoint, method="GET", missing_ok=False):
            calls.append((endpoint, method))
            if method == "DELETE":
                raise ValueError("HTTP 403")
            return {"id": 12, "tag_name": NIGHTLY_TAG}

        with self.assertRaises(ValueError):
            clean_nightly("owner/repo", api=api)
        self.assertEqual(len(calls), 2)  # No retry or tag modification after failure.

    def test_nightly_cleanup_rejects_tag_that_remains(self):
        def api(endpoint, method="GET", missing_ok=False):
            if "/releases/" in endpoint:
                return None
            return {"ref": f"refs/tags/{NIGHTLY_TAG}"}

        with self.assertRaises(ValueError):
            clean_nightly("owner/repo", api=api)

    def test_nightly_readback_must_match_built_commit(self):
        commit = "a" * 40
        for actual, kind in ((commit, "commit"), ("b" * 40, "commit"), (commit, "tree")):
            def api(*args, **kwargs):
                return {"ref": f"refs/tags/{NIGHTLY_TAG}",
                        "object": {"type": kind, "sha": actual}}
            if actual == commit and kind == "commit":
                verify_tag("owner/repo", NIGHTLY_TAG, commit, api=api)
            else:
                with self.assertRaises(ValueError):
                    verify_tag("owner/repo", NIGHTLY_TAG, commit, api=api)

    def test_stable_annotated_tag_readback(self):
        tag, commit, annotation = "Release48.4-polaris", "a" * 40, "b" * 40
        calls = []

        def api(endpoint):
            calls.append(endpoint)
            if endpoint.endswith(f"/git/ref/tags/{tag}"):
                return {"ref": f"refs/tags/{tag}",
                        "object": {"type": "tag", "sha": annotation}}
            self.assertTrue(endpoint.endswith(f"/git/tags/{annotation}"))
            return {"object": {"type": "commit", "sha": commit}}

        verify_tag("owner/repo", tag, commit, api=api)
        self.assertEqual(len(calls), 2)

    def test_cyclic_annotated_tag_readback_fails(self):
        annotation = "b" * 40

        def api(endpoint):
            return {"ref": "refs/tags/Release48-polaris",
                    "object": {"type": "tag", "sha": annotation}}

        with self.assertRaises(ValueError):
            verify_tag("owner/repo", "Release48-polaris", "a" * 40, api=api)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--check-tag")
    parser.add_argument("--clean-nightly", action="store_true")
    parser.add_argument("--verify-tag")
    parser.add_argument("--repository")
    parser.add_argument("--commit")
    parser.add_argument("--directory", type=Path)
    parser.add_argument("--version")
    parser.add_argument("--target", choices=("all", "x86_64"), default="all")
    args = parser.parse_args()
    if args.self_test:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(ContractTests)
        return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1
    try:
        if args.check_tag is not None:
            check_tag(args.check_tag)
        elif args.clean_nightly and args.repository:
            clean_nightly(args.repository)
        elif args.verify_tag and args.repository and args.commit:
            verify_tag(args.repository, args.verify_tag, args.commit)
        elif args.directory is not None and args.version is not None:
            prepare(args.directory, args.version, args.target)
        else:
            parser.error("provide --check-tag or both --directory and --version")
    except (OSError, ValueError) as error:
        parser.exit(1, f"release contract: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
