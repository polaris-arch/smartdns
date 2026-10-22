#!/usr/bin/env python3
"""Bounded real OpenWrt HostBuild lifecycle tests (no SDK download/compiler).

Supply --sdk-source-dir with the pinned SDK tree (include/ and scripts/) or
an explicitly provided flat directory containing the three reference files.
They are verified before execution, not vendored or fetched by this test.
"""
import argparse
import copy
import io
import tarfile
import types
from unittest import mock
import hashlib
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

REFERENCE_HASHES = {
    "host-build.mk": "b895fbf8f789a0cc48b87057e732b2e5af96ce72c7c2f1bec83be92461aadb19",
    "depends.mk": "2e1b80b011cd8085ad580a17b2cd8dacae97497cc40a6fc49a057f6de0db4cae",
    "timestamp.pl": "ace291f5b42950731e2eadeefc91cd70b35d3dd933ce29475e5b008b687261bf",
}
REFERENCE_COMMIT = "78b23a26c4c98938d549e7ff5876508544e33d4d"
SOURCE_DIR = None
HELPER = None


def verified_sources(root):
    result = {}
    for name, digest in REFERENCE_HASHES.items():
        nested = root / ("scripts" if name.endswith(".pl") else "include") / name
        path = nested if nested.exists() else root / name
        if not path.is_file() or path.is_symlink():
            raise ValueError("missing/nonregular pinned reference: " + str(path))
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError("pinned reference hash mismatch: " + str(path))
        result[name] = path
    return result


class HostBuildFixture:
    """Actual HostBuild rules; fake only the package's build/install commands.

    The three official source files are executed unchanged. The outside SDK's
    download/quilt/autotools/unpack includes are empty shims: no download, patch
    or configure program is needed for this tiny package. DefaultTargets is the
    standard public-target -> dot-target bridge, not replacement stamp rules.
    """
    def __init__(self, root, sources):
        self.root = root
        self.feed = root / "feeds/packages/lang/rust"
        self.build = root / "build_dir/target-x86_64_musl/host/rustc-1.89.0-src"
        self.prefix = root / "staging_dir/target-x86_64_musl/host"
        self.installed = root / "staging_dir/hostpkg/stamp/.rust_installed"
        self.events = root / "events"
        for path in (self.feed, root / "include", root / "scripts"):
            path.mkdir(parents=True)
        for name, source in sources.items():
            dest = root / ("scripts" if name.endswith(".pl") else "include") / name
            shutil.copyfile(source, dest)
            dest.chmod(0o755 if name.endswith(".pl") else 0o644)
        for name in ("download", "unpack", "quilt", "autotools"):
            (root / "include" / (name + ".mk")).write_text("# fixture external subsystem: unused\n")
        # OpenWrt mkhash's md5 interface, including per-file names, using the
        # system implementation. This is not the dependency algorithm.
        mkhash = root / "scripts/mkhash"
        mkhash.write_text('#!/bin/sh\n[ "$1" = md5 ] || exit 2\nshift\nif [ "$#" -gt 0 ]; then md5sum "$@"; else md5sum | cut -d " " -f1; fi\n')
        mkhash.chmod(0o755)
        (self.feed / "patches").mkdir()
        (self.feed / "patches/fixture.patch").write_text("fixture-overlay-v1\n")
        makefile = r'''
TOPDIR:=%(root)s
INCLUDE_DIR:=$(TOPDIR)/include
SCRIPT_DIR:=$(TOPDIR)/scripts
BUILD_DIR_HOST:=$(TOPDIR)/build_dir/target-x86_64_musl/host
STAGING_DIR_HOSTPKG:=$(TOPDIR)/staging_dir/hostpkg
STAGING_DIR_HOST:=$(TOPDIR)/staging_dir/host
TARGET_PATH_PKG:=$(PATH)
IS_PACKAGE_BUILD:=1
PKG_NAME:=rust
PKG_VERSION:=1.89.0-src
HOST_BUILD_DIR:=$(BUILD_DIR_HOST)/rustc-1.89.0-src
CONFIG_AUTOREBUILD:=y
CONFIG_AUTOREMOVE:=y
MKHASH:=$(SCRIPT_DIR)/mkhash
FIND:=find
XARGS:=xargs
DEFAULT_SUBDIR_TARGETS:=prepare configure compile install
confvar=fixture-config
# Real SDK's generic target bridge; lifecycle recipes remain in host-build.mk.
define DefaultTargets
$(foreach t,$(1),$(eval $(t): .$(t)))
endef
.PHONY: FORCE
FORCE:
include $(INCLUDE_DIR)/host-build.mk

define Host/Prepare
	printf 'prepare\n' >> $(TOPDIR)/events
	printf 'source\n' > $(HOST_BUILD_DIR)/source.c
endef
define Host/Configure
	printf 'configure\n' >> $(TOPDIR)/events
	printf 'actual-generated-toml\n' > $(HOST_BUILD_DIR)/bootstrap.toml
	mkdir -p $(TOPDIR)/provenance
	cp $(HOST_BUILD_DIR)/bootstrap.toml $(TOPDIR)/provenance/bootstrap.toml
endef
define Host/Compile
	printf 'compile\n' >> $(TOPDIR)/events
	test '$(FAIL_COMPILE)' != 1
	printf 'compiled\n' > $(HOST_BUILD_DIR)/compiled
endef
define Host/Install
	printf 'install\n' >> $(TOPDIR)/events
	mkdir -p $(TOPDIR)/staging_dir/target-x86_64_musl/host/bin
	cp $(HOST_BUILD_DIR)/compiled $(TOPDIR)/staging_dir/target-x86_64_musl/host/bin/rustc
endef
$(eval $(call HostBuild))
'''
        (self.feed / "Makefile").write_text(makefile % {"root": root})
        # Input timestamps are deliberately old; real GNUmake creates stamps.
        for path in self.feed.rglob("*"):
            os.utime(path, (946684800, 946684800))

    def make(self, *args, success=True):
        proc = subprocess.run(["make", "--no-print-directory", "-C", str(self.feed),
                               "host-compile", *args], capture_output=True, text=True,
                              timeout=15, env={**os.environ, "LC_ALL": "C"})
        if success and proc.returncode:
            raise AssertionError(proc.stdout + proc.stderr)
        if not success and not proc.returncode:
            raise AssertionError("expected real host compile failure")
        return proc

    def counts(self):
        return self.events.read_text().splitlines() if self.events.exists() else []

    def feed_times(self):
        return {str(p.relative_to(self.feed)): p.stat().st_mtime_ns
                for p in self.feed.rglob("*") if p.is_file()}

    def replay_times_for_mechanism_test(self, times):
        # This deliberately tests only make's mechanism. Production equivalence
        # authorization is tested separately against sdk-host-cache.py.
        for name, ns in times.items():
            os.utime(self.feed / name, ns=(ns, ns))

    def fresh_feed_mtime(self):
        # timestamp.pl compares whole seconds. Advance beyond real producer
        # stamps without sleeping; rdep creates new check stamps at real time.
        ns = (int(time.time()) + 5) * 1000000000
        for path in self.feed.rglob("*"):
            if path.is_file():
                os.utime(path, ns=(ns, ns))


class RealHostBuildLifecycle(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="sdk-host-lifecycle-")
        self.addCleanup(self.tmp.cleanup)
        self.f = HostBuildFixture(Path(self.tmp.name), verified_sources(SOURCE_DIR))

    def test_actual_make_inputs_nul_quote_protocol_without_build(self):
        values = {
            "HOSTCC": "cc -DNAME='two words'",
            "HOSTCXX": "c++ -DNAME='two words'",
            "HOST_CONFIGURE_VARS": "CC='cc wrapper' LABEL='it is quoted'",
            "HOST_CONFIGURE_ARGS": "--prefix='path with spaces' --enable-fixture",
            "RUSTC_HOST_ARCH": "x86_64-unknown-linux-gnu",
            "RUSTC_TARGET_ARCH": "x86_64-unknown-linux-musl",
            "CARGO_HOME": str(self.f.root / "dl/cargo"),
            "TARGET_PATH_PKG": os.environ["PATH"],
        }
        with (self.f.feed / "Makefile").open("a") as stream:
            stream.write("\n" + "\n".join(name + ":=" + value for name, value in values.items()) + "\n")
        before = self.f.counts()
        actual = HELPER.make_inputs(self.f.root)
        for name, value in values.items():
            self.assertEqual(actual[name], value, name)
        self.assertEqual(actual["HOST_BUILD_DIR"], str(self.f.build))
        self.assertEqual(actual["HOST_STAMP_INSTALLED"], str(self.f.installed))
        self.assertEqual(actual["HOST_BUILD_PREFIX"], str(self.f.root / "staging_dir/hostpkg"))
        self.assertTrue(actual["HOST_STAMP_PREPARED"].startswith(str(self.f.build / ".prepared")))
        self.assertEqual(len(actual), 12)
        self.assertEqual(self.f.counts(), before)
        self.assertFalse(self.f.build.exists(), "query must not prepare/configure/compile")

    def test_cold_autoremove_and_true_warm(self):
        self.f.make()
        self.assertEqual(self.f.counts(), ["prepare", "configure", "compile", "install"])
        self.assertTrue(self.f.installed.is_file())
        self.assertTrue((self.f.prefix / "bin/rustc").is_file())
        stamps = list(self.f.build.iterdir())
        self.assertTrue(any(p.name.startswith(".prepared") for p in stamps))
        self.assertTrue(all(p.name.startswith(".") and p.stat().st_size == 0 for p in stamps))
        self.assertFalse((self.f.build / "bootstrap.toml").exists())
        self.assertEqual((self.f.root / "provenance/bootstrap.toml").read_text(), "actual-generated-toml\n")
        old = {p.name: p.stat().st_mtime_ns for p in stamps}
        self.f.make()
        self.assertEqual(len(self.f.counts()), 4)
        for name, ns in old.items():
            self.assertEqual((self.f.build / name).stat().st_mtime_ns, ns)

    def test_fresh_checkout_mtime_rebuilds_real_host(self):
        self.f.make()
        self.f.fresh_feed_mtime()
        # Ensure rdep check target is strictly newer than old prepared stamp,
        # also on filesystems with coarse timestamps (not a compiler benchmark).
        time.sleep(1.05)
        self.f.make()
        self.assertEqual(self.f.counts(), ["prepare", "configure", "compile", "install"] * 2)

    def test_producer_input_mtime_replay_avoids_rebuild(self):
        times = self.f.feed_times()
        self.f.make()
        self.f.fresh_feed_mtime()
        self.f.replay_times_for_mechanism_test(times)
        self.f.make()
        self.assertEqual(len(self.f.counts()), 4)

    def test_content_change_rebuilds_even_if_mtime_is_old(self):
        self.f.make()
        path = self.f.feed / "patches/fixture.patch"
        path.write_text("changed-content\n")
        os.utime(path, (946684800, 946684800))
        self.f.make()
        self.assertEqual(len(self.f.counts()), 8)

    def test_empty_stamps_do_not_prove_installed_closure(self):
        self.f.make()
        (self.f.prefix / "bin/rustc").unlink()
        self.f.make()
        # Actual upstream make happily reuses empty stamps with no compiler!
        # Cache acceptance MUST independently validate installed closure.
        self.assertEqual(len(self.f.counts()), 4)
        self.assertFalse((self.f.prefix / "bin/rustc").exists())

    def test_mode_only_change_is_not_proven_by_make_stamps(self):
        self.f.make()
        (self.f.feed / "patches/fixture.patch").chmod(0o755)
        self.f.make()
        # OpenWrt reproducible hash covers path+content, not permission bits.
        # The production cache's full manifest must reject this independently.
        self.assertEqual(len(self.f.counts()), 4)

    def test_missing_installed_stamp_cannot_be_replaced_by_built_stamp(self):
        self.f.make()
        self.f.installed.unlink()
        # AUTOREMOVE removed the compiled tree. Upstream genuinely attempts
        # installation and fails; it does not magically restore the closure.
        self.f.make(success=False)
        self.assertFalse(self.f.installed.exists())
        self.assertEqual(self.f.counts()[-1], "install")

    def test_modified_reference_source_is_rejected_before_make(self):
        refs = self.f.root / "bad-reference"
        refs.mkdir()
        for name, source in verified_sources(SOURCE_DIR).items():
            shutil.copyfile(source, refs / name)
        with (refs / "depends.mk").open("a") as stream:
            stream.write("\n# unpinned modification\n")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            verified_sources(refs)
        self.assertEqual(self.f.counts(), [])

    def test_failed_build_does_not_produce_installed_stamp(self):
        self.f.make("FAIL_COMPILE=1", success=False)
        self.assertFalse(self.f.installed.exists())
        self.assertFalse((self.f.build / ".built").exists())
        self.assertEqual(self.f.counts(), ["prepare", "configure", "compile"])


class ProductionFeedReplay(unittest.TestCase):
    setUp = RealHostBuildLifecycle.setUp

    def test_verified_producer_mtimes_reuse_real_autoremove_stamps(self):
        state = HELPER.capture_feed_state(self.f.root)
        self.f.make()
        self.f.fresh_feed_mtime()
        HELPER.check_feed_state(self.f.root, state, restore_mtime=True)
        self.f.make()
        self.assertEqual(self.f.counts(), ["prepare", "configure", "compile", "install"])

    def assert_replay_rejected_without_partial_mtime_changes(self, mutate):
        state = HELPER.capture_feed_state(self.f.root)
        self.f.make()
        self.f.fresh_feed_mtime()
        mutate()
        before = self.f.feed_times()
        with self.assertRaises(HELPER.ContractError):
            HELPER.check_feed_state(self.f.root, state, restore_mtime=True)
        self.assertEqual(self.f.feed_times(), before,
                         "rejected feed must not have partial producer mtimes applied")

    def test_changed_content_rejected_before_any_mtime_replay(self):
        self.assert_replay_rejected_without_partial_mtime_changes(
            lambda: (self.f.feed / "patches/fixture.patch").write_text("changed\n"))

    def test_mode_drift_rejected_before_any_mtime_replay(self):
        self.assert_replay_rejected_without_partial_mtime_changes(
            lambda: (self.f.feed / "patches/fixture.patch").chmod(0o755))

    def test_directory_mode_drift_rejected_before_any_mtime_replay(self):
        self.assert_replay_rejected_without_partial_mtime_changes(
            lambda: (self.f.feed / "patches").chmod(0o700))

    def test_path_drift_rejected_before_any_mtime_replay(self):
        self.assert_replay_rejected_without_partial_mtime_changes(
            lambda: (self.f.feed / "patches/fixture.patch").rename(self.f.feed / "patches/renamed.patch"))

    def test_extra_member_rejected_before_any_mtime_replay(self):
        self.assert_replay_rejected_without_partial_mtime_changes(
            lambda: (self.f.feed / "unexpected").write_text("new member\n"))

    def test_missing_member_rejected_before_any_mtime_replay(self):
        self.assert_replay_rejected_without_partial_mtime_changes(
            lambda: (self.f.feed / "patches/fixture.patch").unlink())


class ProductionInstalledClosure(unittest.TestCase):
    setUp = RealHostBuildLifecycle.setUp

    def install_fixture(self):
        # Primary stamps are produced by unchanged HostBuild, never fabricated.
        self.f.make()
        self.metadata = self.f.prefix / "lib/rustlib"
        self.metadata.mkdir(parents=True)
        (self.f.prefix / "bin/rustc").chmod(0o755)
        cargo = self.f.prefix / "bin/cargo"
        cargo.write_text("fixture cargo bytes\n")
        cargo.chmod(0o755)
        self.targets = ("x86_64-unknown-linux-gnu", "x86_64-unknown-linux-musl")
        components = ["rustc", "cargo"]
        (self.metadata / "manifest-rustc").write_text("file:" + str(self.f.prefix / "bin/rustc") + "\n")
        (self.metadata / "manifest-cargo").write_text("file:" + str(self.f.prefix / "bin/cargo") + "\n")
        for target in self.targets:
            directory = self.metadata / target / "lib"
            directory.mkdir(parents=True)
            (directory / "libstd-fixture.rlib").write_text("fixture std " + target + "\n")
            component = "rust-std-" + target
            components.append(component)
            (self.metadata / ("manifest-" + component)).write_text(
                "dir:" + str(self.metadata / target / "lib") + "\n")
        (self.metadata / "components").write_text("\n".join(components) + "\n")
        (self.metadata / "rust-installer-version").write_text("3\n")
        (self.metadata / "uninstall.sh").write_text("#!/bin/sh\nexit 99\n")
        self.entries = HELPER.collect_installed_entries(self.f.root)
        HELPER.validate_installed_closure(self.f.root, self.entries)

    def assert_invalid(self, mutate):
        self.install_fixture()
        mutate()
        with self.assertRaises(HELPER.ContractError):
            HELPER.validate_installed_closure(self.f.root, self.entries)

    def test_real_primary_stamps_survive_new_rdep_hints(self):
        self.install_fixture()
        primary = {e["path"]: e["mtime_ns"] for e in self.entries
                   if e["kind"] == "file" and
                   (e["path"].startswith(HELPER.BUILD + "/") or e["path"] == HELPER.INSTALL_STAMP)}
        self.assertGreaterEqual(len(primary), 4)
        self.assertFalse(any(e["path"].endswith(("_check", "_check.1")) for e in self.entries))
        before = self.f.counts()
        self.f.make()
        self.assertTrue(list(self.f.build.glob("*_check")), "official rdep must actually generate hints")
        HELPER.validate_installed_closure(self.f.root, self.entries)
        self.assertEqual(self.f.counts(), before)
        for path, ns in primary.items():
            self.assertEqual((self.f.root / path).stat().st_mtime_ns, ns)

    def test_installer_absolute_paths_reject_lookalike_outside_and_alias(self):
        self.install_fixture()
        manifest = self.metadata / "manifest-rustc"
        original = manifest.read_bytes()
        for absolute in (str(self.f.prefix) + "-lookalike/bin/rustc",
                         str(self.f.root.parent / "foreign/bin/rustc"),
                         str(self.f.prefix) + "/bin/../bin/rustc",
                         str(self.f.prefix) + "//bin/rustc",
                         "bin/rustc"):
            with self.subTest(record=absolute):
                manifest.write_text("file:" + absolute + "\n")
                with self.assertRaises(HELPER.ContractError):
                    HELPER.collect_installed_entries(self.f.root)
        manifest.write_bytes(original)
        with self.assertRaises(HELPER.ContractError):
            HELPER.collect_installed_entries(self.f.root, declared_sdk_root=self.f.root.parent / "wrong")
        HELPER.validate_installed_closure(self.f.root, self.entries)

    def test_missing_rustc_rejected_despite_empty_stamps(self):
        self.assert_invalid(lambda: (self.f.prefix / "bin/rustc").unlink())

    def test_missing_cargo_rejected_despite_empty_stamps(self):
        self.assert_invalid(lambda: (self.f.prefix / "bin/cargo").unlink())

    def test_missing_gnu_std_rejected(self):
        self.assert_invalid(lambda: (self.metadata / self.targets[0] / "lib/libstd-fixture.rlib").unlink())

    def test_missing_musl_std_rejected(self):
        self.assert_invalid(lambda: (self.metadata / self.targets[1] / "lib/libstd-fixture.rlib").unlink())

    def test_missing_component_manifest_rejected(self):
        self.assert_invalid(lambda: (self.metadata / "manifest-rustc").unlink())

    def test_missing_installer_metadata_rejected(self):
        self.assert_invalid(lambda: (self.metadata / "rust-installer-version").unlink())

    def test_missing_installed_stamp_rejected(self):
        self.assert_invalid(lambda: self.f.installed.unlink())

    def test_payload_byte_tamper_rejected(self):
        self.assert_invalid(lambda: (self.f.prefix / "bin/cargo").write_text("tampered bytes\n"))

    def test_payload_permission_tamper_rejected(self):
        self.assert_invalid(lambda: (self.f.prefix / "bin/cargo").chmod(0o644))

    def test_all_primary_stamp_timestamp_changes_rejected(self):
        self.install_fixture()
        primary = [self.f.build / ".built", self.f.build / ".configured", self.f.installed]
        primary.extend(p for p in self.f.build.glob(".prepared*")
                       if not p.name.endswith(("_check", "_check.1")))
        self.assertGreaterEqual(len(primary), 4)
        for path in primary:
            with self.subTest(stamp=path.name):
                original = path.stat().st_mtime_ns
                try:
                    ns = original + 10000000000
                    os.utime(path, ns=(ns, ns))
                    with self.assertRaises(HELPER.ContractError):
                        HELPER.validate_installed_closure(self.f.root, self.entries)
                finally:
                    os.utime(path, ns=(original, original))
        HELPER.validate_installed_closure(self.f.root, self.entries)

    def test_duplicate_component_rejected(self):
        def change():
            with (self.metadata / "components").open("a") as stream:
                stream.write("rustc\n")
        self.assert_invalid(change)

    def test_manifest_path_escape_rejected(self):
        def change():
            with (self.metadata / "manifest-rustc").open("a") as stream:
                stream.write("file:../../outside\n")
        self.assert_invalid(change)

    def test_symlink_escape_rejected(self):
        def change():
            path = self.f.prefix / "bin/cargo"
            path.unlink()
            path.symlink_to("../../../../../../outside")
        self.assert_invalid(change)

    def test_symlink_cycle_rejected(self):
        def change():
            first = self.f.prefix / "bin/loop-a"
            second = self.f.prefix / "bin/loop-b"
            first.symlink_to("loop-b")
            second.symlink_to("loop-a")
            with (self.metadata / "manifest-rustc").open("a") as stream:
                stream.write("file:" + str(first) + "\nfile:" + str(second) + "\n")
        self.assert_invalid(change)

    def test_special_file_rejected_without_opening_fifo(self):
        def change():
            path = self.f.prefix / "bin/cargo"
            path.unlink()
            os.mkfifo(path)
        self.assert_invalid(change)

    def test_symlink_parent_rejected(self):
        def change():
            directory = self.f.prefix / "bin"
            directory.rename(self.f.prefix / "real-bin")
            directory.symlink_to("real-bin", target_is_directory=True)
        self.assert_invalid(change)

    def test_hardlinked_installed_payload_rejected(self):
        def change():
            cargo = self.f.prefix / "bin/cargo"
            os.link(cargo, self.f.root / "unowned-hardlink")
        self.assert_invalid(change)


class CapsuleFilesystem(unittest.TestCase):
    install_fixture = ProductionInstalledClosure.install_fixture

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="sdk-capsule-")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.f = HostBuildFixture(self.base / "sdk", verified_sources(SOURCE_DIR))
        self.install_fixture()
        self.evidence = self.base / "evidence"
        self.evidence.mkdir()
        self.capsule = self.base / "sdk-host-capsule"
        self.output = self.base / "actions-output"
        self.feed = HELPER.capture_feed_state(self.f.root)
        prepared = next(p for p in self.f.build.glob(".prepared*") if not p.name.endswith(("_check", "_check.1")))
        self.prior = {"cache_key": "fixture-exact-key", "identity": {
            "sdk_root": str(self.f.root), "autorebuild": True,
            "make": {"HOST_STAMP_PREPARED": str(prepared)},
            "feed": HELPER.without_times(self.feed)}}
        self.producer = {"inputs": self.prior, "feed": self.feed,
                         "bootstrap_toml": '[build]\nbuild = "x86_64-unknown-linux-gnu"\nhost = ["x86_64-unknown-linux-gnu"]\ntarget = ["x86_64-unknown-linux-gnu", "x86_64-unknown-linux-musl"]\njobs = 2\n[llvm]\ndownload-ci-llvm = false\nlink-jobs = 1\ntargets = "X86"\nexperimental-targets = ""\n',
                         "producer": {"GITHUB_REPOSITORY": HELPER.REPOSITORY,
                                      "GITHUB_SHA": "1" * 40, "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2"}}
        self.producer["bootstrap_sha256"] = HELPER.digest(self.producer["bootstrap_toml"].encode())
        self.tools = {"fixture": "not actual rustc/runtime execution"}
        for name, value in (("inputs.json", self.prior), ("producer.json", self.producer),
                            ("host-probes.json", [{"origin": "cold", "tools": self.tools, "closure_eligible": True}])):
            HELPER.write_json(self.evidence / name, value)
        # Only platform capacity and executable probing are substituted; actual
        # manifest, filesystem, tar writer/parser, install and rollback run.
        disk = mock.patch.object(HELPER.shutil, "disk_usage", return_value=types.SimpleNamespace(free=8 << 30))
        disk.start()
        self.addCleanup(disk.stop)

    def pack(self):
        HELPER.snapshot(self.f.root, self.evidence, self.capsule, self.output)
        self.manifest = HELPER.read_json(self.capsule / "manifest.json")
        HELPER.validate_manifest(self.manifest, self.prior)
        return self.manifest

    def clear_owned(self):
        shutil.rmtree(self.f.prefix)
        shutil.rmtree(self.f.build)
        self.f.installed.unlink()
        self.f.fresh_feed_mtime()

    def unpack(self):
        staging = self.base / "staging"
        staging.mkdir()
        HELPER.unpack_capsule(self.capsule / "payload.tar.gz", staging, self.manifest)
        return staging

    def rewrite_tar(self, mutate):
        payload = self.capsule / "payload.tar.gz"
        with tarfile.open(payload, "r:gz") as archive:
            members = [(copy.copy(m), archive.extractfile(m).read() if m.isfile() else b"") for m in archive]
        members = mutate(members)
        with tarfile.open(payload, "w:gz", format=tarfile.PAX_FORMAT) as archive:
            for header, data in members:
                archive.addfile(header, io.BytesIO(data) if header.isfile() else None)
        self.manifest["payload_sha256"] = HELPER.file_digest(payload)
        self.manifest["payload_bytes"] = payload.stat().st_size

    def test_actual_pax_snapshot_unpack_restore_and_producer_reuse(self):
        self.pack()
        with tarfile.open(self.capsule / "payload.tar.gz", "r:gz") as archive:
            self.assertTrue(any("mtime" in m.pax_headers for m in archive))
        self.clear_owned()
        before = self.f.counts()
        with mock.patch.object(HELPER, "inspect_tools", return_value=self.tools):
            HELPER.restore(self.f.root, self.evidence, self.capsule, "warm", "true",
                           self.prior["cache_key"], self.prior["cache_key"], self.output)
        self.assertEqual(HELPER.read_json(self.evidence / "producer.json"), self.producer)
        self.assertEqual(HELPER.read_json(self.evidence / "restore.json")["origin"], "cache")
        self.f.make()
        self.assertEqual(self.f.counts(), before)
        HELPER.validate_installed_closure(self.f.root, self.manifest["entries"])

    def test_payload_digest_mismatch_rejected(self):
        self.pack()
        with (self.capsule / "payload.tar.gz").open("ab") as stream:
            stream.write(b"corruption")
        with self.assertRaises(HELPER.ContractError):
            self.unpack()

    def test_tar_missing_member_rejected(self):
        self.pack()
        self.rewrite_tar(lambda members: members[:-1])
        with self.assertRaises(HELPER.ContractError):
            self.unpack()

    def test_tar_duplicate_member_rejected(self):
        self.pack()
        self.rewrite_tar(lambda members: members + [members[-1]])
        with self.assertRaises(HELPER.ContractError):
            self.unpack()

    def test_tar_extra_member_rejected(self):
        self.pack()
        def change(members):
            h = tarfile.TarInfo(HELPER.PREFIX + "/unowned")
            return members + [(h, b"")]
        self.rewrite_tar(change)
        with self.assertRaises(HELPER.ContractError):
            self.unpack()

    def test_tar_member_bytes_tamper_rejected_after_container_hash_matches(self):
        self.pack()
        def change(members):
            for i, (h, data) in enumerate(members):
                if h.isfile() and data:
                    members[i] = (h, bytes([data[0] ^ 1]) + data[1:])
                    break
            return members
        self.rewrite_tar(change)
        with self.assertRaises(HELPER.ContractError):
            self.unpack()

    def test_tar_path_escape_rejected(self):
        self.pack()
        def change(members):
            members[0][0].name = "../escape"
            members[0][0].pax_headers = {}
            return members
        self.rewrite_tar(change)
        with self.assertRaises(HELPER.ContractError):
            self.unpack()
        self.assertFalse((self.base / "escape").exists())

    def test_hardlink_tar_type_rejected(self):
        self.pack()
        def change(members):
            h = tarfile.TarInfo(HELPER.PREFIX + "/hardlink")
            h.type = tarfile.LNKTYPE
            h.linkname = HELPER.PREFIX + "/bin/rustc"
            return members + [(h, b"")]
        self.rewrite_tar(change)
        with self.assertRaises(HELPER.ContractError):
            self.unpack()

    def test_sparse_tar_type_rejected(self):
        self.pack()
        def change(members):
            h = tarfile.TarInfo(HELPER.PREFIX + "/sparse")
            h.type = tarfile.GNUTYPE_SPARSE
            return members + [(h, b"")]
        self.rewrite_tar(change)
        with self.assertRaises(HELPER.ContractError):
            self.unpack()

    def test_unsupported_pax_metadata_rejected(self):
        self.pack()
        def change(members):
            members[0][0].pax_headers = {"GNU.sparse.size": "1000000000000"}
            return members
        self.rewrite_tar(change)
        with self.assertRaises(HELPER.ContractError):
            self.unpack()

    def test_owned_relative_symlink_roundtrip(self):
        link = self.f.prefix / "bin/rustc-alias"
        link.symlink_to("rustc")
        with (self.metadata / "manifest-rustc").open("a") as stream:
            stream.write("file:" + str(link) + "\n")
        self.pack()
        staging = self.unpack()
        self.assertEqual(os.readlink(staging / HELPER.PREFIX / "bin/rustc-alias"), "rustc")
        for source in self.metadata.glob("manifest-*"):
            self.assertEqual((staging / HELPER.PREFIX / "lib/rustlib" / source.name).read_bytes(), source.read_bytes())
        HELPER.validate_installed_closure(staging, self.manifest["entries"], declared_sdk_root=self.f.root)

    def test_tar_symlink_target_mismatch_rejected(self):
        link = self.f.prefix / "bin/rustc-alias"
        link.symlink_to("rustc")
        with (self.metadata / "manifest-rustc").open("a") as stream:
            stream.write("file:" + str(link) + "\n")
        self.pack()
        def change(members):
            for header, _ in members:
                if header.issym():
                    header.linkname = "../../escape"
            return members
        self.rewrite_tar(change)
        with self.assertRaises(HELPER.ContractError):
            self.unpack()

    def test_oversized_pax_block_rejected(self):
        self.pack()
        def change(members):
            members[0][0].pax_headers = {"path": "x" * 17000}
            return members
        self.rewrite_tar(change)
        with self.assertRaises(HELPER.ContractError):
            self.unpack()

    def test_manifest_capacity_duplicate_and_key_rejected(self):
        self.pack()
        for field, value in (("cache_key", "other"), ("expanded_bytes", HELPER.MAX_EXPANDED + 1),
                             ("payload_bytes", HELPER.MAX_CAPSULE + 1),
                             ("entries", self.manifest["entries"] * 2)):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.manifest)
                changed[field] = value
                with self.assertRaises(HELPER.ContractError):
                    HELPER.validate_manifest(changed, self.prior)

    def test_bootstrap_semantic_tamper_rejected_with_valid_digest(self):
        self.pack()
        changed = copy.deepcopy(self.manifest)
        text = changed["producer"]["bootstrap_toml"].replace("jobs = 2", "jobs = 20")
        changed["producer"]["bootstrap_toml"] = text
        changed["producer"]["bootstrap_sha256"] = HELPER.digest(text.encode())
        with self.assertRaises(HELPER.ContractError):
            HELPER.validate_manifest(changed, self.prior)

    def test_ineligible_cold_closure_does_not_report_save_ready(self):
        HELPER.write_json(self.evidence / "host-probes.json", [
            {"origin": "cold", "tools": self.tools, "closure_eligible": False, "reason": "capacity"}])
        HELPER.snapshot(self.f.root, self.evidence, self.capsule, self.output)
        self.assertIn("save_ready=false", self.output.read_text())
        self.assertFalse((self.capsule / "manifest.json").exists())

    def test_actual_cli_warm_key_miss_returns_nonzero_without_compile(self):
        self.pack()
        self.clear_owned()
        before = self.f.counts()
        proc = subprocess.run([sys.executable, HELPER.__file__, "restore", "--sdk-root", str(self.f.root),
                               "--evidence", str(self.evidence), "--capsule-dir", str(self.capsule),
                               "--github-output", str(self.output), "--mode", "warm", "--cache-hit", "true",
                               "--matched-key", "wrong", "--key", self.prior["cache_key"]],
                              capture_output=True, text=True, timeout=10)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("dedicated warm validation", proc.stderr)
        self.assertEqual(self.f.counts(), before)

    def test_disk_capacity_snapshot_reports_not_save_ready(self):
        with mock.patch.object(HELPER.shutil, "disk_usage", return_value=types.SimpleNamespace(free=1)):
            HELPER.snapshot(self.f.root, self.evidence, self.capsule, self.output)
        self.assertFalse(HELPER.read_json(self.evidence / "snapshot.json")["save_ready"])
        self.assertIn("save_ready=false", self.output.read_text())
        self.assertFalse((self.capsule / "manifest.json").exists())

    def test_invalid_snapshot_never_reports_save_ready(self):
        (self.f.prefix / "bin/cargo").unlink()
        with self.assertRaises(HELPER.ContractError):
            HELPER.snapshot(self.f.root, self.evidence, self.capsule, self.output)
        self.assertFalse(self.output.exists())
        self.assertFalse((self.capsule / "manifest.json").exists())

    def test_conflict_precheck_writes_nothing(self):
        self.pack()
        stage = self.unpack()
        dest = self.base / "consumer"
        conflict = dest / HELPER.PREFIX / "bin/cargo"
        conflict.parent.mkdir(parents=True)
        conflict.write_text("existing SDK bytes")
        before = sorted(str(p.relative_to(dest)) for p in dest.rglob("*"))
        with self.assertRaises(HELPER.ContractError):
            HELPER.install_staged(stage, dest, self.manifest["entries"], declared_sdk_root=self.f.root)
        self.assertEqual(sorted(str(p.relative_to(dest)) for p in dest.rglob("*")), before)
        self.assertEqual(conflict.read_text(), "existing SDK bytes")

    def test_mid_install_missing_source_rolls_back_created_only(self):
        self.pack()
        stage = self.unpack()
        (stage / HELPER.PREFIX / "bin/cargo").unlink()
        dest = self.base / "consumer"
        dest.mkdir()
        baseline = dest / "baseline"
        baseline.write_text("keep")
        with self.assertRaises(OSError):
            HELPER.install_staged(stage, dest, self.manifest["entries"], declared_sdk_root=self.f.root)
        self.assertEqual(list(dest.iterdir()), [baseline])

    def test_bad_exact_key_auto_selects_one_cold_fallback(self):
        self.pack()
        self.clear_owned()
        HELPER.restore(self.f.root, self.evidence, self.capsule, "auto", "true", "prefix-not-exact",
                       self.prior["cache_key"], self.output)
        record = HELPER.read_json(self.evidence / "restore.json")
        self.assertTrue(record["cold_fallback_selected"])
        self.assertEqual(record["origin"], "cold")
        self.assertFalse(self.capsule.exists())
        self.assertFalse(self.f.build.exists())
        self.assertEqual(self.output.read_text().count("origin=cold"), 1)

    def test_bad_exact_key_warm_fails_before_build(self):
        self.pack()
        self.clear_owned()
        before = self.f.counts()
        with self.assertRaises(HELPER.ContractError):
            HELPER.restore(self.f.root, self.evidence, self.capsule, "warm", "true", "prefix-not-exact",
                           self.prior["cache_key"], self.output)
        self.assertEqual(self.f.counts(), before)
        self.assertNotIn("origin=cache", self.output.read_text())

    def test_tool_probe_failure_rolls_back_and_preserves_feed_mtime(self):
        self.pack()
        self.clear_owned()
        before = self.f.feed_times()
        with mock.patch.object(HELPER, "inspect_tools", return_value={"wrong": "tools"}):
            HELPER.restore(self.f.root, self.evidence, self.capsule, "auto", "true",
                           self.prior["cache_key"], self.prior["cache_key"], self.output)
        self.assertFalse(self.f.build.exists())
        self.assertFalse(self.f.prefix.exists())
        self.assertEqual(self.f.feed_times(), before)
        self.assertTrue(HELPER.read_json(self.evidence / "restore.json")["cold_fallback_selected"])


    def altered_lifecycle(self, manifest, case):
        changed = copy.deepcopy(manifest)
        entries = changed["entries"]
        prepared = next(e for e in entries if e["path"].startswith(HELPER.BUILD + "/.prepared"))
        if case == "prepared":
            prepared["path"] = HELPER.BUILD + "/.preparedWRONG"
        elif case == "feed":
            file = next(e for e in changed["producer"]["feed"] if e["kind"] == "file")
            file["mtime_ns"] = prepared["mtime_ns"] + 10000000000
        else:
            name = HELPER.INSTALL_STAMP if case == "installed" else HELPER.BUILD + "/." + case
            next(e for e in entries if e["path"] == name)["mtime_ns"] = 0
        return changed

    def test_lifecycle_exact_prepared_order_and_feed_preflight(self):
        self.pack()
        HELPER.validate_lifecycle(self.manifest["entries"], self.prior, self.producer["feed"])
        for case in ("prepared", "configured", "built", "installed", "feed"):
            with self.subTest(case=case):
                changed = self.altered_lifecycle(self.manifest, case)
                with self.assertRaises(HELPER.ContractError):
                    HELPER.validate_manifest(changed, self.prior)

    def test_snapshot_rejects_impossible_stamp_order_without_touch_repair(self):
        configured = self.f.build / ".configured"
        os.utime(configured, ns=(0, 0))
        before = self.f.counts()
        with self.assertRaises(HELPER.ContractError):
            HELPER.snapshot(self.f.root, self.evidence, self.capsule, self.output)
        self.assertEqual(configured.stat().st_mtime_ns, 0)
        self.assertEqual(self.f.counts(), before)
        self.assertFalse(self.output.exists())
        self.assertFalse((self.capsule / "manifest.json").exists())

    def test_wrong_prepared_warm_rejected_before_compile(self):
        self.pack()
        changed = self.altered_lifecycle(self.manifest, "prepared")
        oldpath = next(e["path"] for e in self.manifest["entries"] if e["path"].startswith(HELPER.BUILD + "/.prepared"))
        def alter_tar(members):
            for header, _ in members:
                if header.name == oldpath:
                    header.name = HELPER.BUILD + "/.preparedWRONG"
            return members
        self.rewrite_tar(alter_tar)
        changed.update(payload_bytes=self.manifest["payload_bytes"], payload_sha256=self.manifest["payload_sha256"])
        HELPER.write_json(self.capsule / "manifest.json", changed)
        self.clear_owned()
        before = self.f.counts()
        with self.assertRaises(HELPER.ContractError):
            HELPER.restore(self.f.root, self.evidence, self.capsule, "warm", "true",
                           self.prior["cache_key"], self.prior["cache_key"], self.output)
        self.assertEqual(self.f.counts(), before)
        self.assertFalse(self.f.build.exists())
        self.assertNotIn("origin=cache", self.output.read_text())

    def test_invalid_stamp_order_auto_selects_cold_before_compile(self):
        self.pack()
        changed = self.altered_lifecycle(self.manifest, "configured")
        HELPER.write_json(self.capsule / "manifest.json", changed)
        self.clear_owned()
        before = self.f.counts()
        HELPER.restore(self.f.root, self.evidence, self.capsule, "auto", "true",
                       self.prior["cache_key"], self.prior["cache_key"], self.output)
        self.assertEqual(self.f.counts(), before)
        self.assertFalse(self.f.build.exists())
        self.assertTrue(HELPER.read_json(self.evidence / "restore.json")["cold_fallback_selected"])
        self.assertEqual(self.output.read_text().count("origin=cold"), 1)

    def assert_probe_exception_clean_fallback(self, error):
        self.pack()
        self.clear_owned()
        marker = self.f.root / "foreign-baseline"
        marker.write_text("unchanged")
        times = self.f.feed_times()
        with mock.patch.object(HELPER, "inspect_tools", side_effect=error):
            HELPER.restore(self.f.root, self.evidence, self.capsule, "auto", "true",
                           self.prior["cache_key"], self.prior["cache_key"], self.output)
        self.assertEqual(marker.read_text(), "unchanged")
        self.assertEqual(self.f.feed_times(), times)
        self.assertFalse(self.f.prefix.exists())
        self.assertFalse(self.f.build.exists())
        receipt = HELPER.read_json(self.evidence / "restore.json")
        self.assertEqual(receipt["origin"], "cold")
        self.assertTrue(receipt["cold_fallback_selected"])
        self.assertTrue(receipt["reason"])
        self.assertNotIn("origin=cache", self.output.read_text())

    def test_probe_timeout_after_install_rolls_back_to_cold(self):
        self.assert_probe_exception_clean_fallback(subprocess.TimeoutExpired(["fixture-probe"], 120))

    def test_probe_process_error_after_install_rolls_back_to_cold(self):
        self.assert_probe_exception_clean_fallback(subprocess.CalledProcessError(2, ["fixture-probe"]))

    def test_truncated_archive_auto_fallback(self):
        self.pack()
        payload = self.capsule / "payload.tar.gz"
        data = payload.read_bytes()
        payload.write_bytes(data[:len(data) // 2])
        self.manifest.update(payload_bytes=payload.stat().st_size, payload_sha256=HELPER.file_digest(payload))
        HELPER.write_json(self.capsule / "manifest.json", self.manifest)
        self.clear_owned()
        HELPER.restore(self.f.root, self.evidence, self.capsule, "auto", "true",
                       self.prior["cache_key"], self.prior["cache_key"], self.output)
        self.assertTrue(HELPER.read_json(self.evidence / "restore.json")["cold_fallback_selected"])
        self.assertFalse(self.f.build.exists())

    def test_quarantine_regular_file_unlinked_for_auto(self):
        self.clear_owned()
        self.capsule.write_text("invalid cache is a file")
        times = self.f.feed_times()
        HELPER.restore(self.f.root, self.evidence, self.capsule, "auto", "true",
                       self.prior["cache_key"], self.prior["cache_key"], self.output)
        self.assertFalse(self.capsule.exists())
        self.assertEqual(self.f.feed_times(), times)
        self.assertTrue(HELPER.read_json(self.evidence / "restore.json")["cold_fallback_selected"])

    def test_quarantine_symlink_unlinked_without_touching_foreign_target(self):
        self.clear_owned()
        foreign = self.base / "foreign"
        foreign.mkdir()
        marker = foreign / "marker"
        marker.write_text("untouched")
        self.capsule.symlink_to(foreign, target_is_directory=True)
        times = self.f.feed_times()
        HELPER.restore(self.f.root, self.evidence, self.capsule, "auto", "true",
                       self.prior["cache_key"], self.prior["cache_key"], self.output)
        self.assertFalse(self.capsule.is_symlink())
        self.assertEqual(marker.read_text(), "untouched")
        self.assertEqual(self.f.feed_times(), times)
        self.assertTrue(HELPER.read_json(self.evidence / "restore.json")["cold_fallback_selected"])

    def test_cleanup_failure_is_fatal_with_receipt_not_cold_success(self):
        self.pack()
        self.clear_owned()
        times = self.f.feed_times()
        with mock.patch.object(HELPER, "inspect_tools", side_effect=subprocess.TimeoutExpired(["probe"], 120)), \
             mock.patch.object(HELPER, "rollback_created", side_effect=OSError("injected uncertain rollback")):
            with self.assertRaises((HELPER.ContractError, OSError)):
                HELPER.restore(self.f.root, self.evidence, self.capsule, "auto", "true",
                               self.prior["cache_key"], self.prior["cache_key"], self.output)
        receipt = HELPER.read_json(self.evidence / "restore.json")
        self.assertNotEqual(receipt.get("origin"), "cache")
        self.assertFalse(receipt.get("cold_fallback_selected", False))
        self.assertEqual(self.f.feed_times(), times)
        self.assertNotIn("origin=cold", self.output.read_text())

    def test_nested_install_rollback_failure_is_fatal_with_receipt(self):
        self.pack()
        self.clear_owned()
        baseline = self.f.root / "foreign-baseline"
        baseline.write_text("untouched")
        times = self.f.feed_times()
        original_replace = Path.replace
        def fail_one_move(source, destination):
            if Path(destination) == self.f.prefix / "bin/cargo":
                raise OSError("injected mid-install move failure")
            return original_replace(source, destination)
        # Inject the OS failure after real staging and partial installation,
        # then failure of install_staged's own rollback, not restore's wrapper.
        with mock.patch.object(Path, "replace", autospec=True, side_effect=fail_one_move), \
             mock.patch.object(HELPER, "rollback_created", side_effect=OSError("injected nested rollback failure")):
            with self.assertRaises(HELPER.CleanupError):
                HELPER.restore(self.f.root, self.evidence, self.capsule, "auto", "true",
                               self.prior["cache_key"], self.prior["cache_key"], self.output)
        receipt = HELPER.read_json(self.evidence / "restore.json")
        self.assertNotEqual(receipt.get("origin"), "cache")
        self.assertFalse(receipt.get("cold_fallback_selected", False))
        self.assertNotIn("origin=cold", self.output.read_text())
        self.assertEqual(baseline.read_text(), "untouched")
        self.assertEqual(self.f.feed_times(), times)

    def test_wrong_quarantine_path_remains_fatal_and_untouched(self):
        self.clear_owned()
        foreign = self.base / "not-the-quarantine"
        foreign.write_text("keep")
        with self.assertRaises(HELPER.ContractError):
            HELPER.restore(self.f.root, self.evidence, foreign, "auto", "true",
                           self.prior["cache_key"], self.prior["cache_key"], self.output)
        self.assertEqual(foreign.read_text(), "keep")


REFERENCE_CAPTURED_STEP_NAMES = {'plugin-webui-full': ['Set up job',
                       'Run actions/checkout@v4',
                       'Install the SDK-compatible source-lock checker without a premature cache key',
                       'Validate the tracked dependency lock for tests and both package builds',
                       'Install test compiler and cache the actual plugin workspace and lock',
                       'Run actions/setup-node@v4',
                       'Prepare ordinary build dependencies',
                       'All Rust and real REST tests, including unchanged HTTPS case',
                       'Build matching daemon/plugin and actual generic WebUI package',
                       'Run actions/upload-artifact@v4',
                       'Post Run actions/setup-node@v4',
                       'Post Install test compiler and cache the actual plugin workspace and lock',
                       'Post Install the SDK-compatible source-lock checker without a premature cache key',
                       'Post Run actions/checkout@v4',
                       'Complete job'],
 'native-full / release validation (quic)': ['Set up job',
                                             'Run actions/checkout@v4',
                                             'Check result-gate and measurement source fixtures',
                                             'Prepare distribution dependencies (network enabled)',
                                             'Prepare pinned benchmark source archives',
                                             'Build and run complete existing suite (network disabled)',
                                             'Verify required cases actually executed',
                                             'Compare pinned upstream and candidate (network disabled)',
                                             'Run actions/upload-artifact@v4',
                                             'Post Run actions/checkout@v4',
                                             'Complete job'],
 'native-full / release validation (system)': ['Set up job',
                                               'Run actions/checkout@v4',
                                               'Check result-gate and measurement source fixtures',
                                               'Prepare distribution dependencies (network enabled)',
                                               'Prepare pinned benchmark source archives',
                                               'Build and run complete existing suite (network disabled)',
                                               'Verify required cases actually executed',
                                               'Compare pinned upstream and candidate (network disabled)',
                                               'Run actions/upload-artifact@v4',
                                               'Post Run actions/checkout@v4',
                                               'Complete job']}

class SourceAndReference(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="sdk-source-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.git("init", "-q")
        self.git("config", "user.name", "Fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        self.write(HELPER.RECIPE, "PKG_SOURCE_VERSION:=" + "1" * 40 + "\nPKG_HASH:=" + "2" * 64 + "\n# recipe unchanged\n")
        self.write(HELPER.WORKFLOW, "name: fixture\njobs:\n" + "".join(
            "  " + name + ":\n    if: original\n    steps:\n      - run: echo unchanged\n"
            for name in ("build", "native-full", "plugin-webui-full")))
        self.write("plugin/smartdns-ui/Cargo.lock", "fixture-source-lock\n")
        self.write("product.c", "product bytes\n")
        self.old = self.commit()

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.repo), *args], stderr=subprocess.PIPE).decode().strip()

    def write(self, name, text):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def commit(self):
        self.git("add", ".")
        self.git("commit", "-qm", "fixture commit")
        return self.git("rev-parse", "HEAD")

    def test_exact_reference_scope_allows_only_batch_files(self):
        self.write(HELPER.HELPER, "new helper\n")
        new = self.commit()
        self.assertEqual(HELPER.source_delta(self.repo, self.old, new, reference=True), [HELPER.HELPER])
        with self.assertRaises(HELPER.ContractError):
            HELPER.source_delta(self.repo, self.old, new, reference=False)

    def test_product_diff_rejected(self):
        self.write("product.c", "changed\n")
        with self.assertRaises(HELPER.ContractError):
            HELPER.source_delta(self.repo, self.old, self.commit(), reference=True)

    def test_lock_diff_rejected(self):
        self.write("plugin/smartdns-ui/Cargo.lock", "changed\n")
        with self.assertRaises(HELPER.ContractError):
            HELPER.source_delta(self.repo, self.old, self.commit(), reference=True)

    def test_non_sdk_command_diff_rejected(self):
        path = self.repo / HELPER.WORKFLOW
        path.write_text(path.read_text().replace("echo unchanged", "echo changed"))
        with self.assertRaises(HELPER.ContractError):
            HELPER.source_delta(self.repo, self.old, self.commit(), reference=True)

    def test_allowed_path_mode_drift_rejected(self):
        (self.repo / HELPER.WORKFLOW).chmod(0o755)
        with self.assertRaises(HELPER.ContractError):
            HELPER.source_delta(self.repo, self.old, self.commit(), reference=True)

    def source_archive(self, umask="0002"):
        archive = self.root / "source.tar.gz"
        # git archive uses pax_global_header; verify_source must still verify
        # every resulting product blob/mode rather than trust container hash.
        subprocess.run(["git", "-C", str(self.repo), "-c", "tar.umask=" + umask, "archive", "--format=tar.gz",
                        "--prefix=smartdns-" + self.old + "/", "-o", str(archive), self.old], check=True)
        digest = HELPER.file_digest(archive)
        self.write(HELPER.RECIPE, "PKG_SOURCE_VERSION:=" + self.old + "\nPKG_HASH:=" + digest + "\n# recipe unchanged\n")
        self.commit()
        return archive, digest

    def test_actual_git_archive_full_tree_lock_and_two_pin_gate(self):
        archive, digest = self.source_archive()
        result = HELPER.verify_source(self.repo, archive, self.old, digest,
                                      self.repo / "plugin/smartdns-ui/Cargo.lock")
        self.assertEqual(result["source"], self.old)
        self.assertEqual(result["tracked_files"], 4)

    def test_source_archive_codeload_and_local_modes_preserve_git_identity(self):
        self.write("run.sh", "#!/bin/sh\nexit 0\n")
        (self.repo / "run.sh").chmod(0o755)
        os.symlink("product.c", self.repo / "product-link")
        self.old = self.commit()
        for umask, regular, executable in (("0002", 0o664, 0o775), ("0022", 0o644, 0o755)):
            with self.subTest(umask=umask):
                archive, digest = self.source_archive(umask)
                with tarfile.open(archive) as tar:
                    modes = {m.name.rsplit("/", 1)[-1]: m.mode for m in tar}
                self.assertEqual(modes["product.c"], regular)
                self.assertEqual(modes["run.sh"], executable)
                self.assertEqual(modes["product-link"], 0o777)
                result = HELPER.verify_source(self.repo, archive, self.old, digest,
                                              self.repo / "plugin/smartdns-ui/Cargo.lock")
                self.assertEqual(result["tracked_files"], 6)

    def test_source_archive_permission_and_type_boundaries(self):
        archive, _ = self.source_archive()
        with tarfile.open(archive, "r:gz") as stream:
            original = [(copy.copy(m), stream.extractfile(m).read() if m.isfile() else b"") for m in stream]
        cases = [("file", mode) for mode in (0o600, 0o666, 0o777, 0o755, 0o645, 0o1644, 0o2644, 0o4644)]
        cases += [("dir", mode) for mode in (0o700, 0o777, 0o1775, 0o2775, 0o4775)]
        cases += [("type", value) for value in (tarfile.LNKTYPE, tarfile.SYMTYPE, tarfile.FIFOTYPE,
                                                tarfile.CHRTYPE, tarfile.BLKTYPE)]
        cases += [("sparse", None)]
        for kind, value in cases:
            with self.subTest(kind=kind, value=value):
                members = copy.deepcopy(original)
                index = next(i for i, (m, _) in enumerate(members)
                             if m.isdir()) if kind == "dir" else next(
                                 i for i, (m, _) in enumerate(members) if m.name.endswith("/product.c"))
                header, data = members[index]
                if kind in ("file", "dir"):
                    header.mode = value
                elif kind == "type":
                    header.type = value
                    header.linkname = "product.c"
                    header.size = 0
                else:
                    header.pax_headers = {"GNU.sparse.name": "product.c"}
                with tarfile.open(archive, "w:gz", format=tarfile.PAX_FORMAT) as stream:
                    for member, content in members:
                        stream.addfile(member, io.BytesIO(content) if member.isfile() else None)
                digest = HELPER.file_digest(archive)
                self.write(HELPER.RECIPE, "PKG_SOURCE_VERSION:=" + self.old + "\nPKG_HASH:=" + digest + "\n# recipe unchanged\n")
                self.commit()
                with self.assertRaises(HELPER.ContractError):
                    HELPER.verify_source(self.repo, archive, self.old, digest,
                                         self.repo / "plugin/smartdns-ui/Cargo.lock")

    def test_source_lock_mismatch_rejected(self):
        archive, digest = self.source_archive()
        wrong = self.root / "wrong-lock"
        wrong.write_text("not source lock")
        with self.assertRaises(HELPER.ContractError):
            HELPER.verify_source(self.repo, archive, self.old, digest, wrong)

    def test_source_archive_tampered_members_rejected_even_with_updated_pin(self):
        archive, _ = self.source_archive()
        with tarfile.open(archive, "r:gz") as stream:
            original = [(copy.copy(m), stream.extractfile(m).read() if m.isfile() else b"") for m in stream]
        for mutation in ("missing", "extra", "bytes", "mode", "duplicate"):
            with self.subTest(mutation=mutation):
                members = copy.deepcopy(original)
                position = next(i for i, (m, _) in enumerate(members) if m.name.endswith("/product.c"))
                header, content = members[position]
                if mutation == "missing":
                    members.pop(position)
                elif mutation == "extra":
                    header = tarfile.TarInfo("smartdns-" + self.old + "/extra")
                    members.append((header, b""))
                elif mutation == "bytes":
                    members[position] = (header, b"X" + content[1:])
                elif mutation == "mode":
                    header.mode = 0o755
                else:
                    members.append((copy.copy(header), content))
                with tarfile.open(archive, "w:gz") as stream:
                    for header, content in members:
                        stream.addfile(header, io.BytesIO(content) if header.isfile() else None)
                digest = HELPER.file_digest(archive)
                self.write(HELPER.RECIPE, "PKG_SOURCE_VERSION:=" + self.old + "\nPKG_HASH:=" + digest + "\n# recipe unchanged\n")
                self.commit()
                with self.assertRaises(HELPER.ContractError):
                    HELPER.verify_source(self.repo, archive, self.old, digest,
                                         self.repo / "plugin/smartdns-ui/Cargo.lock")

    def reference_data(self):
        # Reduced from captured REST raw jobs schema (not connector wrapper).
        # Actual required step strings preserved; local IDs/head are synthetic.
        steps = REFERENCE_CAPTURED_STEP_NAMES
        jobs = [{"id": i + 1, "run_id": 123, "name": name, "head_sha": self.old, "run_attempt": 2,
                 "status": "completed", "conclusion": "success",
                 "steps": [{"name": step, "status": "completed", "conclusion": "success"} for step in names]}
                for i, (name, names) in enumerate(steps.items())]
        metadata = {"id": 123, "run_attempt": 2, "head_sha": self.old, "path": HELPER.WORKFLOW,
                    "event": "workflow_dispatch", "repository": {"full_name": HELPER.REPOSITORY},
                    "status": "completed", "conclusion": "failure"}
        return metadata, jobs

    def reference(self, metadata, jobs, total=None):
        calls = []
        base = "/repos/" + HELPER.REPOSITORY + "/actions/runs/123/attempts/2"
        def fetch(path):
            calls.append(path)
            if path == base:
                return copy.deepcopy(metadata)
            self.assertTrue(path.startswith(base + "/jobs?per_page=100&page="))
            page = int(path.rsplit("=", 1)[1])
            self.assertLessEqual(page, 2)
            return {"total_count": len(jobs) if total is None else total,
                    "jobs": copy.deepcopy(jobs[(page - 1) * 100:page * 100])}
        result = HELPER.verify_reference(HELPER.REPOSITORY, 123, 2, self.old, self.repo, fetch=fetch)
        return result, calls

    def test_reference_required_non_sdk_success_does_not_hide_sdk_failure(self):
        data, jobs = self.reference_data()
        result, calls = self.reference(data, jobs)
        self.assertEqual(result["reference_total_conclusion"], "failure")
        self.assertEqual(len(result["accepted_non_sdk_jobs"]), 3)
        self.assertEqual(len(calls), 2)

    def test_reference_wrong_head_attempt_event_repository_rejected(self):
        data, jobs = self.reference_data()
        for field, value in (("head_sha", "f" * 40), ("run_attempt", 3),
                             ("event", "pull_request"), ("repository", {"full_name": "other/repo"})):
            with self.subTest(field=field):
                altered = copy.deepcopy(data)
                altered[field] = value
                with self.assertRaises(HELPER.ContractError):
                    self.reference(altered, jobs)

    def test_reference_pending_cancelled_unknown_outcome_rejected(self):
        data, jobs = self.reference_data()
        for status, conclusion in (("in_progress", None), ("completed", "cancelled"), ("completed", None)):
            with self.subTest(status=status, conclusion=conclusion):
                altered = copy.deepcopy(data)
                altered.update(status=status, conclusion=conclusion)
                with self.assertRaises(HELPER.ContractError):
                    self.reference(altered, jobs)

    def test_reference_cross_run_required_job_rejected(self):
        data, jobs = self.reference_data()
        jobs[0]["run_id"] = 124
        with self.assertRaises(HELPER.ContractError):
            self.reference(data, jobs)

    def test_reference_missing_raw_job_head_or_attempt_rejected(self):
        data, jobs = self.reference_data()
        for field in ("head_sha", "run_attempt", "run_id"):
            with self.subTest(field=field):
                altered = copy.deepcopy(jobs)
                del altered[0][field]
                with self.assertRaises(HELPER.ContractError):
                    self.reference(data, altered)

    def test_reference_required_step_failed_skipped_missing_rejected(self):
        data, jobs = self.reference_data()
        required = "Validate the tracked dependency lock for tests and both package builds"
        for status in ("failure", "skipped", "missing"):
            with self.subTest(status=status):
                altered = copy.deepcopy(jobs)
                job = next(j for j in altered if j["name"] == "plugin-webui-full")
                step = next(s for s in job["steps"] if s["name"] == required)
                if status == "missing":
                    job["steps"].remove(step)
                else:
                    step["conclusion"] = status
                with self.assertRaises(HELPER.ContractError):
                    self.reference(data, altered)

    def test_reference_duplicate_job_and_incomplete_page_rejected(self):
        data, jobs = self.reference_data()
        with self.assertRaises(HELPER.ContractError):
            self.reference(data, jobs + [jobs[0]])
        with self.assertRaises(HELPER.ContractError):
            self.reference(data, jobs, total=101)

    def test_reference_two_pages_consumed(self):
        data, jobs = self.reference_data()
        jobs = [{"id": 1000 + i, "name": "irrelevant"} for i in range(99)] + jobs
        result, calls = self.reference(data, jobs)
        self.assertEqual(len(calls), 3)
        self.assertEqual(len(result["accepted_non_sdk_jobs"]), 3)


def main():
    global SOURCE_DIR, HELPER
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk-source-dir", type=Path, required=True)
    parser.add_argument("--helper", type=Path, default=Path(__file__).with_name("sdk-host-cache.py"))
    args, rest = parser.parse_known_args()
    SOURCE_DIR = args.sdk_source_dir.resolve()
    verified_sources(SOURCE_DIR)
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("sdk_host_cache", args.helper)
    HELPER = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(HELPER)
    unittest.main(argv=[__file__, *rest])


if __name__ == "__main__":
    main()
