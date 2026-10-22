#!/usr/bin/env python3
"""Bounded cache contracts for the pinned SmartDNS OpenWrt SDK job.

This is not a package cache or a generic archive extractor.  GitHub's trusted
workflow/ref cache scope is the trust boundary; the manifest is not a signature.
"""

import argparse
import gzip
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import shlex
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
import urllib.request
import zlib

REPOSITORY = "polaris-arch/smartdns"
SCHEMA = 1
SDK_SHA = "229e871f734a2cee5ce3ad6a3e98d3836b0899bfdeaea4d9c2c5cc7b1fce1407"
BASE = "78b23a26c4c98938d549e7ff5876508544e33d4d"
PACKAGES = "f1470815f41fe199bfdafe9a91ad115bc2e91203"
RUST_SOURCE_SHA = "0b9d55610d8270e06c44f459d1e2b7918a5e673809c592abed9b9c600e33d95a"
RUST_FEED_SHA = "bab5fc713911fbf9b110a0266aa934ff24a5e9a89ef7b52fa1a7b907edec75f6"
RECIPE = "package/openwrt/Makefile"
WORKFLOW = ".github/workflows/webui.yml"
HELPER = ".github/scripts/sdk-host-cache.py"
TEST = ".github/scripts/test-sdk-host-cache.py"
PREFIX = "staging_dir/target-x86_64_musl/host"
BUILD = "build_dir/target-x86_64_musl/host/rustc-1.89.0-src"
INSTALL_STAMP = "staging_dir/hostpkg/stamp/.rust_installed"
RUST_FEED = "feeds/packages/lang/rust"
TARGETS = ("x86_64-unknown-linux-gnu", "x86_64-unknown-linux-musl")
MAX_MEMBERS = 100000
MAX_FILE = 1 << 30
MAX_EXPANDED = 4 << 30
MAX_CAPSULE = 2 << 30


class ContractError(ValueError):
    pass


class CapacityError(ContractError):
    pass


class CleanupError(ContractError):
    """Restoration ownership is uncertain; never continue with a cold build."""
    pass


def capacity(condition, message):
    if not condition:
        raise CapacityError(message)


def require(condition, message):
    if not condition:
        raise ContractError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def read_json(path):
    require(path.stat().st_size <= 64 * 1024 * 1024, "JSON size bound")
    return json.loads(path.read_text())


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    require(not path.is_symlink(), "JSON output symlink")
    temp = path.with_name(path.name + ".tmp")
    require(not temp.exists() and not temp.is_symlink(), "existing temporary output")
    try:
        with temp.open("x") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
        temp.replace(path)
    finally:
        if temp.exists():
            temp.unlink()


def command(argv, cwd=None):
    try:
        result = subprocess.run(argv, cwd=cwd, check=False, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=120)
    except subprocess.TimeoutExpired as exc:
        raise ContractError("command timed out: " + argv[0]) from exc
    require(result.returncode == 0, "command failed: %s: %s" %
            (argv[0], result.stderr.decode(errors="replace")[-2000:]))
    return result.stdout


def git(checkout, *args):
    return command(["git", "-C", str(checkout), *args])


def commit(value):
    require(bool(re.fullmatch(r"[0-9a-f]{40}", value)), "invalid commit identity")
    return value


def git_tree(checkout, sha):
    entries = {}
    for record in git(checkout, "ls-tree", "-rz", "--full-tree", commit(sha)).split(b"\0"):
        if not record:
            continue
        meta, name = record.split(b"\t", 1)
        mode, kind, oid = meta.decode().split()
        name = name.decode("utf-8")
        require(name not in entries and kind == "blob", "unsupported/duplicate tree member")
        entries[name] = (mode, oid)
    return entries


def recipe_without_pins(data):
    for field, width in ((b"PKG_SOURCE_VERSION", 40), (b"PKG_HASH", 64)):
        pattern = rb"(?m)^" + field + rb":=[0-9a-f]{" + str(width).encode() + rb"}$"
        require(len(re.findall(pattern, data)) == 1, "missing or duplicate literal recipe pin")
        data = re.sub(pattern, field + b":=<literal-pin>", data)
    return data


def non_sdk_jobs(data):
    text = data.decode()
    result = {}
    for name in ("build", "native-full", "plugin-webui-full"):
        match = re.search(r"(?ms)^  " + re.escape(name) + r":\n(.*?)(?=^  [a-z][a-z0-9-]*:\n|\Z)", text)
        require(match is not None, "missing original non-SDK job")
        body, count = re.subn(r"(?m)^    if:.*\n", "", match.group(1))
        require(count == 1, "non-SDK job condition count")
        result[name] = body
    return result


def source_delta(checkout, old, new, reference=False):
    old, new = commit(old), commit(new)
    git(checkout, "merge-base", "--is-ancestor", old, new)
    before, after = git_tree(checkout, old), git_tree(checkout, new)
    allowed = {RECIPE, WORKFLOW, HELPER, TEST} if reference else {RECIPE}
    changes = sorted(name for name in before.keys() | after.keys()
                     if before.get(name) != after.get(name))
    require(set(changes) <= allowed, "source delta outside exact allowed paths")
    for name in changes:
        require(name in after and after[name][0] == "100644", "unexpected source mode/deletion")
        if name in before:
            require(before[name][0] == after[name][0], "source mode changed")
    a = git(checkout, "show", old + ":" + RECIPE)
    b = git(checkout, "show", new + ":" + RECIPE)
    require(recipe_without_pins(a) == recipe_without_pins(b), "recipe functional drift")
    if reference:
        require(non_sdk_jobs(git(checkout, "show", old + ":" + WORKFLOW)) ==
                non_sdk_jobs(git(checkout, "show", new + ":" + WORKFLOW)),
                "non-SDK commands changed")
    return changes


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ContractError("GitHub API redirect refused")


def github_api(path):
    require(path.startswith("/repos/" + REPOSITORY + "/actions/"), "API path outside repository")
    token = os.environ.get("GH_TOKEN", "")
    require(bool(token), "missing read-only GitHub token")
    request = urllib.request.Request("https://api.github.com" + path, headers={
        "Accept": "application/vnd.github+json", "Authorization": "Bearer " + token,
        "X-GitHub-Api-Version": "2022-11-28"})
    with urllib.request.build_opener(NoRedirect).open(request, timeout=30) as response:
        payload = response.read(16 * 1024 * 1024 + 1)
    require(len(payload) <= 16 * 1024 * 1024, "GitHub response size")
    return json.loads(payload)


def verify_reference(repository, run, attempt, head, checkout, fetch=github_api):
    require(repository == REPOSITORY and run > 0 and attempt > 0, "reference identity")
    head = commit(head)
    base = "/repos/%s/actions/runs/%d/attempts/%d" % (repository, run, attempt)
    metadata = fetch(base)
    require(metadata.get("id") == run and metadata.get("run_attempt") == attempt and
            metadata.get("head_sha") == head and metadata.get("path") == WORKFLOW and
            metadata.get("event") == "workflow_dispatch" and
            metadata.get("repository", {}).get("full_name") == repository and
            metadata.get("status") == "completed" and metadata.get("conclusion") in ("success", "failure"),
            "reference run identity mismatch")
    jobs, total = [], None
    for page in range(1, 101):
        batch = fetch(base + "/jobs?per_page=100&page=" + str(page))
        require(isinstance(batch.get("jobs"), list), "reference jobs missing")
        if total is None:
            total = batch.get("total_count")
            require(isinstance(total, int) and 0 < total <= 10000, "reference job count")
        require(batch.get("total_count") == total, "reference pagination changed")
        jobs.extend(batch["jobs"])
        if len(jobs) >= total:
            break
        require(len(batch["jobs"]) == 100, "reference incomplete pagination")
    require(len(jobs) == total and len({j.get("id") for j in jobs}) == total,
            "reference jobs duplicate/incomplete")
    expected = {
        "plugin-webui-full": [
            "Validate the tracked dependency lock for tests and both package builds",
            "All Rust and real REST tests, including unchanged HTTPS case",
            "Build matching daemon/plugin and actual generic WebUI package"],
    }
    for profile in ("system", "quic"):
        steps = ["Check result-gate and measurement source fixtures",
                 "Build and run complete existing suite (network disabled)",
                 "Verify required cases actually executed"]
        if profile == "quic":
            steps += ["Prepare pinned benchmark source archives",
                      "Compare pinned upstream and candidate (network disabled)"]
        expected["native-full / release validation (" + profile + ")"] = steps
    accepted = []
    for name, required_steps in expected.items():
        matches = [job for job in jobs if job.get("name") == name]
        require(len(matches) == 1, "required reference job missing/duplicate: " + name)
        job = matches[0]
        require(job.get("run_id") == run and job.get("head_sha") == head and job.get("run_attempt") == attempt and
                job.get("status") == "completed" and job.get("conclusion") == "success",
                "required reference job did not pass: " + name)
        for step in required_steps:
            found = [s for s in job.get("steps", []) if s.get("name") == step]
            require(len(found) == 1 and found[0].get("status") == "completed" and
                    found[0].get("conclusion") == "success", "required reference step: " + step)
        accepted.append({"id": job["id"], "name": name, "required_steps": required_steps})
    current = git(checkout, "rev-parse", "HEAD").decode().strip()
    changed = source_delta(checkout, head, current, reference=True)
    return {"reference_run": run, "reference_attempt": attempt, "reference_head": head,
            "reference_total_status": metadata.get("status"),
            "reference_total_conclusion": metadata.get("conclusion"),
            "consumer_head": current, "accepted_non_sdk_jobs": accepted,
            "exact_allowed_changes": changed, "scope": "non-SDK evidence only; not SDK pass"}


def verify_source(checkout, archive, source, archive_sha256, lock):
    source = commit(source)
    require(bool(re.fullmatch(r"[0-9a-f]{64}", archive_sha256)), "invalid archive hash")
    require(file_digest(archive) == archive_sha256, "archive SHA256 mismatch")
    head = git(checkout, "rev-parse", "HEAD").decode().strip()
    recipe = git(checkout, "show", head + ":" + RECIPE)
    require(re.findall(rb"(?m)^PKG_SOURCE_VERSION:=(.*)$", recipe) == [source.encode()] and
            re.findall(rb"(?m)^PKG_HASH:=(.*)$", recipe) == [archive_sha256.encode()],
            "archive arguments do not match current recipe")
    changes = source_delta(checkout, source, head)
    tree = git_tree(checkout, source)
    prefix = "smartdns-" + source
    seen = set()
    total = 0
    with tarfile.open(archive, "r:gz") as tar:
        for index, member in enumerate(tar):
            require(index < 10000, "source archive member bound")
            name = member.name.rstrip("/")
            require(name == prefix or name.startswith(prefix + "/"), "source archive root")
            relative = name[len(prefix) + 1:]
            require(not relative or (not PurePosixPath(relative).is_absolute() and
                    all(part not in ("", ".", "..") for part in relative.split("/"))),
                    "noncanonical source archive path")
            # Git records regular/executable identity, not POSIX group-write.
            # Codeload emits 0664/0775 (equivalent to tar.umask=0002); local
            # git archive commonly uses 0022 (0644/0755). Accept precisely those
            # representations, never world-write, special bits or type drift.
            require(member.sparse is None and
                    not any(k.startswith("GNU.sparse") for k in member.pax_headers),
                    "source sparse member")
            if member.isdir():
                require(member.type == tarfile.DIRTYPE and member.mode in (0o755, 0o775),
                        "source directory mode")
                require(not relative or any(p.startswith(relative + "/") for p in tree),
                        "unexpected source directory")
                continue
            require(relative in tree and relative not in seen, "source member extra/duplicate")
            seen.add(relative)
            mode, expected = tree[relative]
            if mode == "120000":
                require(member.issym() and member.mode == 0o777, "source symlink mode mismatch")
                data = member.linkname.encode()
                actual = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
            else:
                require(member.type in (tarfile.REGTYPE, tarfile.AREGTYPE) and
                        mode in ("100644", "100755"), "source file type")
                expected_mode = int(mode[-3:], 8)
                require(member.mode in (expected_mode, expected_mode | 0o020),
                        "source executable mode")
                require(0 <= member.size <= 32 * 1024 * 1024, "source file bound")
                total += member.size
                require(total <= 64 * 1024 * 1024, "source total bound")
                h = hashlib.sha1(b"blob " + str(member.size).encode() + b"\0")
                with tar.extractfile(member) as stream:
                    for block in iter(lambda: stream.read(1024 * 1024), b""):
                        h.update(block)
                actual = h.hexdigest()
            require(actual == expected, "source blob mismatch: " + relative)
    require(seen == set(tree), "source archive missing tracked members")
    source_lock = git(checkout, "show", source + ":plugin/smartdns-ui/Cargo.lock")
    require(source_lock == lock.read_bytes(), "source/validated lock mismatch")
    return {"consumer_head": head, "source": source, "archive_sha256": archive_sha256,
            "archive_bytes": archive.stat().st_size, "tracked_files": len(tree),
            "lock_sha256": digest(source_lock), "source_changes": changes}


def safe_relative(value):
    require(isinstance(value, str) and value and not PurePosixPath(value).is_absolute(),
            "absolute or empty member path")
    require(len(value) <= 4096 and all(ord(c) >= 32 and ord(c) != 127 for c in value) and
            all(part not in ("", ".", "..") for part in value.split("/")) and
            "\\" not in value and "\0" not in value, "noncanonical member path")
    return value


def checked_path(root, relative):
    relative = safe_relative(relative)
    path = root / relative
    for parent in [root, *list(path.parents)[:-1]]:
        if parent == root or root in parent.parents:
            require(not parent.is_symlink(), "symlink parent refused")
    return path


def entry(root, path):
    relative = path.relative_to(root).as_posix()
    checked_path(root, relative)
    info = path.lstat()
    mode = stat.S_IMODE(info.st_mode)
    require(mode & 0o7000 == 0, "privileged file mode")
    item = {"path": relative, "mode": mode, "mtime_ns": info.st_mtime_ns}
    if stat.S_ISREG(info.st_mode):
        require(info.st_nlink == 1, "hardlinked file refused")
        capacity(info.st_size <= MAX_FILE, "file size bound")
        item.update(kind="file", size=info.st_size, sha256=file_digest(path))
    elif stat.S_ISDIR(info.st_mode):
        item.update(kind="dir")
    elif stat.S_ISLNK(info.st_mode):
        target = os.readlink(path)
        require(not os.path.isabs(target), "absolute symlink refused")
        resolved = os.path.normpath(str(PurePosixPath(relative).parent / target))
        safe_relative(resolved)
        item.update(kind="symlink", target=target)
    else:
        raise ContractError("special file refused")
    return item


def inventory(root, subtree):
    base = checked_path(root, subtree)
    require(base.is_dir() and not base.is_symlink(), "missing/linked inventory root")
    paths = [base]
    for directory, dirs, files in os.walk(base, followlinks=False):
        paths.extend(Path(directory) / name for name in dirs + files)
        capacity(len(paths) <= MAX_MEMBERS, "member count bound")
    return [entry(root, path) for path in sorted(set(paths))]


def without_times(entries):
    return [{key: value for key, value in e.items() if key != "mtime_ns"} for e in entries]


def capture_feed_state(sdk_root):
    return inventory(sdk_root, RUST_FEED)


def check_feed_state(sdk_root, entries, restore_mtime=False):
    actual = capture_feed_state(sdk_root)
    require(without_times(actual) == without_times(entries), "Rust feed member/content/mode drift")
    if restore_mtime:
        for item in entries:
            if item["kind"] == "file":
                path = checked_path(sdk_root, item["path"])
                os.utime(path, ns=(path.stat().st_atime_ns, item["mtime_ns"]), follow_symlinks=False)


def outputs(path, **values):
    if path is not None:
        with Path(path).open("a") as stream:
            for key, value in values.items():
                value = str(value)
                require(bool(re.fullmatch(r"[A-Za-z0-9_.:-]+", value)), "unsafe action output")
                stream.write(key + "=" + value + "\n")


def make_inputs(sdk_root):
    names = ("HOSTCC", "HOSTCXX", "HOST_CONFIGURE_VARS", "HOST_CONFIGURE_ARGS",
             "HOST_BUILD_DIR", "HOST_BUILD_PREFIX", "HOST_STAMP_PREPARED",
             "HOST_STAMP_INSTALLED", "RUSTC_HOST_ARCH", "RUSTC_TARGET_ARCH", "CARGO_HOME",
             "TARGET_PATH_PKG")
    # Query the real pinned package rules; never reimplement their target mapping.
    quote = lambda name: "$(subst ','\"'\"',$(" + name + "))"
    rule = "print-smartdns-cache-inputs: ; @" + "; ".join(
        "printf '%s\\0' '" + name + "=" + quote(name) + "'" for name in names)
    raw = command(["make", "--no-print-directory", "-s", "-C", str(sdk_root / RUST_FEED),
                   "TOPDIR=" + str(sdk_root), "IS_PACKAGE_BUILD=1", "--eval=" + rule,
                   "print-smartdns-cache-inputs"])
    values = {}
    for record in raw.split(b"\0"):
        if not record:
            continue
        name, value = record.decode().split("=", 1)
        require(name in names and name not in values and value, "make input output mismatch")
        values[name] = value
    require(set(values) == set(names), "make inputs incomplete")
    require(values["HOST_BUILD_DIR"] == str(sdk_root / BUILD) and
            values["HOST_STAMP_INSTALLED"] == str(sdk_root / INSTALL_STAMP) and
            values["RUSTC_HOST_ARCH"] == TARGETS[0] and values["RUSTC_TARGET_ARCH"] == TARGETS[1],
            "SDK host/target layout changed")
    return values


def collect_installed_entries(sdk_root, declared_sdk_root=None):
    """Use the real Rust installer's manifests, not two binaries or empty stamps."""
    # Rust's installed manifests contain absolute destinations, not the relative
    # manifest.in records. Quarantine has a different physical root: never rewrite
    # metadata or follow a declared absolute path back into the live SDK.
    declared = Path(declared_sdk_root) if declared_sdk_root is not None else sdk_root
    require(declared.is_absolute() and str(PurePosixPath(str(declared))) == str(declared)
            and ".." not in declared.parts, "noncanonical declared SDK root")
    declared_prefix = str(declared / PREFIX) + "/"
    metadata = checked_path(sdk_root, PREFIX + "/lib/rustlib")
    components_file = metadata / "components"
    require(components_file.is_file() and not components_file.is_symlink(), "missing installer components")
    require(components_file.stat().st_size <= 65536, "component list size")
    components = components_file.read_text().splitlines()
    require(components and len(components) == len(set(components)) and
            {"rustc", "cargo"}.issubset(components), "incomplete/duplicate installer components")
    require(all(re.fullmatch(r"[A-Za-z0-9_.+-]+", c) for c in components), "unsafe component")
    paths = {components_file}
    for component in components:
        manifest = metadata / ("manifest-" + component)
        require(manifest.is_file() and not manifest.is_symlink() and
                manifest.stat().st_size <= 16 * 1024 * 1024, "missing/bounded installer manifest")
        paths.add(manifest)
        for line in manifest.read_text().splitlines():
            kind, separator, installed = line.partition(":")
            require(separator and kind in ("file", "dir"), "installer manifest record")
            require(installed.startswith(declared_prefix), "installer destination outside declared prefix")
            relative = safe_relative(installed[len(declared_prefix):])
            require(installed == declared_prefix + relative, "noncanonical installer destination")
            path = checked_path(sdk_root, PREFIX + "/" + relative)
            require(path.exists() or path.is_symlink(), "installer member missing")
            if kind == "dir":
                require(path.is_dir() and not path.is_symlink(), "installer directory invalid")
                paths.update(sdk_root / item["path"] for item in inventory(sdk_root, PREFIX + "/" + relative))
            else:
                require(not path.is_dir(), "installer file is directory")
                paths.add(path)
            capacity(len(paths) <= MAX_MEMBERS, "installer member bound")
    for name in ("rust-installer-version", "uninstall.sh"):
        path = metadata / name
        require(path.is_file() and not path.is_symlink(), "missing installer metadata " + name)
        paths.add(path)
    prefix = sdk_root / PREFIX
    for path in tuple(paths):
        parent = path.parent
        while parent != prefix.parent:
            paths.add(parent)
            parent = parent.parent
    build = checked_path(sdk_root, BUILD)
    require(build.is_dir() and not build.is_symlink(), "missing host stamp directory")
    stamps = []
    for path in build.iterdir():
        # A successful official AUTOREMOVE leaves only genuine empty dot files.
        require(path.name.startswith(".") and path.is_file() and not path.is_symlink()
                and path.stat().st_size == 0, "host build not safely auto-removed")
        require(re.fullmatch(r"\.(?:prepared[^/]*|configured[^/]*|built(?:_check(?:\.1)?)?)", path.name),
                "unknown host stamp")
        # rdep's empty check hints are regenerated by official make. Their
        # presence can legitimately change without any host recompilation.
        if not path.name.endswith(("_check", "_check.1")):
            stamps.append(path)
    require(any(p.name.startswith(".prepared") and not p.name.endswith(("_check", "_check.1")) for p in stamps)
            and build / ".configured" in stamps and build / ".built" in stamps, "missing lifecycle stamps")
    installed = checked_path(sdk_root, INSTALL_STAMP)
    require(installed.is_file() and not installed.is_symlink() and installed.stat().st_size == 0,
            "missing genuine installed stamp")
    paths.update(stamps + [build, installed])
    entries = [entry(sdk_root, path) for path in sorted(paths)]
    capacity(len(entries) <= MAX_MEMBERS and
            sum(e.get("size", 0) for e in entries) <= MAX_EXPANDED, "installed closure capacity")
    index = {e["path"]: e for e in entries}
    for item in entries:
        if item["kind"] == "symlink":
            target = os.path.normpath(str(PurePosixPath(item["path"]).parent / item["target"]))
            visited = {item["path"]}
            while True:
                require(target in index and target not in visited, "symlink outside closure/cycle")
                visited.add(target)
                dest = index[target]
                if dest["kind"] != "symlink":
                    break
                target = os.path.normpath(str(PurePosixPath(target).parent / dest["target"]))
    for tool in ("rustc", "cargo"):
        item = index.get(PREFIX + "/bin/" + tool)
        require(item is not None and item["kind"] == "file" and item["mode"] & 0o111,
                "missing executable " + tool)
    for target in TARGETS:
        require(any(e["path"].startswith(PREFIX + "/lib/rustlib/" + target + "/lib/libstd-")
                    and e["kind"] == "file" for e in entries), "missing target std " + target)
    return entries


def validate_installed_closure(sdk_root, entries, declared_sdk_root=None):
    actual = collect_installed_entries(sdk_root, declared_sdk_root)
    require(without_times(actual) == without_times(entries),
            "installed closure member/content/mode mismatch")
    expected = {e["path"]: e for e in entries}
    for item in actual:
        if item["kind"] == "file" and (item["path"].startswith(BUILD + "/") or item["path"] == INSTALL_STAMP):
            require(item["mtime_ns"] == expected[item["path"]]["mtime_ns"], "primary lifecycle stamp changed")


def validate_lifecycle(entries, prior, feed):
    """Preflight the real HostBuild dependency chain, without touching stamps."""
    identity = prior["identity"]
    root = identity["sdk_root"]
    require(isinstance(root, str) and root.startswith("/") and
            str(PurePosixPath(root)) == root and ".." not in PurePosixPath(root).parts,
            "lifecycle SDK root identity")
    absolute = identity["make"]["HOST_STAMP_PREPARED"]
    require(isinstance(absolute, str) and absolute.startswith(root + "/"), "prepared stamp root")
    prepared = safe_relative(absolute[len(root) + 1:])
    require(prepared.startswith(BUILD + "/.prepared") and
            "/" not in prepared[len(BUILD) + 1:] and
            not prepared.endswith(("_check", "_check.1")), "prepared stamp identity")
    index = {item["path"]: item for item in entries}
    primaries = {p for p in index if p.startswith(BUILD + "/.prepared") and
                 not p.endswith(("_check", "_check.1"))}
    require(primaries == {prepared}, "effective prepared stamp missing/ambiguous")
    times = []
    for path in (prepared, BUILD + "/.configured", BUILD + "/.built", INSTALL_STAMP):
        item = index.get(path, {})
        require(item.get("kind") == "file" and item.get("size") == 0 and
                type(item.get("mtime_ns")) is int and 0 <= item["mtime_ns"] < (1 << 63),
                "missing/invalid primary lifecycle stamp")
        times.append(item["mtime_ns"])
    require(times == sorted(times), "host dependency timestamp order would rebuild")
    require(type(identity["autorebuild"]) is bool, "unknown effective AUTOREBUILD")
    if identity["autorebuild"]:
        for item in feed:
            if item["kind"] == "file":
                require(type(item["mtime_ns"]) is int and 0 <= item["mtime_ns"] < (1 << 63),
                        "invalid producer feed timestamp")
                # Official timestamp.pl compares integer st_mtime seconds.
                require(item["mtime_ns"] // 1000000000 <= times[0] // 1000000000,
                        "Rust feed timestamp would invalidate prepared stamp")


def inputs(sdk_root, evidence, github_output):
    require(sdk_root.is_absolute() and sdk_root.resolve() == sdk_root and not sdk_root.is_symlink(),
            "SDK root must be a fixed real absolute path")
    require(os.environ.get("CI") == "true" and os.environ.get("GITHUB_ACTIONS") == "true", "real CI identity required")
    require(os.uname().machine == "x86_64", "unsupported host ABI")
    require(file_digest(sdk_root / RUST_FEED / "Makefile") == RUST_FEED_SHA, "feed overlay identity")
    require(git(sdk_root / "feeds/base", "rev-parse", "HEAD").decode().strip() == BASE and
            git(sdk_root / "feeds/packages", "rev-parse", "HEAD").decode().strip() == PACKAGES,
            "feed commit identity")
    config = (sdk_root / ".config").read_text()
    require("CONFIG_AUTOREMOVE=y\n" in config, "cache lifecycle requires official AUTOREMOVE")
    variables = make_inputs(sdk_root)
    tools = {}
    for name in ("HOSTCC", "HOSTCXX"):
        argv = shlex.split(variables[name])
        require(argv, "missing host compiler")
        executable = shutil.which(argv[0], path=variables["TARGET_PATH_PKG"])
        require(executable is not None, "host compiler unavailable")
        executable = str(Path(executable).resolve())
        tools[name] = {"argv": argv, "executable": executable,
                       "sha256": file_digest(Path(executable)),
                       "version": command([executable, *argv[1:], "--version"]).decode()}
    identity = {"schema": SCHEMA, "sdk_sha256": SDK_SHA, "rust_source_sha256": RUST_SOURCE_SHA,
                "base": BASE, "packages": PACKAGES, "sdk_root": str(sdk_root),
                "helper_sha256": file_digest(Path(__file__)), "make": variables,
                "feed": without_times(capture_feed_state(sdk_root)), "config_sha256": digest(config.encode()),
                "autorebuild": "CONFIG_AUTOREBUILD=y\n" in config,
                "sdk_files": {p: file_digest(sdk_root / p) for p in
                              ("rules.mk", "include/host-build.mk", "include/depends.mk", "include/package.mk",
                               "scripts/timestamp.pl", "feeds.conf")},
                "os_release": Path("/etc/os-release").read_text(), "machine": os.uname().machine,
                "runner_image": {k: os.environ.get(k, "") for k in ("ImageOS", "ImageVersion", "RUNNER_OS", "RUNNER_ARCH")},
                "system_packages": command(["dpkg-query", "-W", "-f=${binary:Package}=${Version}\n"]).decode(),
                "compilers": tools, "make_version": command(["make", "--version"]).decode()}
    key = "smartdns-sdk-host-v%d-%s" % (SCHEMA, digest(canonical(identity)))
    write_json(evidence / "inputs.json", {"cache_key": key, "identity": identity})
    outputs(github_output, cache_key=key)


def validate_bootstrap(text):
    require(isinstance(text, str) and len(text.encode()) < 65536, "bootstrap config size")
    config = tomllib.loads(text)
    require(config["build"]["build"] == TARGETS[0] and config["build"]["host"] == [TARGETS[0]]
            and set(config["build"]["target"]) == set(TARGETS) and config["build"]["jobs"] == 2
            and config["llvm"]["download-ci-llvm"] is False and config["llvm"]["link-jobs"] == 1
            and config["llvm"]["targets"] == "X86" and config["llvm"]["experimental-targets"] == "",
            "actual bootstrap configuration mismatch")


def capture(sdk_root, evidence):
    prior = read_json(evidence / "inputs.json")
    require(make_inputs(sdk_root) == prior["identity"]["make"], "configure changed effective host inputs")
    path = checked_path(sdk_root, BUILD + "/bootstrap.toml")
    require(path.is_file() and not path.is_symlink() and path.stat().st_size < 65536, "missing genuine bootstrap config")
    text = path.read_text()
    validate_bootstrap(text)
    producer = {k: os.environ.get(k, "") for k in
                ("GITHUB_REPOSITORY", "GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")}
    require(producer["GITHUB_REPOSITORY"] == REPOSITORY and
            re.fullmatch(r"[0-9a-f]{40}", producer["GITHUB_SHA"]) and
            all(re.fullmatch(r"[1-9][0-9]*", producer[k]) for k in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")),
            "producer identity unavailable")
    write_json(evidence / "producer.json", {"producer": producer, "inputs": prior,
               "feed": capture_feed_state(sdk_root), "bootstrap_toml": text,
               "bootstrap_sha256": digest(text.encode())})


def inspect_tools(sdk_root):
    prefix = sdk_root / PREFIX
    report = {"tools": {}, "runtime_modules": {}, "target_std": {}}
    for name in ("rustc", "cargo"):
        path = checked_path(sdk_root, PREFIX + "/bin/" + name)
        info = entry(sdk_root, path)
        require(info["kind"] == "file" and info["mode"] & 0o111, "tool not executable")
        with path.open("rb") as stream:
            header = stream.read(20)
        require(header[:6] == b"\x7fELF\x02\x01" and int.from_bytes(header[18:20], "little") == 62,
                "tool not actual x86_64 ELF")
        version = command([str(path), "-vV"]).decode()
        require(version.startswith(name + " 1.89.0 "), "wrong actual tool version")
        report["tools"][name] = {"sha256": info["sha256"], "version": version}
        # This runs only trusted-scope, verified compiler bytes. The capsule's
        # digest is consistency evidence, not a signature for arbitrary code.
        dependencies = command(["ldd", str(path)]).decode()
        require("not found" not in dependencies, "missing runtime library")
        for line in dependencies.splitlines():
            match = re.search(r"(?:=>\s+)?(/\S+)\s+\(", line)
            if not match:
                require("linux-vdso.so" in line or not line.strip(), "unparsed runtime dependency")
                continue
            resolved = Path(match.group(1)).resolve(strict=True)
            require(resolved.is_file(), "runtime module not regular")
            if prefix in resolved.parents:
                identity = resolved.relative_to(sdk_root).as_posix()
            else:
                require(any(Path(base) in resolved.parents for base in ("/lib", "/lib64", "/usr/lib", "/usr/lib64")),
                        "runtime dependency outside captured prefix/system ABI")
                identity = str(resolved)
            report["runtime_modules"][identity] = file_digest(resolved)
    rustc = str(prefix / "bin/rustc")
    sysroot = command([rustc, "--print", "sysroot"]).decode().strip()
    require(Path(sysroot).resolve() == prefix, "unexpected tool sysroot")
    report["sysroot"] = sysroot
    for target in TARGETS:
        directory = command([rustc, "--print", "target-libdir", "--target", target]).decode().strip()
        expected = prefix / "lib/rustlib" / target / "lib"
        require(Path(directory).resolve() == expected, "unexpected target libdir")
        libraries = sorted(expected.glob("libstd-*.rlib"))
        require(libraries, "actual target standard library missing")
        report["target_std"][target] = {p.name: file_digest(p) for p in libraries}
    return report


def probe(sdk_root, evidence, origin):
    require(origin in ("cold", "cache"), "unknown host origin")
    path = evidence / "host-probes.json"
    observations = read_json(path) if path.exists() else []
    require(len(observations) < 2, "duplicate host probe")
    tools = inspect_tools(sdk_root)
    if observations:
        require(observations[0]["tools"] == tools, "application changed host compiler/runtime")
    try:
        entries = collect_installed_entries(sdk_root)
    except CapacityError as exc:
        require(origin == "cold", "restored closure exceeds cache bounds")
        observations.append({"origin": origin, "phase": "after-host" if not observations else "after-application",
                             "time_ns": time.time_ns(), "tools": tools, "closure_eligible": False,
                             "reason": str(exc)})
        write_json(path, observations)
        return
    indexed = {e["path"]: e for e in entries}
    for module, sha in tools["runtime_modules"].items():
        if not module.startswith("/"):
            require(module in indexed and indexed[module].get("sha256") == sha, "runtime module absent from closure")
    if origin == "cache":
        manifest = read_json(evidence / "restored-manifest.json")
        validate_installed_closure(sdk_root, manifest["entries"])
        require(tools == manifest["tools"], "restored tool/runtime identity changed")
        for logfile in ("rust-host-compile.log", "compile.log"):
            log = evidence / logfile
            if log.exists():
                require(not re.search(r"x\.py(?:\s|['\"]).*(?:\bdist\b|\bbuild-manifest\b)", log.read_text()),
                        "warm official entry rebuilt host")
    if observations:
        require(observations[0].get("closure_sha256") == digest(canonical(without_times(entries))),
                "application changed installed host closure")
    observations.append({"origin": origin, "phase": "after-host" if not observations else "after-application",
                         "time_ns": time.time_ns(), "tools": tools, "closure_eligible": True,
                         "closure_sha256": digest(canonical(without_times(entries)))})
    write_json(path, observations)


def snapshot(sdk_root, evidence, capsule_dir, github_output):
    started = time.time_ns()
    prior = read_json(evidence / "inputs.json")
    producer = read_json(evidence / "producer.json")
    probes = read_json(evidence / "host-probes.json")
    require(len(probes) == 1 and probes[0]["origin"] == "cold", "snapshot requires actual cold host probe")
    require(producer["inputs"] == prior, "producer input identity changed")
    check_feed_state(sdk_root, producer["feed"])
    if probes[0].get("closure_eligible") is False:
        write_json(evidence / "snapshot.json", {"save_ready": False, "reason": probes[0]["reason"],
                   "started_ns": started, "ended_ns": time.time_ns()})
        outputs(github_output, save_ready="false")
        return
    entries = collect_installed_entries(sdk_root)
    validate_lifecycle(entries, prior, producer["feed"])
    total = sum(item.get("size", 0) for item in entries)
    report = {"expanded_bytes": total, "members": len(entries), "started_ns": started,
              "cache_key": prior["cache_key"], "save_ready": False}
    require(not capsule_dir.exists() and not capsule_dir.is_symlink(), "cold capsule directory already exists")
    capsule_dir.mkdir(parents=True)
    free = shutil.disk_usage(capsule_dir).free
    if total > MAX_EXPANDED or free < min(total, MAX_CAPSULE) + (128 << 20):
        report.update(reason="bounded-capacity-or-free-space", free_bytes=free, ended_ns=time.time_ns())
        write_json(evidence / "snapshot.json", report)
        outputs(github_output, save_ready="false")
        return
    payload = capsule_dir / "payload.tar.gz"
    try:
        with tarfile.open(payload, "w:gz", compresslevel=1, dereference=False) as archive:
            for item in entries:
                path = checked_path(sdk_root, item["path"])
                require(entry(sdk_root, path) == item, "closure changed during snapshot")
                header = archive.gettarinfo(str(path), arcname=item["path"])
                header.uid = header.gid = 0
                header.uname = header.gname = ""
                if header.isfile():
                    with path.open("rb") as stream:
                        archive.addfile(header, stream)
                else:
                    archive.addfile(header)
                require(payload.stat().st_size <= MAX_CAPSULE, "compressed capsule capacity")
        require(payload.stat().st_size <= MAX_CAPSULE, "compressed capsule capacity")
        validate_installed_closure(sdk_root, entries)
        manifest = {"schema": SCHEMA, "cache_key": prior["cache_key"], "producer": producer,
                    "entries": entries, "tools": probes[0]["tools"], "expanded_bytes": total,
                    "payload_bytes": payload.stat().st_size, "payload_sha256": file_digest(payload)}
        write_json(capsule_dir / "manifest.json", manifest)
        report.update(save_ready=True, compressed_bytes=payload.stat().st_size,
                      payload_sha256=manifest["payload_sha256"], ended_ns=time.time_ns(),
                      persistence="not proven by snapshot or cache/save step success")
    except (OSError, ContractError) as exc:
        # Capacity does not turn a real successful cold compiler into a fake
        # cached success. Dedicated cold validation separately requires a capsule.
        if payload.exists():
            payload.unlink()
        if isinstance(exc, ContractError) and "capacity" not in str(exc):
            raise
        report.update(reason=str(exc), ended_ns=time.time_ns())
    write_json(evidence / "snapshot.json", report)
    outputs(github_output, save_ready=str(report["save_ready"]).lower())


class CapsuleTarInfo(tarfile.TarInfo):
    """Only our small PAX vocabulary; no sparse/global/GNU extension parser."""
    def _proc_member(self, archive):
        if self.type == tarfile.XHDTYPE:
            require(not getattr(archive, "_cache_pax_pending", False), "nested PAX refused")
            require(0 <= self.size <= 16384, "PAX metadata bound")
            data = archive.fileobj.read(((self.size + 511) // 512) * 512)[:self.size]
            require(len(data) == self.size, "truncated PAX")
            values = {}
            offset = 0
            while offset < len(data):
                end = data.find(b" ", offset, offset + 10)
                require(end > offset and data[offset:end].isdigit(), "PAX record length")
                length = int(data[offset:end])
                require(end + 1 < offset + length <= len(data) and data[offset + length - 1:offset + length] == b"\n",
                        "PAX record boundary")
                key, sep, value = data[end + 1:offset + length - 1].partition(b"=")
                require(sep and key in (b"path", b"linkpath", b"mtime") and key not in values
                        and len(value) <= 4096, "unsupported/duplicate PAX field")
                values[key] = value.decode("utf-8", errors="strict")
                offset += length
            archive._cache_pax_pending = True
            try:
                following = type(self).fromtarfile(archive)
            finally:
                archive._cache_pax_pending = False
            if b"path" in values:
                following.name = values[b"path"].rstrip("/")
            if b"linkpath" in values:
                following.linkname = values[b"linkpath"]
            if b"mtime" in values:
                following.mtime = float(values[b"mtime"])
                require(math.isfinite(following.mtime), "nonfinite PAX time")
            following.offset = self.offset
            return following
        require(self.type in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE, tarfile.SYMTYPE),
                "unsupported tar type (including hardlink/sparse/device)")
        return super()._proc_member(archive)


def validate_manifest(manifest, prior):
    require(manifest["schema"] == SCHEMA and manifest["cache_key"] == prior["cache_key"] and
            manifest["producer"]["inputs"] == prior, "capsule input/key mismatch")
    producer = manifest["producer"]
    require(producer["bootstrap_sha256"] == digest(producer["bootstrap_toml"].encode()), "bootstrap evidence digest")
    validate_bootstrap(producer["bootstrap_toml"])
    identity = producer["producer"]
    require(identity["GITHUB_REPOSITORY"] == REPOSITORY and
            re.fullmatch(r"[0-9a-f]{40}", identity["GITHUB_SHA"]) and
            all(re.fullmatch(r"[1-9][0-9]*", identity[k]) for k in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")),
            "capsule producer identity")
    require(without_times(producer["feed"]) == prior["identity"]["feed"], "producer feed mismatch")
    entries = manifest["entries"]
    require(isinstance(entries, list) and 0 < len(entries) <= MAX_MEMBERS, "capsule entry count")
    index = {}
    total = 0
    for item in entries:
        path = safe_relative(item["path"])
        require(path not in index and (path == PREFIX or path.startswith(PREFIX + "/") or
                path == BUILD or (path.startswith(BUILD + "/.") and "/" not in path[len(BUILD) + 1:]) or
                path == INSTALL_STAMP), "capsule member outside installed closure")
        require(type(item["mode"]) is int and 0 <= item["mode"] <= 0o777 and
                type(item["mtime_ns"]) is int and 0 <= item["mtime_ns"] < (1 << 63), "capsule file attributes")
        require(item["kind"] in ("file", "dir", "symlink"), "capsule member kind")
        if item["kind"] == "file":
            require(type(item["size"]) is int and 0 <= item["size"] <= MAX_FILE and
                    re.fullmatch(r"[0-9a-f]{64}", item["sha256"]), "capsule file bounds/hash")
            total += item["size"]
        elif item["kind"] == "symlink":
            require(isinstance(item["target"], str) and not os.path.isabs(item["target"]), "absolute symlink")
            safe_relative(os.path.normpath(str(PurePosixPath(path).parent / item["target"])))
        index[path] = item
    require(total == manifest["expanded_bytes"] and total <= MAX_EXPANDED and
            type(manifest["payload_bytes"]) is int and 0 < manifest["payload_bytes"] <= MAX_CAPSULE and
            re.fullmatch(r"[0-9a-f]{64}", manifest["payload_sha256"]), "capsule aggregate bounds/hash")
    validate_lifecycle(manifest["entries"], prior, manifest["producer"]["feed"])
    return index


def unpack_capsule(payload, staging, manifest):
    expected = {item["path"]: item for item in manifest["entries"]}
    require(payload.is_file() and not payload.is_symlink() and payload.stat().st_nlink == 1 and
            payload.stat().st_size == manifest["payload_bytes"] and
            file_digest(payload) == manifest["payload_sha256"], "capsule payload mismatch")
    require(shutil.disk_usage(staging).free >= manifest["expanded_bytes"] + (128 << 20), "restore free-space bound")
    seen = set()
    with tarfile.open(payload, "r|gz", tarinfo=CapsuleTarInfo) as archive:
        for member in archive:
            name = safe_relative(member.name.rstrip("/"))
            require(name in expected and name not in seen, "extra/duplicate capsule member")
            seen.add(name)
            item = expected[name]
            kind = "dir" if member.isdir() else "file" if member.isfile() else "symlink" if member.issym() else "unsupported"
            require(kind == item["kind"] and member.mode == item["mode"] and member.uid == member.gid == 0,
                    "capsule tar attributes mismatch")
            destination = checked_path(staging, name)
            destination.parent.mkdir(parents=True, exist_ok=True)
            if kind == "dir":
                destination.mkdir(exist_ok=True)
            elif kind == "file":
                require(member.size == item["size"], "capsule tar size mismatch")
                stream = archive.extractfile(member)
                require(stream is not None, "missing capsule data")
                with destination.open("xb") as output:
                    shutil.copyfileobj(stream, output, length=1024 * 1024)
            else:
                require(member.linkname == item["target"], "capsule link target mismatch")
                destination.symlink_to(member.linkname)
            if kind != "symlink":
                destination.chmod(item["mode"])
                os.utime(destination, ns=(item["mtime_ns"], item["mtime_ns"]), follow_symlinks=False)
            require(without_times([entry(staging, destination)]) == without_times([item]), "unpacked member mismatch")
    require(seen == set(expected), "capsule members missing")
    validate_installed_closure(staging, manifest["entries"],
                               Path(manifest["producer"]["inputs"]["identity"]["sdk_root"]))


def install_staged(staging, sdk_root, entries, declared_sdk_root=None):
    created = []
    # Full conflict check before the first write into the SDK; never overwrite
    # baseline SDK content, even when a restored entry claims identical bytes.
    for item in entries:
        destination = checked_path(sdk_root, item["path"])
        if destination.exists() or destination.is_symlink():
            require(item["kind"] == "dir" and destination.is_dir() and not destination.is_symlink()
                    and stat.S_IMODE(destination.stat().st_mode) == item["mode"], "restore destination conflict")
    try:
        for item in sorted(entries, key=lambda e: (e["path"].count("/"), e["kind"] != "dir", e["path"])):
            source = checked_path(staging, item["path"])
            destination = checked_path(sdk_root, item["path"])
            parents = []
            parent = destination.parent
            while not parent.exists():
                parents.append(parent)
                parent = parent.parent
            for parent in reversed(parents):
                parent.mkdir()
                created.append(parent)
            if item["kind"] == "dir":
                if not destination.exists():
                    destination.mkdir(mode=item["mode"])
                    created.append(destination)
            else:
                source.replace(destination)
                created.append(destination)
        validate_installed_closure(sdk_root, entries, declared_sdk_root)
        return created
    except BaseException:
        try:
            rollback_created(created)
        except (ContractError, OSError) as cleanup:
            raise CleanupError("staged installation rollback incomplete") from cleanup
        raise


def rollback_created(created):
    for path in reversed(created):
        if path.is_symlink() or path.is_file():
            path.unlink()
        elif path.is_dir():
            path.rmdir()


def clear_quarantine(path):
    """Remove this job-owned entry, never a symlink target or another SDK path."""
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.exists():
        require(path.is_dir(), "unexpected quarantine filesystem type")
        shutil.rmtree(path)


def restore(sdk_root, evidence, capsule_dir, mode, cache_hit, matched_key, key, github_output):
    require(mode in ("auto", "cold", "warm"), "invalid cache mode")
    require(capsule_dir == sdk_root.parent / "sdk-host-capsule",
            "capsule must be the dedicated sibling quarantine")
    prior = read_json(evidence / "inputs.json")
    require(sdk_root.is_absolute() and sdk_root.is_dir() and sdk_root.resolve() == sdk_root
            and not sdk_root.is_symlink() and str(sdk_root) == prior["identity"]["sdk_root"],
            "SDK root identity mismatch")
    require(key == prior["cache_key"], "requested cache key mismatch")
    record = {"mode": mode, "cache_hit": cache_hit, "matched_key": matched_key,
              "requested_key": key, "started_ns": time.time_ns(), "origin": "cold"}
    created = []
    feed_before = capture_feed_state(sdk_root)
    try:
        require(mode != "cold", "dedicated cold selection")
        require(cache_hit == "true" and matched_key == key, "no exact primary-key hit")
        require(not capsule_dir.is_symlink() and capsule_dir.is_dir() and
                {p.name for p in capsule_dir.iterdir()} == {"manifest.json", "payload.tar.gz"},
                "capsule directory incomplete/extra members")
        manifest_path = capsule_dir / "manifest.json"
        require(manifest_path.is_file() and not manifest_path.is_symlink() and manifest_path.stat().st_nlink == 1,
                "invalid capsule manifest file")
        manifest = read_json(manifest_path)
        validate_manifest(manifest, prior)
        check_feed_state(sdk_root, manifest["producer"]["feed"])
        with tempfile.TemporaryDirectory(prefix="sdk-host-verify-", dir=sdk_root.parent) as temporary:
            staging = Path(temporary)
            unpack_capsule(capsule_dir / "payload.tar.gz", staging, manifest)
            created = install_staged(staging, sdk_root, manifest["entries"])
        tools = inspect_tools(sdk_root)
        require(tools == manifest["tools"], "restored binary/runtime/target identity mismatch")
        check_feed_state(sdk_root, manifest["producer"]["feed"], restore_mtime=True)
        write_json(evidence / "restored-manifest.json", manifest)
        write_json(evidence / "producer.json", manifest["producer"])
        (evidence / "rust-bootstrap.toml").write_text(manifest["producer"]["bootstrap_toml"])
        record.update(origin="cache", producer=manifest["producer"]["producer"],
                      payload_bytes=manifest["payload_bytes"], expanded_bytes=manifest["expanded_bytes"])
    except CleanupError as exc:
        record.update(reason=str(exc), cleanup_error=str(exc), cold_fallback_selected=False,
                      ended_ns=time.time_ns())
        write_json(evidence / "restore.json", record)
        raise
    except (ContractError, OSError, ValueError, KeyError, TypeError, tarfile.TarError,
            subprocess.SubprocessError, EOFError, zlib.error) as exc:
        record.update(reason=type(exc).__name__ + ": " + str(exc), cold_fallback_selected=False,
                      immutable_bad_key=(cache_hit == "true" and matched_key == key))
        try:
            if created:
                rollback_created(created)
            check_feed_state(sdk_root, feed_before, restore_mtime=True)
            clear_quarantine(capsule_dir)
        except (ContractError, OSError, ValueError, KeyError, TypeError) as cleanup:
            record.update(cleanup_error=type(cleanup).__name__ + ": " + str(cleanup),
                          ended_ns=time.time_ns())
            write_json(evidence / "restore.json", record)
            raise ContractError("cache cleanup uncertain; refusing cold continuation") from cleanup
        record["cold_fallback_selected"] = mode == "auto"
        if mode == "warm":
            record["ended_ns"] = time.time_ns()
            write_json(evidence / "restore.json", record)
            raise ContractError("dedicated warm validation requires an exact valid capsule: " + str(exc)) from exc
    record["ended_ns"] = time.time_ns()
    write_json(evidence / "restore.json", record)
    outputs(github_output, origin=record["origin"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    reference = commands.add_parser("reference")
    for name in ("repository", "run", "attempt", "head", "checkout", "evidence"):
        reference.add_argument("--" + name, required=True)
    source = commands.add_parser("source")
    for name in ("checkout", "archive", "source", "archive-sha256", "lock", "evidence"):
        source.add_argument("--" + name, required=True)
    for name in ("inputs", "restore", "capture", "probe", "snapshot"):
        sub = commands.add_parser(name)
        sub.add_argument("--sdk-root", required=True, type=Path)
        sub.add_argument("--evidence", required=True, type=Path)
        if name in ("inputs", "restore", "snapshot"):
            sub.add_argument("--github-output", required=True, type=Path)
        if name in ("restore", "snapshot"):
            sub.add_argument("--capsule-dir", required=True, type=Path)
        if name == "probe":
            sub.add_argument("--origin", required=True, choices=("cold", "cache"))
        if name == "restore":
            for option in ("mode", "cache-hit", "matched-key", "key"):
                sub.add_argument("--" + option, required=True)
    args = parser.parse_args()
    if args.operation == "reference":
        require(args.repository == REPOSITORY, "reference repository mismatch")
        result = verify_reference(args.repository, int(args.run), int(args.attempt), args.head, Path(args.checkout))
        write_json(Path(args.evidence) / "reference.json", result)
    elif args.operation == "source":
        result = verify_source(Path(args.checkout), Path(args.archive), args.source, args.archive_sha256, Path(args.lock))
        write_json(Path(args.evidence) / "source-identity.json", result)
    else:
        require(args.sdk_root.is_absolute() and args.sdk_root.resolve() == args.sdk_root and
                not args.sdk_root.is_symlink(), "SDK root identity")
        args.evidence.mkdir(parents=True, exist_ok=True)
        if args.operation == "inputs":
            inputs(args.sdk_root, args.evidence, args.github_output)
        elif args.operation == "capture":
            capture(args.sdk_root, args.evidence)
        elif args.operation == "probe":
            probe(args.sdk_root, args.evidence, args.origin)
        elif args.operation == "snapshot":
            require(args.capsule_dir == args.sdk_root.parent / "sdk-host-capsule", "dedicated capsule location")
            snapshot(args.sdk_root, args.evidence, args.capsule_dir, args.github_output)
        else:
            restore(args.sdk_root, args.evidence, args.capsule_dir, args.mode, args.cache_hit,
                    args.matched_key, args.key, args.github_output)


if __name__ == "__main__":
    try:
        main()
    except (ContractError, OSError, ValueError, KeyError, TypeError, tarfile.TarError) as error:
        print("SDK cache contract failed: " + str(error), file=sys.stderr)
        sys.exit(1)
