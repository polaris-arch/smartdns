#!/usr/bin/env python3
"""Bounded, loopback-only comparative SmartDNS measurements (Python stdlib).

Run only in the release-validation container with --network none:
  python3 .github/scripts/benchmark-native-offline.py \
    --baseline /baseline/smartdns --candidate /candidate/smartdns \
    --output-dir ci-results/benchmark --tls-cert /tmp/localhost.crt \
    --tls-key /tmp/localhost.key

The wrapper must build upstream dfc9ef4bd947891178924c06070fbccc3ea370ba
and the candidate with identical compiler, dependencies, and optimization flags.
The executable hashes recorded here identify inputs, not their source provenance.
This does not build binaries, query providers, or download anything.

Inspired by test/cases/test-perf.cc and test/cases/test-same-pending-query.cc:
one local upstream, no speed checks, controlled answers, and delayed duplicate
requests. This is a bounded measurement driver, not a replacement test framework.

Common cases use byte-identical normalized configuration and request schedules:
100 cold serial ANY queries followed by the same 100 names, and fresh-process
100-duplicate / 100-unique bursts with cache-size 0. Cold/repeated names get an A
answer. Repeated-name sends are measured, not assumed to be cache hits. Separate
candidate-only aggregate cases return REFUSED to ANY and A/TXT to typed fallback.
Their cold/repeated phases keep at most eight queries in flight, matching the
candidate's per-source operation capacity. This bounds warm-up duration without
changing per-query deadlines or hiding slow completion in latency samples.
The healthy, unrestricted common bursts require 100 successful answers.
Candidate-only aggregate admission limits may reject burst requests.
All-response and successful-response latency distributions are reported
separately, alongside every response code and timeout; fast rejection is not
a speedup.

The HTTP/1.1 TLS fixture returns 429 with Retry-After: 1 throughout a fixed
50-query, 10-query/second phase, then switches to successful DNS replies.
After 1.2 seconds, a 20-query recovery phase runs on the SAME resolver process.
Baseline recovery is an observation; candidate recovery must succeed.
This does not cover HTTP/2, HTTP/3, real
providers, throughput saturation, network loss, or long-term memory growth.

Latency includes Python/OS scheduling and loopback transport. Percentiles use
nearest rank, without interpolation. CPU comes from Linux /proc; VmHWM is the
process lifetime resident high-water mark through the end of the phase, not
allocation accounting. Warm/cold phases share one process. Fixture-observed DNS
messages are "upstream sends"; TCP retransmissions and unsent internal attempts
are not observable here. Shared sends cannot be attributed to individual
duplicate clients; the report gives sends/submitted-query and per-name totals.
Logs are counted after orderly shutdown; startup-prefix and remaining counts
use a sampled byte boundary, since asynchronous logging can flush late. No
performance pass/fail thresholds
or statistical significance claims are made. Repeats, CPU pinning, and timing
noise analysis remain the release reviewer’s responsibility.

--self-test checks source-level wire parsing, validation, workload, percentiles,
and accounting without sockets, subprocesses, or SmartDNS execution.
"""

from __future__ import annotations

import argparse
import collections
import contextlib
import hashlib
import heapq
import json
import math
import os
from pathlib import Path
import select
import signal
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import unittest
from unittest import mock


BASELINE_REVISION = "dfc9ef4bd947891178924c06070fbccc3ea370ba"
QUERY_COUNT = 100
QUERY_TIMEOUT = 4.0
AGGREGATE_INFLIGHT = 8
UPSTREAM_LIMIT = 4000
GLOBAL_TIMEOUT = 180
LOOPBACK = "127.0.0.1"
ANY, A, TXT = 255, 1, 16
ADDRESS = bytes((192, 0, 2, 1))
TEXT = b"offline-benchmark"
TYPE_NAMES = {A: "A", TXT: "TXT", ANY: "ANY"}
COMMON_TEMPLATE = """\
bind 127.0.0.1:{resolver_port}
bind-tcp 127.0.0.1:{resolver_port}
{upstream}
cache-size {cache_size}
restart-on-crash no
cache-persist no
prefetch-domain no
serve-expired no
resolv-hostname no
local-ptr-enable no
speed-check-mode none
dualstack-ip-selection no
log-level warn
log-file {log_file}
log-size 16M
log-num 1
log-color no
log-console no
log-syslog no
audit-enable no
"""
AGGREGATE_CONFIG = """\
any-response-mode aggregate
any-aggregate-types A,TXT
any-aggregate-concurrency 2
any-aggregate-max-attempts 3
any-aggregate-timeout-ms 950
any-aggregate-partial no
"""


class InvalidMeasurement(RuntimeError):
    """Incomplete or invalid experiment, rather than a performance regression."""


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for part in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(part)
    return digest.hexdigest()


def encode_name(name):
    parts = name.rstrip(".").split(".")
    if not parts or any(not part or len(part.encode("ascii")) > 63 for part in parts):
        raise ValueError("invalid DNS name")
    wire = b"".join(bytes((len(part),)) + part.encode("ascii") for part in parts) + b"\0"
    if len(wire) > 255:
        raise ValueError("DNS name too long")
    return wire


def read_name(wire, offset):
    labels, visited, end = [], set(), None
    for _ in range(128):
        if offset in visited or offset >= len(wire):
            raise ValueError("truncated or cyclic DNS name")
        visited.add(offset)
        length = wire[offset]
        offset += 1
        if length & 0xC0 == 0xC0:
            if offset >= len(wire):
                raise ValueError("truncated name pointer")
            target = ((length & 0x3F) << 8) | wire[offset]
            if target < 12 or target >= offset - 1:
                raise ValueError("invalid name pointer")
            if end is None:
                end = offset + 1
            offset = target
        elif length & 0xC0:
            raise ValueError("unsupported DNS label")
        elif length == 0:
            return ".".join(labels).lower(), offset if end is None else end
        else:
            if offset + length > len(wire):
                raise ValueError("truncated DNS label")
            labels.append(wire[offset:offset + length].decode("ascii"))
            offset += length
    raise ValueError("DNS name traversal limit")


def question(wire):
    if len(wire) < 12:
        raise ValueError("short DNS header")
    ident, flags, qd, an, ns, ar = struct.unpack_from("!6H", wire)
    if qd != 1 or flags & 0x7800:
        raise ValueError("expected exactly one standard query question")
    name, offset = read_name(wire, 12)
    if offset + 4 > len(wire):
        raise ValueError("truncated question")
    qtype, qclass = struct.unpack_from("!HH", wire, offset)
    if qclass != 1:
        raise ValueError("expected IN class")
    return ident, flags, name, qtype, offset + 4, (an, ns, ar)


def make_query(name, ident, qtype=ANY):
    return struct.pack("!6H", ident, 0x0100, 1, 0, 0, 0) + encode_name(name) + struct.pack("!HH", qtype, 1)


def make_answer(query, aggregate=False):
    ident, flags, name, qtype, _, _ = question(query)
    if flags & 0x8000 or qtype not in TYPE_NAMES:
        raise ValueError("unexpected fixture request")
    rcode = 5 if aggregate and qtype == ANY else 0
    answers = []
    if not rcode:
        if qtype in (ANY, A):
            answers.append((A, ADDRESS))
        elif qtype == TXT:
            answers.append((TXT, bytes((len(TEXT),)) + TEXT))
    wire = struct.pack("!6H", ident, 0x8180 | rcode, 1, len(answers), 0, 0)
    wire += encode_name(name) + struct.pack("!HH", qtype, 1)
    for record_type, data in answers:
        wire += b"\xc0\x0c" + struct.pack("!HHIH", record_type, 1, 60, len(data)) + data
    return wire


def validate_response(wire, name, ident, aggregate=False, allowed_rcodes=(0,)):
    actual_id, flags, actual_name, qtype, offset, counts = question(wire)
    if actual_id != ident or actual_name != name or qtype != ANY:
        raise ValueError("response question/ID differs from request")
    if not flags & 0x8000 or flags & 0x0200:
        raise ValueError("response QR/TC flags incorrect")
    rcode = flags & 15
    if rcode not in allowed_rcodes:
        raise ValueError("unexpected response code %d" % rcode)
    records = []
    for section, count in enumerate(counts):
        for _ in range(count):
            owner, offset = read_name(wire, offset)
            if offset + 10 > len(wire):
                raise ValueError("truncated resource-record header")
            kind, klass, ttl, size = struct.unpack_from("!HHIH", wire, offset)
            offset += 10
            if offset + size > len(wire):
                raise ValueError("truncated resource-record data")
            data = wire[offset:offset + size]
            offset += size
            if section == 0:
                if owner != name or klass != 1 or not ttl:
                    raise ValueError("invalid answer owner, class, or TTL")
                records.append((kind, data))
    if offset != len(wire):
        raise ValueError("trailing DNS data")
    expected = [(A, ADDRESS)]
    if aggregate:
        expected.append((TXT, bytes((len(TEXT),)) + TEXT))
    if rcode == 0 and sorted(records) != sorted(expected):
        raise ValueError("NOERROR response has incorrect answer data")
    if rcode != 0 and records:
        raise ValueError("error response unexpectedly has answers")
    return rcode


def percentile(values, percent):
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * percent / 100) - 1)]


def latency_summary(values):
    return {"samples": len(values), "p50_ms": percentile(values, 50),
            "p95_ms": percentile(values, 95)}


def names(kind):
    if kind == "duplicate":
        return ["duplicate.benchmark.test"] * QUERY_COUNT
    return ["%s-%03d.benchmark.test" % (kind, index) for index in range(QUERY_COUNT)]


def expected_case_names():
    dns_cases = ("cold_any", "repeated_any", "duplicate_100", "unique_100")
    result = ["common/%s/%s" % (label, case) for label in ("baseline", "candidate")
              for case in dns_cases + ("sustained_429", "recovery_after_429")]
    result += ["candidate_only_aggregate/candidate/" + case for case in dns_cases]
    return sorted(result)


def proc_metrics(pid):
    children = Path("/proc/%d/task/%d/children" % (pid, pid)).read_text().strip()
    if children:
        raise InvalidMeasurement("resolver PID has child processes; refusing monitor-parent resource measurements")
    # Linux stat comm can contain spaces or parentheses: split after its last ')'.
    stat = Path("/proc/%d/stat" % pid).read_text()
    fields = stat[stat.rfind(")") + 2:].split()
    ticks = os.sysconf("SC_CLK_TCK")
    status = Path("/proc/%d/status" % pid).read_text()
    values = {}
    for line in status.splitlines():
        if line.startswith(("VmHWM:", "VmRSS:")):
            key, value, unit = line.split()
            if unit != "kB":
                raise InvalidMeasurement("unexpected /proc RSS unit")
            values[key.rstrip(":")] = int(value)
    if "VmHWM" not in values:
        raise InvalidMeasurement("missing process high-water RSS")
    return {"user_cpu_seconds": int(fields[11]) / ticks,
            "system_cpu_seconds": int(fields[12]) / ticks,
            "peak_rss_kib": values["VmHWM"], "current_rss_kib": values["VmRSS"]}


def resolver_environment(source):
    # The environment can activate monitoring BEFORE configuration is parsed.
    # Popen's child is never PID 1; -R is not supplied; foreground -f and the
    # explicit restart-on-crash no config disable the remaining monitor paths.
    result = dict(source)
    result.pop("SMARTDNS_RESTART_ON_CRASH", None)
    return result


class Fixture:
    """One bounded UDP reactor or bounded HTTP/1.1-TLS connection set."""

    def __init__(self, aggregate=False, delay=0.0, cert=None, key=None):
        self.aggregate, self.delay = aggregate, delay
        self.is_tls = cert is not None
        self.mode = "ok"
        self.transitions = []
        self.lock = threading.Lock()
        self.events, self.errors, self.connections = [], [], []
        self.stop_event = threading.Event()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM if self.is_tls else socket.SOCK_DGRAM)
        self.sock.bind((LOOPBACK, 0))
        self.port = self.sock.getsockname()[1]
        self.sock.settimeout(0.05)
        self.workers = []
        if self.is_tls:
            self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.context.load_cert_chain(str(cert), str(key))
            self.context.set_alpn_protocols(["http/1.1"])
            self.sock.listen(16)
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def set_mode(self, mode):
        with self.lock:
            self.mode = mode
            self.transitions.append({"mode": mode, "time_ns": time.monotonic_ns()})

    def snapshot(self):
        with self.lock:
            if self.errors:
                raise InvalidMeasurement("upstream fixture: " + "; ".join(self.errors))
            return list(self.events)

    def _record(self, wire):
        ident, flags, name, qtype, _, _ = question(wire)
        if flags & 0x8000 or qtype not in TYPE_NAMES or not name.endswith(".benchmark.test"):
            raise ValueError("unexpected upstream question")
        with self.lock:
            if len(self.events) >= UPSTREAM_LIMIT:
                raise ValueError("upstream safety request limit exceeded")
            mode = self.mode
            self.events.append({"time_ns": time.monotonic_ns(), "name": name,
                                "qtype": qtype, "id": ident,
                                "http_status": 429 if mode == "429" else 200 if self.is_tls else None})
        return mode

    def _run(self):
        try:
            if self.is_tls:
                self._tls_accept()
            else:
                self._udp()
        except Exception as exc:
            if not self.stop_event.is_set():
                with self.lock:
                    self.errors.append(str(exc))

    def _udp(self):
        pending, sequence = [], 0
        while not self.stop_event.is_set():
            now = time.monotonic()
            while pending and pending[0][0] <= now:
                _, _, wire, address = heapq.heappop(pending)
                self.sock.sendto(wire, address)
            wait = min(0.02, max(0, pending[0][0] - now)) if pending else 0.02
            ready, _, _ = select.select([self.sock], [], [], wait)
            if not ready:
                continue
            query, address = self.sock.recvfrom(4096)
            if address[0] != LOOPBACK:
                raise ValueError("non-loopback fixture client")
            self._record(query)
            sequence += 1
            heapq.heappush(pending, (time.monotonic() + self.delay, sequence,
                                     make_answer(query, self.aggregate), address))

    def _tls_accept(self):
        accepted = 0
        while not self.stop_event.is_set():
            try:
                conn, address = self.sock.accept()
            except socket.timeout:
                continue
            accepted += 1
            if accepted > 256 or address[0] != LOOPBACK:
                conn.close()
                raise ValueError("TLS connection safety limit or non-loopback peer")
            conn.settimeout(0.2)
            # Handshake belongs to the worker so one connection cannot block accepts.
            worker = threading.Thread(target=self._http, args=(conn,), daemon=True)
            self.workers.append(worker)
            worker.start()

    def _http(self, raw):
        conn = raw
        try:
            raw.settimeout(2)
            conn = self.context.wrap_socket(raw, server_side=True)
            conn.settimeout(0.2)
            with self.lock:
                self.connections.append(conn)
            buffer = b""
            while not self.stop_event.is_set():
                try:
                    data = conn.recv(8192)
                except socket.timeout:
                    continue
                if not data:
                    return
                buffer += data
                if len(buffer) > 1024 * 1024:
                    raise ValueError("HTTP input buffer safety limit exceeded")
                while b"\r\n\r\n" in buffer:
                    end = buffer.index(b"\r\n\r\n")
                    if end > 16384:
                        raise ValueError("HTTP header safety limit exceeded")
                    head = buffer[:end].decode("ascii").split("\r\n")
                    if head[0] != "POST /dns-query HTTP/1.1":
                        raise ValueError("unexpected HTTP request line")
                    headers = {}
                    for line in head[1:]:
                        key, value = line.split(":", 1)
                        key = key.strip().lower()
                        if key in headers:
                            raise ValueError("duplicate HTTP header")
                        headers[key] = value.strip()
                    if headers.get("content-type") != "application/dns-message" or "transfer-encoding" in headers:
                        raise ValueError("unexpected HTTP body encoding")
                    size = int(headers["content-length"])
                    if size < 12 or size > 4096:
                        raise ValueError("invalid HTTP DNS body size")
                    body_start = end + 4
                    if len(buffer) < body_start + size:
                        break
                    query = buffer[body_start:body_start + size]
                    buffer = buffer[body_start + size:]
                    mode = self._record(query)
                    if mode == "429":
                        response = (b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 1\r\n"
                                    b"Content-Length: 0\r\nConnection: keep-alive\r\n\r\n")
                    else:
                        body = make_answer(query)
                        response = (b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n"
                                    b"Content-Length: " + str(len(body)).encode("ascii") +
                                    b"\r\nConnection: keep-alive\r\n\r\n" + body)
                    conn.sendall(response)
        except (ConnectionError, ssl.SSLEOFError):
            # A resolver can close a prohibited endpoint or an idle connection.
            pass
        except Exception as exc:
            if not self.stop_event.is_set():
                with self.lock:
                    self.errors.append(str(exc))
        finally:
            conn.close()

    def close(self):
        self.stop_event.set()
        self.thread.join(timeout=1)
        self.sock.close()
        with self.lock:
            connections = list(self.connections)
        for conn in connections:
            with contextlib.suppress(OSError):
                conn.shutdown(socket.SHUT_RDWR)
        for worker in self.workers:
            worker.join(timeout=0.1)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def reserve_resolver_port():
    # Keep UDP reserved while proving TCP can use the same ephemeral port.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.bind((LOOPBACK, 0))
        port = udp.getsockname()[1]
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp:
            tcp.bind((LOOPBACK, port))
        return port


def log_counts(path):
    data = path.read_bytes() if path.exists() else b""
    return count_log_bytes(data)


def count_log_bytes(data):
    return {"bytes": len(data), "lines": len(data.splitlines()),
            "backpressure_lines": data.count(b"upstream backpressure"),
            "http_429_lines": sum(b"429" in line for line in data.splitlines())}


class Resolver:
    def __init__(self, binary, directory, fixture, cache_size, aggregate=False):
        self.directory = directory
        directory.mkdir(parents=True)
        self.port = reserve_resolver_port()
        self.logfile = directory / "smartdns.log"
        upstream = ("server-https https://127.0.0.1:%d/dns-query -no-check-certificate -alpn http/1.1"
                    if fixture.is_tls else "server 127.0.0.1:%d") % fixture.port
        config = COMMON_TEMPLATE.format(resolver_port=self.port, upstream=upstream,
                                        cache_size=cache_size, log_file=self.logfile)
        if aggregate:
            config += AGGREGATE_CONFIG
        self.config = config
        config_path = directory / "smartdns.conf"
        config_path.write_text(config)
        self.console = open(directory / "console.log", "wb")
        try:
            self.process = subprocess.Popen([str(binary), "-f", "-c", str(config_path), "-p", "-"],
                                            cwd=directory, stdout=self.console, stderr=subprocess.STDOUT,
                                            env=resolver_environment(os.environ))
        except BaseException:
            self.console.close()
            raise
        self.final_metrics = None
        self.startup_log_bytes = 0
        self.startup_console_bytes = 0
        self.shutdown_forced = False

    def wait_ready(self):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise InvalidMeasurement("resolver exited during startup: " + str(self.directory))
            try:
                with socket.create_connection((LOOPBACK, self.port), timeout=0.05):
                    self.startup_log_bytes = log_counts(self.logfile)["bytes"]
                    self.startup_console_bytes = log_counts(self.directory / "console.log")["bytes"]
                    return
            except OSError:
                time.sleep(0.02)
        raise InvalidMeasurement("resolver did not listen within startup deadline")

    def close(self):
        try:
            if self.process.poll() is None:
                with contextlib.suppress(OSError, InvalidMeasurement):
                    self.final_metrics = proc_metrics(self.process.pid)
                self.process.terminate()
                try:
                    self.process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self.shutdown_forced = True
                    self.process.kill()
                    self.process.wait(timeout=2)
        finally:
            self.console.close()

    def __enter__(self):
        try:
            self.wait_ready()
        except BaseException:
            self.close()
            raise
        return self

    def __exit__(self, *_):
        self.close()


def upstream_summary(events, submitted):
    by_type = collections.Counter(TYPE_NAMES[e["qtype"]] for e in events)
    by_name = {}
    for event in events:
        counts = by_name.setdefault(event["name"], collections.Counter())
        counts[TYPE_NAMES[event["qtype"]]] += 1
    return {"sends": len(events), "sends_per_submitted_query": len(events) / submitted,
            "by_qtype": dict(by_type), "by_name": {name: dict(counts) for name, counts in sorted(by_name.items())},
            "http_status_counts": dict(collections.Counter(str(e["http_status"]) for e in events if e["http_status"]))}


def summarise(samples, events, extra_responses):
    success = [row["latency_ms"] for row in samples if row["outcome"] == "response" and row["rcode"] == 0]
    response = [row["latency_ms"] for row in samples if row["outcome"] == "response"]
    counts = collections.Counter(row["outcome"] for row in samples)
    rcodes = collections.Counter(str(row["rcode"]) for row in samples if row["outcome"] == "response")
    return {"submitted": len(samples), "accounted": sum(counts.values()),
            "responses": len(response), "successful_responses": len(success),
            "timeouts": counts["timeout"], "invalid_responses": counts["invalid"],
            "extra_or_duplicate_responses": extra_responses, "rcode_counts": dict(rcodes),
            "response_latency": latency_summary(response), "successful_response_latency": latency_summary(success),
            "upstream": upstream_summary(events, len(samples))}


def query_capacity(query_count, serial, max_inflight):
    capacity = 1 if serial else query_count if max_inflight is None else max_inflight
    if not 1 <= capacity <= query_count:
        raise ValueError("invalid in-flight query capacity")
    return capacity


def run_queries(resolver, fixture, query_names, *, serial=False, interval=0.0,
                aggregate=False, allowed_rcodes=(0,), timeout=QUERY_TIMEOUT, max_inflight=None):
    """One UDP client; fixed IDs/names/order; absolute paced or immediate burst."""
    capacity = query_capacity(len(query_names), serial, max_inflight)
    initial_events = len(fixture.snapshot())
    before = proc_metrics(resolver.process.pid)
    start = time.monotonic()
    pending, samples, next_query, extra = {}, [], 0, 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
        sock.connect((LOOPBACK, resolver.port))
        sock.setblocking(False)
        while next_query < len(query_names) or pending:
            if resolver.process.poll() is not None:
                raise InvalidMeasurement("resolver exited while processing queries")
            fixture.snapshot()
            now = time.monotonic()
            while next_query < len(query_names) and len(pending) < capacity:
                if now < start + next_query * interval:
                    break
                ident = 1000 + next_query
                name = query_names[next_query]
                sent = time.monotonic()
                sock.send(make_query(name, ident))
                pending[ident] = {"index": next_query, "id": ident, "name": name,
                                  "sent_seconds": sent - start, "_sent": sent}
                next_query += 1
            now = time.monotonic()
            for ident, row in list(pending.items()):
                if now - row["_sent"] >= timeout:
                    row.update(outcome="timeout", rcode=None, latency_ms=None, deadline_ms=timeout * 1000,
                               reason="No matching DNS response before the fixed client deadline")
                    del row["_sent"]
                    samples.append(row)
                    del pending[ident]
            wait = 0.02
            if next_query < len(query_names) and len(pending) < capacity:
                wait = min(wait, max(0, start + next_query * interval - time.monotonic()))
            ready, _, _ = select.select([sock], [], [], wait)
            if ready:
                while True:
                    try:
                        wire = sock.recv(65535)
                    except BlockingIOError:
                        break
                    received = time.monotonic()
                    ident = struct.unpack_from("!H", wire)[0] if len(wire) >= 2 else -1
                    if ident not in pending:
                        extra += 1
                        continue
                    row = pending.pop(ident)
                    row["latency_ms"] = (received - row.pop("_sent")) * 1000
                    try:
                        row["rcode"] = validate_response(wire, row["name"], ident, aggregate, allowed_rcodes)
                        row["outcome"] = "response"
                    except ValueError as exc:
                        row.update(outcome="invalid", rcode=None, error=str(exc))
                    samples.append(row)
        # Drain a bounded window to detect duplicate callbacks without contaminating
        # the next phase's fixture counters. This is excluded from query latency.
        drain_until = time.monotonic() + 0.05
        while time.monotonic() < drain_until:
            ready, _, _ = select.select([sock], [], [], max(0, drain_until - time.monotonic()))
            if ready:
                sock.recv(65535)
                extra += 1
    elapsed = time.monotonic() - start
    after = proc_metrics(resolver.process.pid)
    events = fixture.snapshot()[initial_events:]
    samples.sort(key=lambda row: row["index"])
    result = summarise(samples, events, extra)
    result.update(expected_submitted=len(query_names), elapsed_seconds=elapsed,
                  client_max_inflight=capacity,
                  session_directory=str(resolver.directory),
                  cpu_seconds={"user": after["user_cpu_seconds"] - before["user_cpu_seconds"],
                               "system": after["system_cpu_seconds"] - before["system_cpu_seconds"]},
                  process_peak_rss_kib=after["peak_rss_kib"], samples=samples, upstream_events=events)
    return result


def check_result(result, *, all_success=False, allow_timeouts=False, minimum_sends=0, maximum_sends=UPSTREAM_LIMIT):
    failures = []
    if result["submitted"] != result["expected_submitted"] or result["accounted"] != result["expected_submitted"]:
        failures.append("query operation count mismatch")
    if result["invalid_responses"] or result["extra_or_duplicate_responses"]:
        failures.append("invalid or duplicate response")
    if not allow_timeouts and result["timeouts"]:
        failures.append("query deadline expired")
    if all_success and result["successful_responses"] != result["submitted"]:
        failures.append("expected successful answers for every query")
    if "samples" in result:
        submitted_names = {sample["name"] for sample in result["samples"]}
        if any(event["name"] not in submitted_names for event in result["upstream_events"]):
            failures.append("upstream work belongs to a different phase")
    if not minimum_sends <= result["upstream"]["sends"] <= maximum_sends:
        failures.append("upstream operation count outside scenario bounds")
    result["validation"] = {"passed": not failures, "failures": failures,
                            "minimum_upstream_sends": minimum_sends, "maximum_upstream_sends": maximum_sends,
                            "requires_all_success": all_success, "permits_timeout_observations": allow_timeouts}
    return result


def check_burst_result(result, aggregate):
    factor = 3 if aggregate else 1
    # Healthy unrestricted passthrough must preserve every successful completion.
    # Only the explicitly bounded aggregate experiment permits admission errors.
    return check_result(result, all_success=not aggregate, minimum_sends=factor,
                        maximum_sends=QUERY_COUNT * factor)


def finish_session(report, resolver, fixture):
    events = fixture.snapshot()
    log = resolver.logfile.read_bytes() if resolver.logfile.exists() else b""
    console = (resolver.directory / "console.log").read_bytes()
    measured_times = {event["time_ns"] for case in report["cases"].values()
                      if case["session_directory"] == str(resolver.directory)
                      for event in case["upstream_events"]}
    unassigned = [event for event in events if event["time_ns"] not in measured_times]
    report["sessions"].append({"directory": str(resolver.directory), "configuration": resolver.config,
                               "process_metrics": resolver.final_metrics, "exit_code": resolver.process.returncode,
                               "shutdown_forced": resolver.shutdown_forced,
                               "log_file_present": resolver.logfile.exists(),
                               "logs": count_log_bytes(log),
                               "console_logs": count_log_bytes(console),
                               "logs_startup_sampled_prefix": count_log_bytes(log[:resolver.startup_log_bytes]),
                               "logs_after_ready_sampled": count_log_bytes(log[resolver.startup_log_bytes:]),
                               "console_startup_sampled_prefix": count_log_bytes(console[:resolver.startup_console_bytes]),
                               "console_after_ready_sampled": count_log_bytes(console[resolver.startup_console_bytes:]),
                               "log_scope_note": "Session totals include startup/shutdown. The readiness byte boundary is sampled; asynchronous flushes can cross it.",
                               "fixture_mode_transitions": list(fixture.transitions),
                               "upstream_events_outside_measured_phases": unassigned,
                               "upstream_total_sends": len(events)})
    if resolver.shutdown_forced:
        raise InvalidMeasurement("resolver required forced shutdown: " + str(resolver.directory))
    if resolver.process.returncode not in (0, -signal.SIGTERM):
        raise InvalidMeasurement("resolver exited abnormally with code %s: %s" %
                                 (resolver.process.returncode, resolver.directory))


def run_dns_cases(report, label, binary, root, aggregate=False):
    scope = "candidate_only_aggregate" if aggregate else "common"
    prefix = "%s/%s" % (scope, label)
    with Fixture(aggregate=aggregate) as fixture:
        resolver = Resolver(binary, root / scope / label / "cold-hot", fixture, 256, aggregate)
        with resolver:
            cold_names = names("cold")
            for phase in ("cold_any", "repeated_any"):
                result = run_queries(resolver, fixture, cold_names, serial=not aggregate, aggregate=aggregate,
                                     max_inflight=AGGREGATE_INFLIGHT if aggregate else None)
                factor = 3 if aggregate else 1
                check_result(result, all_success=True, minimum_sends=QUERY_COUNT * factor if phase == "cold_any" else 0,
                             maximum_sends=QUERY_COUNT * factor)
                result["workload"] = ("cold ANY; 100 fresh names" if phase == "cold_any" else
                                      "hot/repeated ANY; same 100 names after cold phase; cache hits measured, not assumed")
                report["cases"][prefix + "/" + phase] = result
        finish_session(report, resolver, fixture)
    for kind in ("duplicate", "unique"):
        # 25 ms delay permits genuine overlapping work; no per-packet sleep on a
        # single fixture thread that would accidentally serialize unique names.
        with Fixture(aggregate=aggregate, delay=0.025) as fixture:
            resolver = Resolver(binary, root / scope / label / kind, fixture, 0, aggregate)
            with resolver:
                result = run_queries(resolver, fixture, names(kind), aggregate=aggregate, allowed_rcodes=(0, 2))
                check_burst_result(result, aggregate)
                result["admission_note"] = ("One source address submits 100 concurrent requests. "
                                            + ("Aggregate admission failures are recorded separately from successful work."
                                               if aggregate else
                                               "Healthy unrestricted passthrough requires all 100 successful answers; "
                                               "SERVFAIL is retained as a failed completion."))
                result["cache_note"] = ("Fresh process and cold names, cache-size 0 disables completed-result caching "
                                        "in both variants. In-flight coalescing may reduce observed upstream sends.")
                report["cases"][prefix + "/" + kind + "_100"] = result
            finish_session(report, resolver, fixture)


def run_backpressure(report, label, binary, root, cert, key):
    prefix = "common/%s/" % label
    with Fixture(cert=cert, key=key) as fixture:
        fixture.set_mode("429")
        resolver = Resolver(binary, root / "common" / label / "http429", fixture, 0)
        with resolver:
            limited = ["limited-%03d.benchmark.test" % index for index in range(50)]
            result = run_queries(resolver, fixture, limited, interval=0.1, allowed_rcodes=(2,), timeout=4)
            check_result(result, allow_timeouts=True, minimum_sends=1, maximum_sends=50 * 4)
            result["phase"] = "429 held for the entire submission and response-deadline interval"
            report["cases"][prefix + "sustained_429"] = result
            fixture.set_mode("ok")
            time.sleep(1.2)  # Shared Retry-After: 1 expiry, not a performance threshold.
            recovery = ["recovery-%03d.benchmark.test" % index for index in range(20)]
            result = run_queries(resolver, fixture, recovery, interval=0.1, allowed_rcodes=(0, 2), timeout=4)
            check_result(result, all_success=label == "candidate", allow_timeouts=label == "baseline",
                         minimum_sends=20 if label == "candidate" else 0, maximum_sends=20 * 4)
            result["recovery_succeeded_for_all_queries"] = result["successful_responses"] == 20
            result["phase"] = "same process; fixture healthy; 1.2 seconds after the fixture became healthy"
            report["cases"][prefix + "recovery_after_429"] = result
        finish_session(report, resolver, fixture)


def write_report(root, report):
    path = root / "results.json"
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    lines = [
        "Offline SmartDNS comparative benchmark",
        "",
        "No performance thresholds. Timings are observations from this host.",
        "Compare successful work and errors before comparing latency.",
        "p50/p95 use successful responses only in the summary below; all responses",
        "and complete request/fixture samples are retained in results.json.",
        "Peak RSS is process lifetime VmHWM; cold/repeated share a process.",
        "",
        "case | success/submitted | timeout | success p50 ms | success p95 ms | sends/query | peak RSS KiB",
    ]
    for name, case in sorted(report["cases"].items()):
        latency = case["successful_response_latency"]
        fmt = lambda value: "n/a" if value is None else "%.3f" % value
        lines.append("%s | %d/%d | %d | %s | %s | %.3f | %d" %
                     (name, case["successful_responses"], case["submitted"], case["timeouts"],
                      fmt(latency["p50_ms"]), fmt(latency["p95_ms"]),
                      case["upstream"]["sends_per_submitted_query"], case["process_peak_rss_kib"]))
    lines.extend(["", "Experiment validation: " + report["status"]])
    if report.get("error"):
        lines.append("Error: " + report["error"])
    (root / "summary.txt").write_text("\n".join(lines) + "\n")


class SourceTests(unittest.TestCase):
    def test_question_and_minimal_any(self):
        query = make_query("cold-000.benchmark.test", 1234)
        wire = make_answer(query)
        self.assertEqual(validate_response(wire, "cold-000.benchmark.test", 1234), 0)
        self.assertEqual(question(query)[2:4], ("cold-000.benchmark.test", ANY))

    def test_refused_fixture(self):
        query = make_query("cold-000.benchmark.test", 1234)
        self.assertEqual(validate_response(make_answer(query, True), "cold-000.benchmark.test", 1234,
                                          allowed_rcodes=(5,)), 5)

    def test_typed_fixture_answers(self):
        for kind, data in ((A, ADDRESS), (TXT, bytes((len(TEXT),)) + TEXT)):
            wire = make_answer(make_query("typed.benchmark.test", 55, kind), True)
            _, _, _, actual, offset, counts = question(wire)
            self.assertEqual((actual, counts), (kind, (1, 0, 0)))
            _, offset = read_name(wire, offset)
            self.assertEqual(wire[offset + 10:], data)

    def test_malformed_and_wrong_identity(self):
        query = make_query("cold-000.benchmark.test", 1234)
        wire = make_answer(query)
        for broken in (wire[:10], wire[:-1], wire + b"x", wire[:12] + b"\xc0\x0c"):
            with self.assertRaises(ValueError):
                validate_response(broken, "cold-000.benchmark.test", 1234)
        with self.assertRaises(ValueError):
            validate_response(wire, "wrong.benchmark.test", 1234)
        with self.assertRaises(ValueError):
            validate_response(wire, "cold-000.benchmark.test", 1235)
        with self.assertRaises(ValueError):
            validate_response(wire[:-4] + b"\x01\x02\x03\x04", "cold-000.benchmark.test", 1234)

    def test_percentile(self):
        self.assertIsNone(percentile([], 95))
        self.assertEqual(percentile(list(range(1, 101)), 50), 50)
        self.assertEqual(percentile(list(range(1, 101)), 95), 95)
        self.assertEqual(percentile([7], 95), 7)

    def test_workloads(self):
        self.assertEqual(len(names("duplicate")), 100)
        self.assertEqual(len(set(names("duplicate"))), 1)
        self.assertEqual(len(set(names("unique"))), 100)
        self.assertEqual(names("cold"), names("cold"))
        self.assertEqual(len(expected_case_names()), 16)
        self.assertEqual(len(set(expected_case_names())), 16)
        self.assertEqual(query_capacity(100, True, None), 1)
        self.assertEqual(query_capacity(100, False, None), 100)
        self.assertEqual(query_capacity(100, False, AGGREGATE_INFLIGHT), 8)
        with self.assertRaises(ValueError):
            query_capacity(100, False, 0)

    def test_bounded_inflight_with_slow_responses_uses_virtual_time_only(self):
        # Exercise the actual client loop without sockets, processes, or sleeps.
        # A one-second completion cost must remain visible in every latency
        # sample, while 100 queries at capacity eight finish in thirteen waves.
        clock = [0.0]

        class VirtualSocket:
            def __init__(self):
                self.pending = []
                self.peak_pending = 0

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return None

            def setsockopt(self, *_):
                pass

            def connect(self, *_):
                pass

            def setblocking(self, *_):
                pass

            def send(self, wire):
                self.pending.append((clock[0] + 1.0, make_answer(wire)))
                self.peak_pending = max(self.peak_pending, len(self.pending))
                return len(wire)

            def recv(self, _size):
                if not self.pending or self.pending[0][0] > clock[0]:
                    raise BlockingIOError
                return self.pending.pop(0)[1]

        sock = VirtualSocket()

        def virtual_select(readers, _writers, _errors, wait):
            next_ready = sock.pending[0][0] if sock.pending else math.inf
            clock[0] = min(clock[0] + wait, next_ready)
            return (readers, [], []) if next_ready <= clock[0] else ([], [], [])

        resolver, fixture = mock.Mock(), mock.Mock()
        resolver.process.poll.return_value = None
        resolver.port, resolver.directory = 12345, Path("/virtual/source-test")
        fixture.snapshot.return_value = []
        metrics = {"user_cpu_seconds": 0, "system_cpu_seconds": 0, "peak_rss_kib": 1}
        with mock.patch.object(socket, "socket", return_value=sock), \
                mock.patch.object(select, "select", side_effect=virtual_select), \
                mock.patch.object(time, "monotonic", side_effect=lambda: clock[0]), \
                mock.patch.dict(run_queries.__globals__, proc_metrics=lambda _pid: metrics):
            result = run_queries(resolver, fixture, names("cold"), max_inflight=AGGREGATE_INFLIGHT)
        self.assertEqual(result["successful_responses"], 100)
        self.assertEqual(result["timeouts"], 0)
        self.assertEqual(sock.peak_pending, 8)
        self.assertEqual(result["client_max_inflight"], 8)
        self.assertAlmostEqual(result["elapsed_seconds"], 13.05)
        self.assertAlmostEqual(result["successful_response_latency"]["p50_ms"], 1000.0)
        self.assertAlmostEqual(result["successful_response_latency"]["p95_ms"], 1000.0)

    def test_accounting_does_not_reward_fast_failure(self):
        samples = [{"outcome": "response", "rcode": 0, "latency_ms": 20.0},
                   {"outcome": "response", "rcode": 2, "latency_ms": 0.1},
                   {"outcome": "timeout", "rcode": None, "latency_ms": None}]
        events = [{"qtype": ANY, "name": "a.benchmark.test", "http_status": None}]
        result = summarise(samples, events, 0)
        result["expected_submitted"] = 3
        check_result(result, all_success=True)
        self.assertEqual(result["successful_response_latency"]["p50_ms"], 20)
        self.assertEqual(result["response_latency"]["p50_ms"], 0.1)
        self.assertEqual(result["upstream"]["sends_per_submitted_query"], 1 / 3)
        self.assertEqual(result["responses"] + result["timeouts"], 3)
        self.assertFalse(result["validation"]["passed"])

    def test_common_bursts_require_all_success_aggregate_keeps_capacity_observations(self):
        for aggregate in (False, True):
            for successes in (32, 8, 100):
                with self.subTest(aggregate=aggregate, successful_responses=successes):
                    samples = [{"outcome": "response", "rcode": 0 if index < successes else 2,
                                "latency_ms": 20.0 if index < successes else 0.1}
                               for index in range(100)]
                    events = [{"qtype": kind, "name": "burst.benchmark.test", "http_status": None}
                              for kind in ((ANY, A, TXT) if aggregate else (ANY,))]
                    result = summarise(samples, events, 0)
                    result["expected_submitted"] = 100
                    check_burst_result(result, aggregate)
                    self.assertEqual(result["responses"], 100)
                    self.assertEqual(result["successful_responses"], successes)
                    self.assertEqual(result["validation"]["requires_all_success"], not aggregate)
                    self.assertEqual(result["validation"]["passed"], aggregate or successes == 100)
                    if not aggregate and successes < 100:
                        self.assertIn("expected successful answers for every query",
                                      result["validation"]["failures"])

    def test_operation_counts_reject_incomplete_or_duplicate(self):
        samples = [{"outcome": "response", "rcode": 0, "latency_ms": 1}]
        result = summarise(samples, [], 1)
        result["expected_submitted"] = 2
        check_result(result)
        self.assertIn("query operation count mismatch", result["validation"]["failures"])
        self.assertIn("invalid or duplicate response", result["validation"]["failures"])

    def test_timeout_observation_is_not_a_success(self):
        result = summarise([{"outcome": "timeout", "rcode": None, "latency_ms": None}], [], 0)
        result["expected_submitted"] = 1
        check_result(result, allow_timeouts=True)
        self.assertTrue(result["validation"]["passed"])
        self.assertEqual(result["successful_responses"], 0)
        self.assertIsNone(result["successful_response_latency"]["p50_ms"])
        check_result(result, allow_timeouts=True, all_success=True)
        self.assertFalse(result["validation"]["passed"])

    def test_log_counts(self):
        counts = count_log_bytes(b"startup\nupstream backpressure status=429\n")
        self.assertEqual(counts["lines"], 2)
        self.assertEqual(counts["backpressure_lines"], 1)
        self.assertEqual(counts["http_429_lines"], 1)
        # tlog disables file output when logcount is zero; keep warning evidence.
        self.assertIn("log-num 1\n", COMMON_TEMPLATE)

    def test_monitor_environment_is_disabled_without_mutating_parent(self):
        source = {"SMARTDNS_RESTART_ON_CRASH": "1", "PATH": "/usr/bin"}
        self.assertEqual(resolver_environment(source), {"PATH": "/usr/bin"})
        self.assertEqual(source["SMARTDNS_RESTART_ON_CRASH"], "1")
        self.assertIn("restart-on-crash no\n", COMMON_TEMPLATE)

    def test_cross_phase_work_is_not_silently_attributed(self):
        samples = [{"outcome": "response", "rcode": 0, "latency_ms": 1, "name": "current.benchmark.test"}]
        events = [{"qtype": ANY, "name": "previous.benchmark.test", "http_status": None}]
        result = summarise(samples, events, 0)
        result.update(expected_submitted=1, samples=samples, upstream_events=events)
        check_result(result)
        self.assertIn("upstream work belongs to a different phase", result["validation"]["failures"])


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    for option in ("baseline", "candidate", "output-dir", "tls-cert", "tls-key"):
        parser.add_argument("--" + option, type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(SourceTests)
        return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1
    required = ("baseline", "candidate", "output_dir", "tls_cert", "tls_key")
    if any(getattr(args, option) is None for option in required):
        parser.error("--baseline, --candidate, --output-dir, --tls-cert and --tls-key are required")
    interfaces = {name for _, name in socket.if_nameindex()}
    if interfaces != {"lo"}:
        parser.error("requires an isolated loopback-only network namespace; got " + repr(sorted(interfaces)))
    for option in ("baseline", "candidate", "tls_cert", "tls_key"):
        path = getattr(args, option).resolve(strict=True)
        if not path.is_file():
            parser.error("not a regular file: " + str(path))
        setattr(args, option, path)
    for binary in (args.baseline, args.candidate):
        if not os.access(binary, os.X_OK):
            parser.error("binary is not executable: " + str(binary))
    root = args.output_dir.resolve()
    if any(char.isspace() or char in "#'\"" for char in str(root)):
        parser.error("--output-dir must not contain whitespace or configuration quote/comment characters")
    # Never overwrite or mix measurements from separate invocations.
    root.mkdir(parents=True, exist_ok=False)
    report = {"schema_version": 1, "status": "incomplete", "cases": {}, "sessions": [],
              "expected_cases": expected_case_names(), "expected_submitted_queries": 1340,
              "expected_baseline_source_revision": BASELINE_REVISION,
              "source_provenance": "Caller must retain exact source archives/build manifest; binary hash alone is insufficient.",
              "binaries": {label: {"path": str(binary), "sha256": sha256(binary)}
                           for label, binary in (("baseline", args.baseline), ("candidate", args.candidate))},
              "common_config_template": COMMON_TEMPLATE, "candidate_only_aggregate_config": AGGREGATE_CONFIG,
              "child_environment_adjustments": ["SMARTDNS_RESTART_ON_CRASH removed"],
              "host": {"uname": list(os.uname()), "python": sys.version, "network_interfaces": sorted(interfaces)},
              "limits": {"global_timeout_seconds": GLOBAL_TIMEOUT, "per_query_timeout_seconds": QUERY_TIMEOUT,
                         "upstream_messages_per_fixture": UPSTREAM_LIMIT},
              "measurement_notes": __doc__}

    def deadline_handler(_signum, _frame):
        raise InvalidMeasurement("global experiment safety deadline exceeded")

    previous = signal.signal(signal.SIGALRM, deadline_handler)
    signal.alarm(GLOBAL_TIMEOUT)
    try:
        for label, binary in (("baseline", args.baseline), ("candidate", args.candidate)):
            run_dns_cases(report, label, binary, root)
            write_report(root, report)
            run_backpressure(report, label, binary, root, args.tls_cert, args.tls_key)
            write_report(root, report)
        run_dns_cases(report, "candidate", args.candidate, root, aggregate=True)
        if sorted(report["cases"]) != report["expected_cases"]:
            raise InvalidMeasurement("missing or extra benchmark case")
        if sum(case["submitted"] for case in report["cases"].values()) != report["expected_submitted_queries"]:
            raise InvalidMeasurement("total submitted operation count mismatch")
        report["status"] = "passed" if all(case["validation"]["passed"] for case in report["cases"].values()) else "failed"
    except Exception as exc:
        report["status"] = "failed"
        report["error"] = "%s: %s" % (type(exc).__name__, exc)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)
        write_report(root, report)
    print((root / "summary.txt").read_text())
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
