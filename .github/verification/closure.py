#!/usr/bin/env python3
"""Temporary qualification controls; never included in the upstream topics."""
import argparse
import fnmatch
import json
from pathlib import Path
import re
import subprocess
import xml.etree.ElementTree as ET


def keep_tests(text, names):
    for match in reversed(list(re.finditer(r'TEST_F\([^,]+,\s*(\w+)\)\s*\{', text))):
        if match[1] in names:
            continue
        end, depth = match.end(), 1
        while depth:
            depth += (text[end] == '{') - (text[end] == '}')
            end += 1
        text = text[:match.start()] + text[end:]
    return text


def baseline(pr, candidate, target):
    for path in candidate['paths']:
        if not path.startswith('test/'):
            continue
        if pr == 2490 and path in ('test/Makefile', 'test/cases/test-hpack-state.cc'):
            continue
        if pr == 2494 and path == 'test/cases/test-http3-control.cc':
            continue
        destination = target / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(subprocess.check_output(['git', 'show', candidate['sha'] + ':' + path]))
    if pr == 2493:
        path = target / 'test/cases/test-http2-cancellation.cc'
        source = keep_tests(path.read_text(), {
            'AbortDiscardsUnscheduledBodyAndReleasesCapacity', 'NormalCloseStillFlushesAfterWindowUpdate'})
        source = source.replace('#include "dns_client/conn_stream.h"', '#include "dns_client/conn_stream.h"\n'
            'static void http2_stream_abort(http2_stream *s) { http2_stream_close(s); }')
        path.write_text(source)
    if pr == 2494:
        path = target / 'test/cases/test-quic-lifecycle.cc'
        source = keep_tests(path.read_text(), {'LocalControlStartsWithSettingsAndRemainsOpen',
            'ResetIsProcessedWithoutKernelReadability', 'HardReadErrorRetiresTheStream',
            'CompleteDoqPayloadWaitsForNormalFin', 'StopSendingAloneRetiresTheWriteSide'})
        path.write_text('#define UPSTREAM_BASELINE\n' + source)
        header = 'src/dns_client/client_http3_control.h'
        (target / header).write_bytes(subprocess.check_output(['git', 'show', candidate['sha'] + ':' + header]))
    if pr == 2489:
        # Add observations around the OLD transport operation, preserving its
        # original map publication, send state, references and error cleanup.
        path = target / 'src/fast_ping/fast_ping.c'
        source = path.read_text()
        start = source.index('static int _fast_ping_sendping(struct ping_host_struct *ping_host)')
        end = source.index('\nstatic void _fast_ping_print_result', start)
        old = source[start:end]
        old = old.replace('\n\tgettimeofday', '\n#ifdef TEST\n'
            '\tif (fast_ping_test_send_hook && fast_ping_test_send_hook(ping_host, 1)) {\n'
            '\t\tping_host->error = errno; return -1;\n\t}\n#endif\n\tgettimeofday', 1)
        old = old.replace('\n\t\t_fast_ping_fake_put(fake);', '\n#ifdef TEST\n'
            '\t\tif (fast_ping_test_send_hook) fast_ping_test_send_hook(ping_host, 0);\n#endif\n'
            '\t\t_fast_ping_fake_put(fake);', 1)
        old = old.replace('\n\tping_host->send = 1;', '\n#ifdef TEST\n'
            '\tif (fast_ping_test_send_hook) fast_ping_test_send_hook(ping_host, 0);\n#endif\n'
            '\tping_host->send = 1;', 1)
        declaration = '#ifdef TEST\nextern int fast_ping_test_send_hook(struct ping_host_struct *, int) __attribute__((weak));\n#endif\n'
        path.write_text(source[:start] + declaration + old + source[end:])
    subprocess.run(['git', '-C', str(target), 'diff', '--check'], check=True)


def xml_check(path, candidate, negative=False):
    root = ET.parse(path).getroot()
    cases = {c.attrib['classname'] + '.' + c.attrib['name']: c for c in root.iter('testcase')}
    assert cases and int(root.attrib.get('errors', 0)) == 0, root.attrib
    if negative:
        required = candidate['required_failures']
        assert all(name in cases and cases[name].find('failure') is not None for name in required), required
    else:
        assert int(root.attrib['failures']) == 0, root.attrib
        assert set(candidate['required_tests']) <= cases.keys(), set(candidate['required_tests']) - cases.keys()
        assert all(cases[name].find('skipped') is None for name in candidate['required_tests'])
    print(json.dumps({'cases': len(cases), 'failures': root.attrib['failures'], 'negative': negative}))


def ui_inverse(path):
    text = path.read_text()
    old = 'self.request_dropped.fetch_add(count, Ordering::Relaxed);'
    assert text.count(old) == 1
    text = text.replace(old, 'self.request_dropped.fetch_and(count, Ordering::Relaxed);')
    path.write_text(text)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=['baseline', 'xml', 'inverse-ui', 'inverse-h2-wakeup'])
    parser.add_argument('path', type=Path)
    parser.add_argument('--manifest', type=Path)
    parser.add_argument('--pr', type=int)
    parser.add_argument('--negative', action='store_true')
    args = parser.parse_args()
    if args.mode == 'inverse-ui':
        ui_inverse(args.path)
    elif args.mode == 'inverse-h2-wakeup':
        text = args.path.read_text()
        assert text.count('if (send_ret == 0) {') == 1
        args.path.write_text(text.replace('if (send_ret == 0) {', 'if (send_ret == 0 && 0) {'))
    else:
        item = next(t for t in json.loads(args.manifest.read_text()) if t['pr'] == args.pr)
        if args.mode == 'baseline': baseline(args.pr, item, args.path)
        else: xml_check(args.path, item, args.negative)
