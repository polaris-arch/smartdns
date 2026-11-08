#!/usr/bin/env python3
"""Relink existing native objects with pristine libssl; do not rebuild the app."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
CASE = 'StrictPeerCredit.GcPublishesCreditWithoutFurtherApplicationIo'
OUT = ROOT / 'ci-results'
SLOT = ROOT / '.ci-openssl/secondary'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    # Qualify the exact candidate's actual full-suite execution first.
    matches = [node for suite in ET.parse(OUT / 'results.xml').getroot().iter('testsuite')
               for node in suite.findall('testcase') if suite.get('name') + '.' + node.get('name') == CASE]
    if len(matches) != 1 or matches[0].get('result') != 'completed' or list(matches[0]):
        raise RuntimeError('Candidate credit/scheduling case did not actually pass')
    sanitizers = os.environ.get('CI_NATIVE_SANITIZERS') == '1'
    verify = ['python3', '.github/scripts/openssl-dependency.py', 'verify', '--pristine',
              '--prefix', str(SLOT / 'install')]
    if sanitizers:
        verify += ['--sanitizers']
    subprocess.run(verify, cwd=ROOT, check=True)
    objects = sorted((ROOT / 'test').rglob('*.o'))
    objects += [ROOT / 'src/libsmartdns-test.a', ROOT / '.ci-openssl/candidate/probe.o']
    before = {str(p.relative_to(ROOT)): digest(p) for p in objects}
    binary = SLOT / 'native-control.test.bin'
    flags = ['-L' + str(SLOT / 'install/lib'), '-Wl,-Map=' + str(OUT / 'native-pristine-link.map')]
    if sanitizers:
        flags += ['-fsanitize=address,undefined']
    subprocess.run(['make', '-C', 'test', 'BIN=' + str(binary),
                    'EXTRA_LDFLAGS=' + ' '.join(flags)], cwd=ROOT, check=True)
    if before != {str(p.relative_to(ROOT)): digest(p) for p in objects}:
        raise RuntimeError('Native negative control unexpectedly changed application/test objects')
    link_map = (OUT / 'native-pristine-link.map').read_text()
    for library in ['libssl.a', 'libcrypto.a']:
        if 'LOAD ' + str(SLOT / 'install/lib' / library) not in link_map:
            raise RuntimeError('Pristine control did not link its exact static archive: ' + library)
    try:
        result = subprocess.run([str(binary), '--gtest_filter=' + CASE], cwd=ROOT,
                                capture_output=True, text=True, timeout=20)
        code, log = result.returncode, result.stdout + result.stderr
    except subprocess.TimeoutExpired as exc:
        code, log = 124, str(exc)
    (OUT / 'native-pristine-credit-control.log').write_text(log)
    forbidden = ['AddressSanitizer:', 'LeakSanitizer:', 'runtime error:', 'Sanitizer has encountered']
    qualified = (code == 1 and 'GC must publish MAX_DATA in the same tick' in log
                 and not any(marker in log for marker in forbidden))
    record = {'case': CASE, 'candidate': 0, 'pristine': code, 'qualified_failure': qualified,
              'binary_sha256': digest(binary), 'unchanged_objects': before}
    path = OUT / 'openssl-quic-tests.json'
    report = json.loads(path.read_text())
    report['native_credit_control'] = record
    path.write_text(json.dumps(report, indent=2) + '\n')
    # Child execution is finished and objects are no longer referenced. Keep
    # exact identities/maps/logs; free the secondary slot for fair comparison.
    shutil.rmtree(SLOT)
    if not qualified:
        raise RuntimeError('Pristine credit/scheduling control did not fail at the expected real protocol assertion')


if __name__ == '__main__':
    main()
