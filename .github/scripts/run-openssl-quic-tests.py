#!/usr/bin/env python3
"""Build two bounded CI-only dependency variants and test real archive objects."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / '.ci-openssl'
OUT = ROOT / 'ci-results'


def run(command, **kwargs):
    print('+', ' '.join(str(x) for x in command), flush=True)
    subprocess.run([str(x) for x in command], check=True, **kwargs)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--sanitizers', action='store_true')
    args = parser.parse_args()
    OUT.mkdir(exist_ok=True)
    BUILD.mkdir(exist_ok=True)
    if shutil.disk_usage(BUILD).free < 3 * 1024 ** 3:
        raise RuntimeError('Reserve 3 GiB for the two dependency/test slots')
    required = runpy.run_path(str(ROOT / '.github/scripts/check-native-results.py'))['OPENSSL_QUIC_REQUIRED']
    spec = json.loads((ROOT / '.github/dependencies/openssl.json').read_text())
    report = {'archive_sha256': spec['sha256'],
              'patch_sha256': hashlib.sha256((ROOT / spec['patch']).read_bytes()).hexdigest(),
              'sanitizers': args.sanitizers, 'variants': {}, 'cases': []}
    results = {}
    recipe = ROOT / '.github/scripts/openssl-dependency.py'
    common = ['--archive', BUILD / 'openssl.tar.gz']
    # OSSL_LIST_MEMBER changes layout in debug builds. Match Configure's
    # release library ABI; our CHECK assertions do not depend on assert().
    flags = ['-DNDEBUG', '-O1', '-g', '-fno-omit-frame-pointer']
    if args.sanitizers:
        common += ['--sanitizers']
        flags += ['-fsanitize=address,undefined', '-fno-sanitize-recover=all']
    for variant in ['candidate', 'pristine']:
        slot = BUILD / ('candidate' if variant == 'candidate' else 'secondary')
        prefix = slot / 'install'
        source = slot / 'build/source'
        command = ['python3', recipe, 'build', *common, '--work', slot / 'build', '--prefix', prefix,
                   '--receipt', OUT / ('openssl-' + variant + '.json')]
        if variant == 'pristine':
            command += ['--pristine']
        run(command)
        binary = slot / 'regressions'
        run(['cc', *flags, *(['-DSD_QUIC_PATCHED=1'] if variant == 'candidate' else []),
             '-I' + str(prefix / 'include'), '-I' + str(source / 'include'), '-I' + str(source),
             ROOT / '.github/tests/openssl-quic-reclamation.c', '-o', binary,
             prefix / 'lib/libssl.a', prefix / 'lib/libcrypto.a', '-ldl', '-lpthread',
             '-Wl,--wrap=CRYPTO_free,--wrap=ossl_quic_fifd_init',
             '-Wl,-Map=' + str(OUT / ('openssl-' + variant + '-link.map'))])
        report['variants'][variant] = {'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                                       'receipt': 'openssl-' + variant + '.json'}
        for name in sorted(required):
            start = time.monotonic()
            try:
                result = subprocess.run([str(binary), name], stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, text=True, timeout=20)
                code, log = result.returncode, result.stdout
            except subprocess.TimeoutExpired as exc:
                code, log = 124, str(exc)
            (OUT / ('openssl-' + variant + '-' + name + '.log')).write_text(log)
            results[(variant, name)] = (code, time.monotonic() - start, log)
        # Joined executions: retain only pristine archives for the native relink
        # control. Comparison later reuses this same fixed secondary slot.
        if variant == 'pristine':
            shutil.rmtree(slot / 'build')
    for name in sorted(required):
        candidate, candidate_time, candidate_log = results[('candidate', name)]
        pristine, pristine_time, pristine_log = results[('pristine', name)]
        clean = not any(marker in candidate_log + pristine_log for marker in
                        ['AddressSanitizer:', 'LeakSanitizer:', 'runtime error:', 'Sanitizer has encountered'])
        report['cases'].append({'name': name, 'candidate': candidate, 'pristine': pristine,
                                'seconds': candidate_time + pristine_time,
                                'candidate_completed': name + ': PASS (' in candidate_log,
                                'pristine_expected_failure': required[name] in pristine_log and name + ': FAIL (' in pristine_log,
                                'sanitizer_clean': clean})
    (OUT / 'openssl-quic-tests.json').write_text(json.dumps(report, indent=2) + '\n')
    if any(item['candidate'] != 0 or item['pristine'] != 1 or not item['candidate_completed']
           or not item['pristine_expected_failure'] or not item['sanitizer_clean'] for item in report['cases']):
        raise RuntimeError('Dependency regressions require candidate=0 and controlled pristine assertion=1; crashes/timeouts never qualify')


if __name__ == '__main__':
    main()
