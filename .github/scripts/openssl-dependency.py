#!/usr/bin/env python3
"""One pinned OpenSSL recipe for offline native tests and release toolchains.

Only fetch uses the network. Compilation belongs to CI, never this developer's
machine. A restored toolchain is trusted only after checking its installed files
against a receipt bound to the archive, patch, compiler and complete recipe.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
SPEC = ROOT / '.github/dependencies/openssl.json'


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest() if hasattr(hashlib, 'file_digest') else _old_sha(stream)


def _old_sha(stream):
    digest = hashlib.sha256()
    for block in iter(lambda: stream.read(1024 * 1024), b''):
        digest.update(block)
    return digest.hexdigest()


def run(args, **kwargs):
    print('+', ' '.join(str(x) for x in args), flush=True)
    return subprocess.run([str(x) for x in args], check=True, **kwargs)


def identity(args, spec):
    compiler = shutil.which(args.cc)
    if compiler is None:
        raise RuntimeError('Compiler not found: ' + args.cc)
    return {
        'version': spec['version'], 'archive_sha256': spec['sha256'],
        'patch_sha256': sha(ROOT / spec['patch']) if not args.pristine else None,
        'recipe_sha256': sha(__file__), 'spec_sha256': sha(SPEC),
        'target': args.target, 'compiler': str(Path(compiler).resolve()),
        'compiler_sha256': sha(compiler),
        'compiler_version': subprocess.check_output([compiler, '--version'], text=True).splitlines()[0],
        'configure': spec['configure'] + ['--libdir=lib'],
        'cflags': '-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=all' if args.sanitizers else '-Os',
        'sanitizers': args.sanitizers, 'pristine': args.pristine,
    }


def installed_files(prefix):
    paths = [prefix / 'lib/libssl.a', prefix / 'lib/libcrypto.a']
    paths += sorted((prefix / 'include/openssl').glob('*.h'))
    if len(paths) < 20 or any(not p.is_file() for p in paths):
        raise RuntimeError('Incomplete OpenSSL installation')
    return {str(p.relative_to(prefix)): {'size': p.stat().st_size, 'sha256': sha(p)} for p in paths}


def verify(args, spec):
    prefix = args.prefix.resolve()
    receipt = json.loads((prefix / 'openssl-build-receipt.json').read_text())
    if receipt['input'] != identity(args, spec):
        raise RuntimeError('OpenSSL cache input identity mismatch')
    if receipt['files'] != installed_files(prefix):
        raise RuntimeError('OpenSSL cache installed content mismatch')
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['fetch', 'build', 'verify'])
    parser.add_argument('--archive', type=Path)
    parser.add_argument('--work', type=Path)
    parser.add_argument('--prefix', type=Path)
    parser.add_argument('--target', default='linux-x86_64')
    parser.add_argument('--cc', default='cc')
    parser.add_argument('--sanitizers', action='store_true')
    parser.add_argument('--pristine', action='store_true')
    parser.add_argument('--jobs', type=int, default=4)
    parser.add_argument('--receipt', type=Path)
    args = parser.parse_args()
    spec = json.loads(SPEC.read_text())
    if args.action == 'fetch':
        if args.archive is None:
            parser.error('fetch requires --archive')
        args.archive.parent.mkdir(parents=True, exist_ok=True)
        if args.archive.exists() and args.archive.stat().st_size == spec['size'] and sha(args.archive) == spec['sha256']:
            return
        partial = args.archive.with_suffix('.partial')
        try:
            with urllib.request.urlopen(spec['url'], timeout=120) as response, partial.open('wb') as out:
                shutil.copyfileobj(response, out)
            if partial.stat().st_size != spec['size'] or sha(partial) != spec['sha256']:
                raise RuntimeError('OpenSSL archive size/SHA256 mismatch')
            partial.replace(args.archive)
        finally:
            partial.unlink(missing_ok=True)
        return
    if args.prefix is None:
        parser.error('build/verify require --prefix')
    if args.action == 'build':
        if args.work is None or args.archive is None:
            parser.error('build requires --work and --archive')
        if not 1 <= args.jobs <= 16:
            parser.error('jobs must be between 1 and 16')
        if args.archive.stat().st_size != spec['size'] or sha(args.archive) != spec['sha256']:
            raise RuntimeError('OpenSSL archive size/SHA256 mismatch before extraction')
        # Callers own this fixed build slot. Refuse reuse, rather than mixing objects.
        args.work.mkdir(parents=True, exist_ok=False)
        source = args.work / 'source'
        source.mkdir()
        run(['tar', '-xzf', args.archive.resolve(), '--strip-components=1', '-C', source])
        if not args.pristine:
            run(['patch', '--batch', '--forward', '--fuzz=0', '-p1'], cwd=source,
                input=(ROOT / spec['patch']).read_bytes())
        build_input = identity(args, spec)
        environment = os.environ.copy()
        # Do not inherit application sanitizer/linker flags into another variant.
        for name in ['CFLAGS', 'CXXFLAGS', 'CPPFLAGS', 'LDFLAGS', 'EXTRA_CFLAGS', 'EXTRA_LDFLAGS']:
            environment.pop(name, None)
        environment['CC'] = args.cc
        environment['CFLAGS'] = build_input['cflags']
        if args.sanitizers:
            environment['LDFLAGS'] = '-fsanitize=address,undefined'
        run(['./Configure', args.target, '--prefix=' + str(args.prefix.resolve()),
             *build_input['configure']], cwd=source, env=environment)
        run(['make', '-j' + str(args.jobs), 'build_libs'], cwd=source, env=environment)
        run(['make', 'install_sw'], cwd=source, env=environment)
        args.prefix.mkdir(parents=True, exist_ok=True)
        receipt = {'input': build_input, 'files': installed_files(args.prefix.resolve())}
        (args.prefix / 'openssl-build-receipt.json').write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n')
    receipt = verify(args, spec)
    if args.receipt:
        args.receipt.parent.mkdir(parents=True, exist_ok=True)
        args.receipt.write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n')
    print('Verified installed OpenSSL', receipt['input']['version'], 'pristine=' + str(args.pristine))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.CalledProcessError) as exc:
        sys.exit(str(exc))
