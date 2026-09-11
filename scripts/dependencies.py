#!/usr/bin/env python3
"""Local, pinned dependency setup. No target traffic or application startup."""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def sha256(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def run(args, **kwargs):
    return subprocess.run([str(a) for a in args], check=True, **kwargs)


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    temporary.replace(path)


def read_receipt(path):
    try:
        value = path.read_text()
        decoded = json.loads(value)
        return decoded if isinstance(decoded, dict) else {}
    except (OSError, ValueError):
        return {}


def platform_key():
    arch = {'x86_64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64'}.get(platform.machine())
    if platform.system() != 'Linux' or not arch:
        raise RuntimeError('Supported platforms: Linux x86_64 and arm64.')
    return f'linux-{arch}'


def selected_tools(manifest, extras):
    return {n: t for n, t in manifest['tools'].items() if extras or t['group'] == 'core'}


def download(url, destination, digest, offline=False):
    if destination.exists() and sha256(destination) == digest:
        return
    if offline:
        raise RuntimeError(f'No verified cached download: {destination.name}')
    destination.parent.mkdir(parents=True, exist_ok=True)
    partial = destination.with_suffix(destination.suffix + '.partial')
    try:
        request = urllib.request.Request(url, headers={'User-Agent': 'vandal-dependency-installer'})
        with urllib.request.urlopen(request, timeout=60) as source, partial.open('wb') as target:
            shutil.copyfileobj(source, target)
        if sha256(partial) != digest:
            raise RuntimeError(f'SHA-256 mismatch for {url}')
        partial.replace(destination)
    finally:
        partial.unlink(missing_ok=True)


def install_binary(name, spec, key, offline):
    asset = spec['assets'][key]
    target = ROOT / '.tools' / 'bin' / name
    receipt = ROOT / '.tools' / 'receipts' / f'{name}.json'
    if target.is_file() and receipt.is_file():
        saved = read_receipt(receipt)
        if (saved.get('asset_sha256') == asset['sha256'] and
                saved.get('installed_sha256') == sha256(target) and os.access(target, os.X_OK)):
            print(f'OK   {name} {spec["version"]} (unchanged)', flush=True)
            return
    cache = ROOT / '.cache' / 'downloads' / asset['sha256']
    print(f'GET  {name} {spec["version"]}', flush=True)
    download(asset['url'], cache, asset['sha256'], offline)
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=target.parent) as staging:
        staged = Path(staging) / name
        if asset['format'] == 'zip':
            with zipfile.ZipFile(cache) as archive:
                # Extract only the exact binary, never arbitrary archive paths.
                matches = [i for i in archive.infolist() if i.filename == name and not i.is_dir()]
                if len(matches) != 1 or matches[0].file_size > 512 * 1024 * 1024:
                    raise RuntimeError(f'Invalid binary archive for {name}')
                with archive.open(matches[0]) as source, staged.open('wb') as dest:
                    shutil.copyfileobj(source, dest)
        else:
            shutil.copyfile(cache, staged)
        staged.chmod(0o755)
        staged.replace(target)
    write_json(receipt, {'version': spec['version'], 'platform': key, 'url': asset['url'],
                         'asset_sha256': asset['sha256'], 'installed_sha256': sha256(target)})


def environment_inventory(python):
    result = run([python, '-m', 'pip', 'list', '--format=json', '--disable-pip-version-check'],
                 capture_output=True, text=True)
    return sorted(json.loads(result.stdout), key=lambda p: p['name'].lower())


def environment_python_version(python):
    result = run([python, '-c', 'import sys; print("%s.%s" % sys.version_info[:2])'],
                 capture_output=True, text=True)
    return result.stdout.strip()


def environment_matches(directory, lockfile):
    python = directory / 'bin' / 'python'
    receipt = directory / '.vandal-receipt.json'
    if not python.exists() or not receipt.exists():
        return False
    saved = read_receipt(receipt)
    if saved.get('lock_sha256') != sha256(lockfile):
        return False
    try:
        if environment_python_version(python) != f'{sys.version_info.major}.{sys.version_info.minor}':
            return False
        inventory = environment_inventory(python)
        run([python, '-m', 'pip', 'check', '--disable-pip-version-check'], capture_output=True)
        return saved.get('inventory') == inventory
    except subprocess.CalledProcessError:
        return False


def install_environment(name, directory, lockfile, offline):
    if environment_matches(directory, lockfile):
        print(f'OK   {name} Python environment (unchanged)', flush=True)
        return
    if not (directory / 'bin' / 'python').exists():
        run([sys.executable, '-m', 'venv', directory])
    python = directory / 'bin' / 'python'
    if environment_python_version(python) != f'{sys.version_info.major}.{sys.version_info.minor}':
        raise RuntimeError(f'{directory} uses another Python version; move it aside before switching interpreters.')
    args = [python, '-m', 'pip', 'install', '--disable-pip-version-check', '--require-hashes', '-r', lockfile]
    if offline:
        # A prepared wheelhouse is explicit; pip's HTTP cache is not an offline index.
        args += ['--no-index', '--find-links', ROOT / '.cache' / 'wheels']
    run(args)
    run([python, '-m', 'pip', 'check', '--disable-pip-version-check'])
    write_json(directory / '.vandal-receipt.json',
               {'lock_sha256': sha256(lockfile), 'inventory': environment_inventory(python)})


def browser_path():
    override = os.environ.get('VANDAL_CHROME')
    if override:
        return shutil.which(override)
    return next((p for n in ['chromium', 'chromium-browser', 'google-chrome', 'google-chrome-stable']
                 if (p := shutil.which(n))), None)


def tool_version(path, name):
    args = ['version'] if name == 'gowitness' else ['--version'] if name in ['bbot', 'nmap', 'chromium'] else ['-version']
    try:
        result = subprocess.run([str(path), *args], capture_output=True, text=True, timeout=30,
                                env={**os.environ, 'NO_COLOR': '1'})
        text = (result.stdout + result.stderr).strip()
        return result.returncode == 0, text[-1500:]
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)


def doctor(manifest, key, extras, json_output=False):
    checks = []
    for name, directory in [('runtime', ROOT / '.venv'), ('bbot-python', ROOT / '.tools' / 'bbot')]:
        lock = ROOT / 'dependencies' / ('bbot.lock' if name == 'bbot-python' else 'runtime.lock')
        try:
            ok = environment_matches(directory, lock)
        except (OSError, ValueError):
            ok = False
        checks.append({'name': name, 'ok': ok, 'detail': 'locked environment intact' if ok else 'missing or changed environment'})
    for name, spec in selected_tools(manifest, extras).items():
        binary = ROOT / '.tools' / 'bin' / name
        receipt = ROOT / '.tools' / 'receipts' / f'{name}.json'
        try:
            saved = json.loads(receipt.read_text())
            ok = (saved['asset_sha256'] == spec['assets'][key]['sha256'] and
                  saved['installed_sha256'] == sha256(binary))
        except (OSError, ValueError, KeyError):
            ok = False
        works, detail = tool_version(binary, name) if ok else (False, 'missing or changed binary')
        checks.append({'name': name, 'ok': ok and works, 'pinned': spec['version'], 'detail': detail})
    for name, path in [('bbot', ROOT / '.tools' / 'bbot' / 'bin' / 'bbot'),
                       ('nmap', shutil.which('nmap')), ('chromium', browser_path())]:
        ok, detail = tool_version(path, name) if path else (False, 'not found; run ./install.sh --system')
        checks.append({'name': name, 'ok': ok, 'detail': detail})
    nessus = shutil.which('nessuscli') or ('/opt/nessus/sbin/nessuscli' if Path('/opt/nessus/sbin/nessuscli').exists() else None)
    checks.append({'name': 'nessus', 'ok': bool(nessus), 'optional': True,
                   'detail': nessus or 'vendor-managed; not required for importing Nessus reports'})
    if json_output:
        print(json.dumps(checks, indent=2))
    else:
        for c in checks:
            label = 'OK' if c['ok'] else 'OPTIONAL' if c.get('optional') else 'MISSING'
            print(f'{label:8} {c["name"]}: {c["detail"]}')
        print('Doctor checks installation only; it does not run scans or provision BBOT modules.')
    return 0 if all(c['ok'] or c.get('optional') for c in checks) else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', nargs='?', choices=['install', 'doctor'], default='install')
    parser.add_argument('--system', action='store_true', help='install missing Debian-family packages with sudo')
    parser.add_argument('--extras', action='store_true', help='also install Katana, Nuclei and TLSx')
    parser.add_argument('--offline', action='store_true', help='use verified downloads and .cache/wheels only')
    parser.add_argument('--json', action='store_true', help='machine-readable doctor output')
    args = parser.parse_args()
    if not (3, 11) <= sys.version_info[:2] <= (3, 13):
        parser.error('Use Python 3.11–3.13 (VANDAL_PYTHON can select the interpreter).')
    if args.command == 'doctor' and (args.system or args.offline):
        parser.error('doctor is read-only; --system/--offline apply to installation')
    if args.json and args.command != 'doctor':
        parser.error('--json requires doctor')
    if args.offline and args.system:
        parser.error('--offline cannot install system packages')
    key = platform_key()
    manifest = json.loads((ROOT / 'dependencies' / 'tools.lock.json').read_text())
    if args.command == 'doctor':
        return doctor(manifest, key, args.extras, args.json)
    (ROOT / '.tools').mkdir(exist_ok=True)
    with (ROOT / '.tools' / 'install.lock').open('w') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('Another installer is running.')
        if args.system:
            run(['bash', ROOT / 'scripts' / 'install-system.sh'])
        install_environment('runtime', ROOT / '.venv', ROOT / 'dependencies' / 'runtime.lock', args.offline)
        install_environment('BBOT', ROOT / '.tools' / 'bbot', ROOT / 'dependencies' / 'bbot.lock', args.offline)
        for name, spec in selected_tools(manifest, args.extras).items():
            install_binary(name, spec, key, args.offline)
        run([sys.executable, ROOT / 'scripts' / 'import-fonts.py'])
        bindir = ROOT / '.tools' / 'bin'
        bindir.mkdir(exist_ok=True)
        link = bindir / 'bbot'
        if not link.is_symlink() or os.readlink(link) != '../bbot/bin/bbot':
            if link.exists() and not link.is_symlink():
                raise RuntimeError(f'Refusing to overwrite unmanaged file {link}')
            link.unlink(missing_ok=True)
            link.symlink_to('../bbot/bin/bbot')
    print('\nDependency installation finished. Checking readiness…', flush=True)
    return doctor(manifest, key, args.extras)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (RuntimeError, OSError, ValueError, subprocess.CalledProcessError, zipfile.BadZipFile) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        sys.exit(1)
