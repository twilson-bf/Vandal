import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

spec = importlib.util.spec_from_file_location('dependencies', Path(__file__).resolve().parents[1] / 'scripts/dependencies.py')
deps = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deps)


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.patcher = patch.object(deps, 'ROOT', self.root)
        self.patcher.start()
        self.version_patch = patch.object(deps, 'environment_python_version',
                                          return_value=f'{sys.version_info.major}.{sys.version_info.minor}')
        self.version_patch.start()

    def tearDown(self):
        self.version_patch.stop()
        self.patcher.stop()
        self.temp.cleanup()

    def binary_spec(self, data=b'#!/bin/sh\nexit 0\n', archive=False):
        if archive:
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, 'w') as z:
                z.writestr('example', data)
                z.writestr('../escape', 'must not be extracted')
            data = stream.getvalue()
        digest = hashlib.sha256(data).hexdigest()
        cache = self.root / '.cache/downloads' / digest
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_bytes(data)
        return {'version': 'v1', 'assets': {'linux-amd64': {
            'url': 'https://example.invalid/tool', 'sha256': digest,
            'format': 'zip' if archive else 'binary'}}}

    def test_binary_rerun_is_noop_and_corruption_is_repaired_offline(self):
        spec = self.binary_spec()
        with patch.object(deps.urllib.request, 'urlopen', side_effect=AssertionError('network forbidden')):
            deps.install_binary('example', spec, 'linux-amd64', True)
            binary = self.root / '.tools/bin/example'
            original = binary.read_bytes()
            timestamp = binary.stat().st_mtime_ns
            deps.install_binary('example', spec, 'linux-amd64', True)
            self.assertEqual(timestamp, binary.stat().st_mtime_ns)
            binary.write_bytes(b'corrupted')
            deps.install_binary('example', spec, 'linux-amd64', True)
            self.assertEqual(original, binary.read_bytes())

    def test_checksum_mismatch_is_not_published(self):
        destination = self.root / 'download'
        with patch.object(deps.urllib.request, 'urlopen', return_value=io.BytesIO(b'wrong')):
            with self.assertRaisesRegex(RuntimeError, 'SHA-256 mismatch'):
                deps.download('https://example.invalid', destination, '0' * 64)
        self.assertFalse(destination.exists())
        self.assertFalse(destination.with_suffix('.partial').exists())

    def test_corrupt_receipt_is_recovered(self):
        spec = self.binary_spec()
        deps.install_binary('example', spec, 'linux-amd64', True)
        receipt = self.root / '.tools/receipts/example.json'
        receipt.write_text('{incomplete')
        deps.install_binary('example', spec, 'linux-amd64', True)
        self.assertEqual(json.loads(receipt.read_text())['version'], 'v1')

    def test_failed_download_preserves_old_binary(self):
        spec = self.binary_spec()
        deps.install_binary('example', spec, 'linux-amd64', True)
        binary = self.root / '.tools/bin/example'
        old = binary.read_bytes()
        spec['assets']['linux-amd64']['sha256'] = '0' * 64
        with self.assertRaises(RuntimeError):
            deps.install_binary('example', spec, 'linux-amd64', True)
        self.assertEqual(old, binary.read_bytes())

    def test_zip_only_extracts_exact_binary(self):
        deps.install_binary('example', self.binary_spec(archive=True), 'linux-amd64', True)
        self.assertTrue((self.root / '.tools/bin/example').exists())
        self.assertFalse(list(self.root.rglob('escape')))

    def test_missing_offline_cache_does_not_download(self):
        with patch.object(deps.urllib.request, 'urlopen', side_effect=AssertionError('network forbidden')):
            with self.assertRaisesRegex(RuntimeError, 'No verified cached'):
                deps.download('https://example.invalid', self.root / 'missing', '0' * 64, True)

    def test_environment_drift_and_lock_changes_are_detected(self):
        directory = self.root / 'env'
        (directory / 'bin').mkdir(parents=True)
        (directory / 'bin/python').touch()
        lock = self.root / 'example.lock'
        lock.write_text('package==1\n')
        inventory = [{'name': 'package', 'version': '1'}]
        deps.write_json(directory / '.vandal-receipt.json', {'lock_sha256': deps.sha256(lock), 'inventory': inventory})
        with patch.object(deps, 'run'), patch.object(deps, 'environment_inventory', return_value=inventory):
            self.assertTrue(deps.environment_matches(directory, lock))
            lock.write_text('package==2\n')
            self.assertFalse(deps.environment_matches(directory, lock))
        lock.write_text('package==1\n')
        with patch.object(deps, 'run'), patch.object(deps, 'environment_inventory', return_value=[]):
            self.assertFalse(deps.environment_matches(directory, lock))

    def test_extras_are_opt_in(self):
        manifest = {'tools': {'a': {'group': 'core'}, 'b': {'group': 'extras'}}}
        self.assertEqual(set(deps.selected_tools(manifest, False)), {'a'})
        self.assertEqual(set(deps.selected_tools(manifest, True)), {'a', 'b'})

    def test_supported_architectures(self):
        with patch.object(deps.platform, 'system', return_value='Linux'):
            for machine, key in [('x86_64', 'linux-amd64'), ('aarch64', 'linux-arm64')]:
                with patch.object(deps.platform, 'machine', return_value=machine):
                    self.assertEqual(deps.platform_key(), key)
            with patch.object(deps.platform, 'machine', return_value='unknown'):
                with self.assertRaises(RuntimeError):
                    deps.platform_key()

    def test_system_packages_skip_existing_and_only_install_missing(self):
        mockbin = self.root / 'mockbin'
        mockbin.mkdir()
        log = self.root / 'calls'
        scripts = {
            'dpkg-query': '#!/bin/bash\nif [[ "${@: -1}" == "${FAKE_MISSING:-}" ]]; then exit 1; fi\nprintf "install ok installed"\n',
            'sudo': '#!/bin/bash\nexec "$@"\n',
            'apt-get': '#!/bin/bash\nprintf "%s\\n" "$*" >> "$FAKE_LOG"\n',
        }
        for name, script in scripts.items():
            path = mockbin / name
            path.write_text(script)
            path.chmod(0o755)
        env = {**os.environ, 'PATH': f'{mockbin}:{os.environ["PATH"]}', 'FAKE_LOG': str(log)}
        script = Path(__file__).resolve().parents[1] / 'scripts/install-system.sh'
        # This integration test is only applicable to the supported Debian-family host.
        release = Path('/etc/os-release').read_text() if Path('/etc/os-release').exists() else ''
        if not any(n in release.lower() for n in ['debian', 'ubuntu', 'kali']):
            self.skipTest('Debian-family package script')
        subprocess.run(['bash', str(script)], env=env, check=True, capture_output=True)
        self.assertFalse(log.exists())
        subprocess.run(['bash', str(script)], env={**env, 'FAKE_MISSING': 'nmap'}, check=True, capture_output=True)
        calls = log.read_text().splitlines()
        self.assertEqual(len(calls), 2)
        self.assertTrue(calls[0].endswith(' update'))
        self.assertTrue(calls[1].endswith(' install -y --no-install-recommends nmap'))
        self.assertEqual(calls[0].rsplit(' update', 1)[0], calls[1].split(' install ', 1)[0])
        self.assertIn('Dir::Etc::sourcelist=-', calls[0])
        self.assertIn('Dir::State::lists=/tmp/vandal-apt.', calls[0])


if __name__ == '__main__':
    unittest.main()
