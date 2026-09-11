import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('apt_sources', Path(__file__).resolve().parents[1] / 'scripts/apt_sources.py')
apt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(apt)


class AptSourcesTests(unittest.TestCase):
    def test_kali_snapshot_survives_broken_third_party_source(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            parts = root / 'sources.list.d'
            parts.mkdir()
            configured = 'Types: deb\nURIs: http://http.kali.org/kali/\nSuites: kali-last-snapshot\nComponents: main contrib non-free non-free-firmware\nSigned-By: /usr/share/keyrings/kali-archive-keyring.gpg\n'
            (parts / 'kali.sources').write_text(configured)
            (parts / 'hashicorp.list').write_text('deb [signed-by=/key.gpg] https://apt.releases.hashicorp.com kali-rolling main\n')
            (parts / 'github.list').write_text('deb https://cli.github.com/packages stable main\n')
            apt.select_sources(root, root / 'selected', 'kali')
            selected = (root / 'selected/distribution.sources').read_text()
            self.assertIn('suites: kali-last-snapshot', selected)
            self.assertIn('signed-by: /usr/share/keyrings/kali-archive-keyring.gpg', selected)
            self.assertNotIn('hashicorp', selected)
            self.assertNotIn('github', selected)
            self.assertEqual((root / 'selected/distribution.list').read_text(), '\n')
            self.assertEqual((parts / 'kali.sources').read_text(), configured)

    def test_legacy_lines_and_disabled_mixed_stanzas(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            parts = root / 'sources.list.d'
            parts.mkdir()
            line = 'deb [arch=amd64 signed-by=/key.gpg] https://deb.debian.org/debian stable main'
            (root / 'sources.list').write_text(line + '\n# deb https://deb.debian.org/debian unstable main\n')
            (parts / 'mixed.sources').write_text('Types: deb\nURIs: https://security.debian.org/debian-security https://unrelated.invalid/\nSuites: stable-security\nComponents: main\n\nTypes: deb\nURIs: https://deb.debian.org/debian\nSuites: unstable\nEnabled: no\nComponents: main\n')
            apt.select_sources(root, root / 'selected', 'debian')
            self.assertEqual((root / 'selected/distribution.list').read_text().strip(), line)
            selected = (root / 'selected/distribution.sources').read_text()
            self.assertIn('stable-security', selected)
            self.assertNotIn('unrelated', selected)
            self.assertNotIn('unstable', selected)

    def test_no_official_sources_fails_without_adding_a_suite(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'sources.list').write_text('deb https://kali.org.evil.invalid/kali kali-rolling main\n')
            with self.assertRaisesRegex(ValueError, 'No configured official'):
                apt.select_sources(root, root / 'selected', 'kali')


if __name__ == '__main__':
    unittest.main()
