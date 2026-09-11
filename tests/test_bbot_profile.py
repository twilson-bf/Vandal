import unittest
from unittest.mock import patch

from vandal.jobs import prepare


class BbotProfileTests(unittest.TestCase):
    def plan(self):
        return prepare('bbot-passive', ['example.com'], {},
                       [{'action': 'include', 'target': 'example.com'}])

    def test_missing_core_dependency_blocks_before_launch(self):
        with patch('vandal.jobs.executable', return_value='/tools/bbot'), \
             patch('vandal.jobs.shutil.which', side_effect=lambda name: None if name == 'gcc' else '/usr/bin/' + name), \
             patch('vandal.jobs.Path.is_file', return_value=True):
            with self.assertRaisesRegex(ValueError, 'gcc.*install.sh --system'):
                self.plan()

    def test_ready_profile_resolves_dns_without_module_installs(self):
        with patch('vandal.jobs.executable', return_value='/tools/bbot'), \
             patch('vandal.jobs.shutil.which', return_value='/usr/bin/tool'), \
             patch('vandal.jobs.Path.is_file', return_value=True):
            command = self.plan()['command']
        self.assertIn('dns.disable=false', command)
        self.assertIn('shodan_idb', command)
        self.assertIn('deps.behavior=disable', command)
        self.assertEqual(command[command.index('-rf') + 1], 'passive')
