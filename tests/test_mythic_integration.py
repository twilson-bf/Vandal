import os
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from vandal.app import app
from vandal.ingest import ingest, queue_import


NMAP = b'''<?xml version="1.0"?><nmaprun args="nmap -sV 192.0.2.1" start="1700000000"><host endtime="1700000010"><status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/><hostnames><hostname name="www.example.com" type="user"/></hostnames><ports/></host><runstats><finished exit="success"/></runstats></nmaprun>'''


class MythicIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {
            'VANDAL_DATA': self.temp.name,
            'VANDAL_WORKER': '0',
            'VANDAL_ADMIN_PASSWORD': 'test-password-1234',
        })
        self.env.start()
        self.context = TestClient(app)
        self.client = self.context.__enter__()
        self.client.post('/api/login', json={'name': 'admin', 'password': 'test-password-1234'})
        self.client.headers['X-CSRF-Token'] = self.client.get('/api/session').json()['csrf']
        self.eid = self.client.post('/api/engagements', json={'name': 'Test'}).json()['id']
        self.base = f'/api/e/{self.eid}'

    def tearDown(self):
        self.context.__exit__(None, None, None)
        self.env.stop()
        self.temp.cleanup()

    def test_callback_marks_host_and_map_and_deep_links_to_mythic(self):
        integration = self.client.post(self.base + '/integrations/mythic', json={
            'name': 'Mythic test', 'public_url': 'https://mythic.example.test', 'operation_id': 2,
        })
        self.assertEqual(integration.status_code, 200, integration.text)
        source = integration.json()
        self.assertTrue(source['token'].startswith('vnd_mythic_'))

        queued, _ = queue_import(self.eid, 'scan.xml', NMAP, 'test')
        ingest(queued)
        callback = {
            'id': 41, 'display_id': 7, 'operation_id': 2, 'operation_name': 'Test operation',
            'host': 'www.example.com', 'user': 'operator', 'external_ip': '192.0.2.1',
            'ip': '["10.10.10.4"]', 'os': 'linux', 'architecture': 'x64',
            'payload_type': 'apollo', 'active': True,
            'init_callback': '2026-09-16T12:00:00Z', 'last_checkin': '2026-09-16T12:01:00Z',
        }
        ingest_url = f"/api/integrations/mythic/{source['id']}/callbacks"
        self.assertEqual(self.client.post(ingest_url, json={'callbacks': [callback]}).status_code, 401)
        result = self.client.post(ingest_url, headers={'Authorization': 'Bearer ' + source['token']}, json={'callbacks': [callback], 'full_snapshot': True})
        self.assertEqual(result.status_code, 200, result.text)
        self.assertEqual(result.json()['received'], 1)
        self.assertGreaterEqual(result.json()['asset_matches'], 2)

        hosts = self.client.get(self.base + '/hosts').json()['items']
        host = next(item for item in hosts if item['value'] == '192.0.2.1')
        self.assertTrue(host['pwned'])
        self.assertEqual(host['callback_count'], 1)
        self.assertEqual(self.client.get(self.base + '/hosts?q=has:pwned').json()['total'], 1)
        detail = self.client.get(self.base + f"/hosts/{host['id']}").json()
        beacon = detail['mythic_callbacks'][0]
        self.assertEqual(beacon['source_url'], 'https://mythic.example.test/new/callbacks/7')
        self.assertEqual(set(beacon['match_basis']), {'exact external IP', 'exact hostname'})

        marker = next(item for item in self.client.get(self.base + '/dashboard?view=current').json()['locations'] if item['value'] == '192.0.2.1')
        self.assertTrue(marker['pwned'])
        self.assertEqual(marker['callback_count'], 1)

        rotated = self.client.post(self.base + f"/integrations/mythic/{source['id']}/token")
        self.assertEqual(rotated.status_code, 200, rotated.text)
        replacement = rotated.json()
        self.assertTrue(replacement['token'].startswith('vnd_mythic_'))
        self.assertNotEqual(replacement['token'], source['token'])
        self.assertEqual(replacement['operation_id'], 2)
        self.assertEqual(self.client.post(ingest_url, headers={'Authorization': 'Bearer ' + source['token']}, json={'callbacks': []}).status_code, 401)
        self.assertEqual(self.client.post(ingest_url, headers={'Authorization': 'Bearer ' + replacement['token']}, json={'callbacks': [callback]}).status_code, 200)

        self.client.delete(self.base + f"/integrations/mythic/{source['id']}")
        denied = self.client.post(ingest_url, headers={'Authorization': 'Bearer ' + replacement['token']}, json={'callbacks': []})
        self.assertEqual(denied.status_code, 401)
        self.assertTrue(self.client.get(self.base + f"/hosts/{host['id']}").json()['pwned'])

    def test_callback_received_before_asset_is_matched_after_import(self):
        source = self.client.post(self.base + '/integrations/mythic', json={
            'name': 'Mythic early', 'public_url': 'https://mythic.example.test', 'operation_id': 2,
        }).json()
        response = self.client.post(
            f"/api/integrations/mythic/{source['id']}/callbacks",
            headers={'Authorization': 'Bearer ' + source['token']},
            json={'callbacks': [{'id': 1, 'display_id': 1, 'operation_id': 2, 'external_ip': '192.0.2.1'}]},
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()['asset_matches'], 0)
        queued, _ = queue_import(self.eid, 'scan.xml', NMAP, 'test')
        ingest(queued)
        host = next(item for item in self.client.get(self.base + '/hosts').json()['items'] if item['value'] == '192.0.2.1')
        self.assertTrue(host['pwned'])


if __name__ == '__main__':
    unittest.main()
