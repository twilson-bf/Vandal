import os
import tempfile
import unittest
from unittest.mock import patch

from fastapi import HTTPException

from vandal.db import connect, migrate, now
from vandal.mythic import attach, authenticate, create_source, ingest, rematch_engagement, rotate_token


class MythicDataTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {'VANDAL_DATA': self.temp.name})
        self.env.start()
        migrate()
        with connect() as con:
            self.eid = con.execute('INSERT INTO engagements(name,created_at) VALUES (?,?)', ('Test', now())).lastrowid
            self.source_id, self.token = create_source(con, self.eid, 'Mythic test', 'https://mythic.example.test', 2)

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def test_token_ingest_exact_match_and_projection(self):
        with connect() as con:
            asset_id = con.execute('INSERT INTO assets(engagement_id,kind,value) VALUES (?,?,?)', (self.eid, 'ip', '192.0.2.1')).lastrowid
            source = authenticate(con, self.source_id, 'Bearer ' + self.token)
            result = ingest(con, source, {'callbacks': [{
                'id': 41, 'display_id': 7, 'operation_id': 2, 'external_ip': '192.0.2.1', 'host': 'WWW.EXAMPLE.COM.',
                'user': 'alice', 'last_checkin': '2026-09-16T12:00:00Z',
            }]})
            self.assertEqual(result['asset_matches'], 1)
            assets = [dict(con.execute('SELECT * FROM assets WHERE id=?', (asset_id,)).fetchone(), associated=[])]
            attach(con, self.eid, assets)
        self.assertTrue(assets[0]['pwned'])
        self.assertEqual(assets[0]['callback_count'], 1)
        self.assertEqual(assets[0]['mythic_callbacks'][0]['source_url'], 'https://mythic.example.test/new/callbacks/7')

    def test_revoked_or_incorrect_token_is_rejected(self):
        with connect() as con:
            with self.assertRaises(HTTPException):
                authenticate(con, self.source_id, 'Bearer wrong')
            con.execute('UPDATE integration_sources SET active=0 WHERE id=?', (self.source_id,))
            with self.assertRaises(HTTPException):
                authenticate(con, self.source_id, 'Bearer ' + self.token)

    def test_rotated_token_replaces_previous_token(self):
        with connect() as con:
            source, replacement = rotate_token(con, self.source_id, self.eid)
            self.assertEqual(source['operation_id'], 2)
            self.assertNotEqual(replacement, self.token)
            with self.assertRaises(HTTPException):
                authenticate(con, self.source_id, 'Bearer ' + self.token)
            self.assertEqual(authenticate(con, self.source_id, 'Bearer ' + replacement)['id'], self.source_id)

    def test_asset_created_after_callback_is_rematched(self):
        with connect() as con:
            source = authenticate(con, self.source_id, 'Bearer ' + self.token)
            result = ingest(con, source, {'callbacks': [{'id': 1, 'display_id': 1, 'operation_id': 2, 'external_ip': '192.0.2.9'}]})
            self.assertEqual(result['asset_matches'], 0)
            asset_id = con.execute('INSERT INTO assets(engagement_id,kind,value) VALUES (?,?,?)', (self.eid, 'ip', '192.0.2.9')).lastrowid
            rematch_engagement(con, self.eid)
            self.assertEqual(con.execute('SELECT asset_id FROM mythic_callback_assets').fetchone()[0], asset_id)


if __name__ == '__main__':
    unittest.main()
