import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from vandal import app as routes
from vandal.db import connect, migrate, now
from vandal.ingest import ingest, queue_import
from vandal.inventory import search
from vandal.jobs import scope_targets
from vandal.scope_rules import policy


class ScopeGroupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {'VANDAL_DATA': self.temp.name})
        self.env.start()
        migrate()
        with connect() as con:
            self.eid = con.execute("INSERT INTO engagements(name,created_at) VALUES ('Scope fixture',?)", (now(),)).lastrowid
        iid, _ = queue_import(self.eid, 'targets.txt', b'one.example.com\ntwo.example.net\n192.0.2.10\n', 'fixture')
        ingest(iid)
        self.request = SimpleNamespace()
        self.actor = {'name': 'operator'}
        self.auth = patch('vandal.app.auth.access', return_value=self.actor)
        self.auth.start()

    def tearDown(self):
        self.auth.stop()
        self.env.stop()
        self.temp.cleanup()

    def test_open_by_default_and_include_limit(self):
        with connect() as con:
            rules, limited = policy(con, self.eid)
        self.assertFalse(limited)
        self.assertEqual(scope_targets(['one.example.com'], rules), (['one.example.com'], []))
        updated = routes.update_scope_settings(self.eid, self.request, {'limit_to_included': True})
        self.assertTrue(updated['limit_to_included'])
        with connect() as con:
            rules, limited = policy(con, self.eid)
        self.assertEqual(scope_targets(['one.example.com'], rules, limited)[0], [])
        routes.add_scope(self.eid, self.request, {'tag': 'customer', 'action': 'include', 'targets': 'example.com', 'hidden': False})
        with connect() as con:
            rules, limited = policy(con, self.eid)
        self.assertEqual(scope_targets(['one.example.com'], rules, limited)[0], ['one.example.com'])
        self.assertEqual(scope_targets(['two.example.net'], rules, limited)[0], [])

    def test_group_state_and_visibility_are_independent(self):
        routes.add_scope(self.eid, self.request, {'tag': 'EPT', 'action': 'exclude', 'targets': 'example.com', 'hidden': False})
        groups = routes.scope_groups(self.eid, self.request)
        self.assertEqual(groups[0]['tag'], 'EPT')
        self.assertEqual((groups[0]['action'], groups[0]['hidden'], groups[0]['matched_assets']), ('exclude', False, 1))
        with connect(visible_eid=self.eid) as con:
            self.assertEqual(con.execute("SELECT count(*) FROM assets WHERE value='one.example.com'").fetchone()[0], 1)
        routes.update_scope_group(self.eid, 'EPT', self.request, {'hidden': True})
        with connect(visible_eid=self.eid) as con:
            self.assertEqual(con.execute("SELECT count(*) FROM assets WHERE value='one.example.com'").fetchone()[0], 0)
        routes.update_scope_group(self.eid, 'EPT', self.request, {'action': 'include', 'hidden': False})
        result = routes.scope_group_targets(self.eid, 'EPT', self.request)
        self.assertEqual(result['targets'], ['example.com'])

    def test_scope_tag_search_and_facet(self):
        routes.add_scope(self.eid, self.request, {'tag': 'Web estate', 'action': 'include', 'targets': 'example.com', 'hidden': False})
        with connect(visible_eid=self.eid) as con:
            data = search(con, self.eid, {'q': 'scope_tag:"Web estate"', 'mode': 'hostname'})
        self.assertEqual([a['value'] for a in data['items']], ['one.example.com'])
        self.assertEqual(data['facets']['scope_tag'], [('Web estate', 1)])

    def test_migration_preserves_old_exclusion_visibility_and_reason_as_tag(self):
        with tempfile.TemporaryDirectory() as old_data, patch.dict(os.environ, {'VANDAL_DATA': old_data}):
            db = Path(old_data) / 'vandal.db'
            con = sqlite3.connect(db)
            con.execute('CREATE TABLE migrations(version TEXT PRIMARY KEY, applied_at TEXT NOT NULL)')
            root = Path(__file__).parents[1] / 'vandal' / 'migrations'
            for path in sorted(root.glob('*.sql')):
                if path.name >= '008_scope_groups.sql':
                    continue
                con.executescript(path.read_text())
                con.execute('INSERT INTO migrations VALUES (?,?)', (path.name, now()))
            eid = con.execute('INSERT INTO engagements(name,created_at) VALUES (?,?)', ('Old install', now())).lastrowid
            con.execute('INSERT INTO scope_rules(engagement_id,action,target,reason) VALUES (?,?,?,?)', (eid, 'exclude', 'example.com', 'EPT'))
            con.commit()
            con.close()
            migrate()
            with connect() as upgraded:
                rule = dict(upgraded.execute('SELECT * FROM scope_rules').fetchone())
                mode = upgraded.execute('SELECT scope_mode FROM engagements').fetchone()[0]
            self.assertEqual((rule['tag'], rule['hidden'], mode), ('EPT', 1, 'open'))


if __name__ == '__main__':
    unittest.main()
