"""Reverse DNS validation without live DNS or external process activity."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from vandal.db import connect, migrate, now
from vandal.ingest import ingest, queue_import
from vandal.jobs import prepare
from vandal.parsers import parse
from vandal.probes import reverse_validate
from vandal.projection import build


class TextValue:
    def __init__(self, value): self.value = value
    def to_text(self): return self.value


class Response:
    def to_text(self): return 'fixture DNS response'


class Answer:
    def __init__(self, values):
        self.values = [TextValue(value) for value in values]
        self.rrset = self if values else None
        self.ttl = 300
        self.response = Response()
    def __iter__(self): return iter(self.values)


class Resolver:
    def resolve(self, name, record_type, raise_on_no_answer=False):
        if record_type == 'PTR':
            return Answer(['confirmed.example.com.', 'stale.example.net.'])
        if name == 'confirmed.example.com' and record_type == 'A':
            return Answer(['192.0.2.10'])
        if name == 'stale.example.net' and record_type == 'A':
            return Answer(['198.51.100.7'])
        return Answer([])


class ReverseDnsTests(unittest.TestCase):
    def test_profile_accepts_ips_and_builds_multi_resolver_command(self):
        plan = prepare('reverse-dns', ['192.0.2.10'], {'resolvers':['1.1.1.1','9.9.9.9']}, [], '/tmp/reverse-job')
        self.assertEqual(plan['targets'], ['192.0.2.10'])
        self.assertEqual(plan['command'][-2:], ['--resolvers', '1.1.1.1,9.9.9.9'])
        with self.assertRaisesRegex(ValueError, 'individual IP'):
            prepare('reverse-dns', ['host.example.com'], {}, [], '/tmp/reverse-job')
        with self.assertRaisesRegex(ValueError, 'supported reverse DNS resolver'):
            prepare('reverse-dns', ['192.0.2.10'], {'resolvers':[]}, [], '/tmp/reverse-job')

    def test_probe_classifies_confirmed_and_mismatched_ptr_names(self):
        with tempfile.TemporaryDirectory() as folder:
            targets, output = Path(folder)/'targets.txt', Path(folder)/'output.jsonl'
            targets.write_text('192.0.2.10\n')
            with patch('vandal.probes.resolver_at', return_value=Resolver()):
                reverse_validate(targets, output, ('1.1.1.1','8.8.8.8'))
            records = [json.loads(line) for line in output.read_text().splitlines()]
        self.assertEqual(len(records), 2)
        self.assertTrue(all(record['status'] == 'confirmed' for record in records))
        states = {item['hostname']:item['status'] for item in records[0]['forward']}
        self.assertEqual(states, {'confirmed.example.com':'confirmed', 'stale.example.net':'forward-mismatch'})
        self.assertEqual(records[0]['confirmed_names'], ['confirmed.example.com'])

    def test_parser_and_projection_promote_only_forward_confirmed_name(self):
        record = {
            'host':'192.0.2.10', 'resolver':'fixture', 'query_type':'PTR', 'rcode':'NOERROR',
            'timestamp':'2026-01-01T00:00:00Z', 'status':'confirmed',
            'ptr':['confirmed.example.com','stale.example.net'],
            'confirmed_names':['confirmed.example.com'],
            'forward':[
                {'hostname':'confirmed.example.com','status':'confirmed','addresses':['192.0.2.10']},
                {'hostname':'stale.example.net','status':'forward-mismatch','addresses':['198.51.100.7']},
            ],
        }
        parsed = parse(json.dumps(record).encode(), 'reverse.jsonl')
        links = set(parsed.records[0]['links'])
        self.assertIn(('confirmed.example.com','192.0.2.10','resolves-to'), links)
        self.assertNotIn(('stale.example.net','198.51.100.7','resolves-to'), links)
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {'VANDAL_DATA':folder}):
            migrate()
            with connect() as con:
                eid = con.execute('INSERT INTO engagements(name,created_at) VALUES (?,?)', ('Fixture',now())).lastrowid
            iid, _ = queue_import(eid, 'reverse.jsonl', json.dumps(record).encode(), 'test')
            ingest(iid)
            with connect() as con:
                hosts = {item['value']:item for item in build(con,eid)}
            self.assertEqual(hosts['confirmed.example.com']['address_view']['primary_ip'], '192.0.2.10')
            self.assertIsNone(hosts['stale.example.net']['address_view']['primary_ip'])
            self.assertEqual(hosts['stale.example.net']['address_view']['history'][0]['status'], 'reverse-name only')


if __name__ == '__main__':
    unittest.main()
