import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
from vandal.app import app
from vandal.db import connect, migrate, now, dump
from vandal.auth import hasher
from vandal.ingest import queue_import, ingest
from vandal.identity import identity
from vandal.parsers import parse
from vandal.jobs import prepare, scope_targets
from vandal.worker import execute, stop


NMAP = b'''<?xml version="1.0"?><nmaprun args="nmap -sV 192.0.2.1" start="1700000000"><host endtime="1700000010"><status state="up" reason="user-set"/><address addr="192.0.2.1" addrtype="ipv4"/><hostnames><hostname name="www.example.com" type="PTR"/></hostnames><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https" method="table" conf="3"/></port><port protocol="udp" portid="53"><state state="open|filtered"/></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>'''


class PlatformTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.patch = patch.dict(os.environ, {'VANDAL_DATA': self.temp.name, 'VANDAL_WORKER': '0', 'VANDAL_ADMIN_PASSWORD': 'test-password-1234'})
        self.patch.start()
        self.client_ctx = TestClient(app)
        self.client = self.client_ctx.__enter__()
        r = self.client.post('/api/login', json={'name': 'admin', 'password': 'test-password-1234'})
        self.assertEqual(r.status_code, 200)
        self.csrf = self.client.get('/api/session').json()['csrf']
        self.client.headers['X-CSRF-Token'] = self.csrf
        self.eid = self.client.post('/api/engagements', json={'name': 'Test'}).json()['id']
        self.base = f'/api/e/{self.eid}'

    def tearDown(self):
        self.client_ctx.__exit__(None, None, None)
        self.patch.stop()
        self.temp.cleanup()

    def load(self, data=NMAP, name='scan.xml'):
        iid, duplicate = queue_import(self.eid, name, data, 'test')
        if not duplicate:
            ingest(iid)
        return iid

    def test_bulk_exclusions_hide_evidence_and_restore(self):
        iid = self.load()
        self.load(NMAP.replace(b'192.0.2.1', b'198.51.100.1').replace(b'www.example.com', b'other.example.net'), 'other.xml')
        with connect() as con:
            aid = con.execute("SELECT id FROM assets WHERE value='192.0.2.1'").fetchone()[0]
            rid = con.execute('SELECT record_id FROM record_assets WHERE asset_id=?', (aid,)).fetchone()[0]
        self.client.post(self.base+'/findings', json={'title':'Potential CVE-2024-12345', 'asset_ids':[aid], 'evidence':[rid], 'category':'potential CVE'})
        body = {'action':'exclude', 'targets':'192.0.2.1 - 192.0.2.10, blocked.example.org', 'preview':True}
        preview = self.client.post(self.base+'/scope', json=body)
        self.assertEqual(preview.status_code, 200, preview.text)
        self.assertEqual(preview.json()['matched_assets'], 1)
        self.assertEqual(self.client.get(self.base+'/scope').json(), [])
        body['preview'] = False
        result = self.client.post(self.base+'/scope', json=body)
        self.assertEqual(result.status_code, 200, result.text)
        self.assertEqual(self.client.post(self.base+'/scope', json=body).json()['added'], 0)
        for endpoint in ('inventory?mode=ip','assets','dashboard','overview','map','findings','records','facets','imports','timeline'):
            response = self.client.get(self.base+'/'+endpoint)
            self.assertEqual(response.status_code, 200, response.text)
            self.assertNotIn('192.0.2.1', response.text, endpoint)
        self.assertEqual(self.client.get(self.base+'/dashboard').json()['hosts'], 1)
        self.assertEqual(self.client.get(self.base+'/findings').json(), [])
        for endpoint in (f'inventory/{aid}', f'assets/{aid}', f'records/{rid}', f'imports/{iid}/original?download=true'):
            self.assertEqual(self.client.get(self.base+'/'+endpoint).status_code, 404, endpoint)
        for rule in self.client.get(self.base+'/scope').json():
            self.client.delete(self.base+f"/scope/{rule['id']}")
        self.assertEqual(self.client.get(self.base+'/dashboard').json()['hosts'], 2)
        self.assertEqual(self.client.get(self.base+f'/imports/{iid}/original?download=true').content, NMAP)

    def test_mixed_import_raw_is_hidden_and_exclusion_cancels_queue(self):
        host = NMAP[NMAP.index(b'<host '):NMAP.index(b'<runstats>')]
        data = NMAP.replace(b'<runstats>', host.replace(b'192.0.2.1',b'198.51.100.1').replace(b'www.example.com',b'other.example.net') + b'<runstats>')
        iid = self.load(data)
        self.client.post(self.base+'/scope', json={'action':'include','target':'example.com'})
        job = self.client.post(self.base+'/jobs',json={'profile':'dns-validate','targets':['www.example.com']}).json()['id']
        self.client.post(self.base+'/scope',json={'action':'exclude','targets':'192.0.2.1, www.example.com'})
        self.assertEqual(self.client.get(self.base+'/dashboard').json()['hosts'],1)
        self.assertEqual(len(self.client.get(self.base+'/imports').json()),1)
        self.assertEqual(self.client.get(self.base+f'/imports/{iid}/original').status_code,404)
        self.assertNotIn('192.0.2.1', self.client.get(self.base+'/records').text)
        self.assertEqual(self.client.get(self.base+'/jobs').json(),[])
        with connect() as con:
            self.assertEqual(con.execute('SELECT status FROM jobs WHERE id=?',(job,)).fetchone()[0],'cancelled')

    def test_scope_range_validation(self):
        from vandal.scope_rules import parse_targets, matcher
        rules = parse_targets('192.0.2.1-192.0.2.3\n2001:db8::1 - 2001:db8::3; *.Example.COM # comment')
        match = matcher(rules)
        for value in ('192.0.2.1', '192.0.2.3', '2001:db8::2', 'child.example.com'):
            self.assertTrue(match(value))
        for value in ('192.0.2.0','192.0.2.4','2001:db8::4','notexample.com'):
            self.assertFalse(match(value))
        for value in ('192.0.2.3-192.0.2.1', '192.0.2.1-2001:db8::1', ''):
            with self.assertRaises(ValueError): parse_targets(value)

    def test_nmap_hostname_snapshot_and_tuning(self):
        answers = [(2,1,6,'',('192.0.2.1',0)),(2,1,6,'',('192.0.2.2',0))]
        body = {'profile':'nmap-services','targets':['www.example.com'],'add_scope':True,'config':{'port_mode':'top','top_ports':100,'service_detection':'thorough','safe_vulns':True,'vulners':True,'max_rate':50}}
        with patch('vandal.jobs.executable',return_value='/usr/bin/nmap'), patch('vandal.nmap_options.socket.getaddrinfo',return_value=answers):
            preview = self.client.post(self.base+'/jobs/preview',json=body)
            self.assertEqual(preview.status_code,200,preview.text)
            plan = preview.json()
            self.assertEqual(plan['scan_targets'],['192.0.2.1','192.0.2.2'])
            self.assertEqual(plan['resolutions'],{'www.example.com':['192.0.2.1','192.0.2.2']})
            self.assertIn('--script',plan['command'])
            self.assertIn('--top-ports',plan['command'])
            self.assertIn('9',plan['command'])
            self.assertEqual(self.client.get(self.base+'/scope').json(),[])
            body['resolutions'] = plan['resolutions']
            r = self.client.post(self.base+'/jobs',json=body)
            self.assertEqual(r.status_code,200,r.text)
            with connect() as con:
                job = dict(con.execute('SELECT * FROM jobs WHERE id=?',(r.json()['id'],)).fetchone())
            config = json.loads(job['config'])
            self.assertEqual(config['_nmap_snapshot'],plan['resolutions'])
        with patch('vandal.jobs.executable',return_value='/usr/bin/nmap'), patch('vandal.nmap_options.socket.getaddrinfo',return_value=answers[:1]):
            with self.assertRaisesRegex(ValueError,'DNS changed'):
                prepare('nmap-services',['www.example.com'],config,[{'action':'include','target':'example.com'}])
            self.assertEqual(self.client.post(self.base+'/jobs',json=body).status_code,400)
        with patch('vandal.jobs.executable',return_value='/usr/bin/nmap'), patch('vandal.nmap_options.socket.getaddrinfo',return_value=answers):
            self.client.post(self.base+'/scope',json={'action':'exclude','target':'192.0.2.2'})
            self.assertEqual(self.client.post(self.base+'/jobs/preview',json=body).status_code,400)

    def test_nmap_options_reject_invalid_flags(self):
        from vandal.nmap_options import arguments
        for config in ({'ports':'80;id'},{'max_rate':'--script'},{'safe_vulns':'true'},{'service_detection':'off','vulners':True},{'port_mode':'shell'},{'script_timeout':0,'service_scripts':True}):
            with self.assertRaises(ValueError): arguments(config,'80,443')
        self.assertIn('-p-',arguments({'port_mode':'all'},'80'))
        self.assertNotIn('-sV',arguments({'service_detection':'off'},'80'))

    def test_nmap_cve_claims_remain_unconfirmed(self):
        xml = NMAP.replace(b'</port>', b'<script id="vulners" output="CVE-2024-12345 9.8"/></port>',1)
        self.load(xml)
        findings = self.client.get(self.base+'/findings').json()
        self.assertEqual(len(findings),1)
        self.assertEqual(findings[0]['confirmed'],0)
        self.assertEqual(findings[0]['actor'],'nmap')
        self.assertIn('CVE-2024-12345',findings[0]['title'])
        self.load(NMAP.replace(b'</port>',b'<script id="ssl-test" output="NOT VULNERABLE CVE-2024-99999"/></port>',1),'negative.xml')
        self.assertEqual(len(self.client.get(self.base+'/findings').json()),1)

    def test_scan_selection_includes_all_filtered_pages_and_explicit_ids(self):
        self.load(('\n'.join('host%d.example.com'%i for i in range(31))).encode(),'hosts.txt')
        all_rows=self.client.get(self.base+'/scan-targets?q=hostname:example.com&mode=hostname').json()
        self.assertEqual(all_rows['count'],31)
        with connect() as con:
            aid=con.execute("SELECT id FROM assets WHERE value='host0.example.com'").fetchone()[0]
        selected=self.client.get(self.base+f'/scan-targets?ids={aid}&q=hostname:no-match.example.com').json()
        self.assertEqual(selected['targets'],['host0.example.com'])
        self.client.post(self.base+'/scope',json={'action':'exclude','target':'host0.example.com'})
        self.assertEqual(self.client.get(self.base+f'/scan-targets?ids={aid}').status_code,400)
        self.assertEqual(self.client.get(self.base+'/scan-targets?mode=hostname').json()['count'],30)

    def test_http_validation_records_confirm_service_without_version_guess(self):
        self.load(json.dumps({'host':'192.0.2.1','url':'https://192.0.2.1:8443','status_code':401,'title':'Sign in'}).encode(),'http.jsonl')
        inventory=self.client.get(self.base+'/inventory?mode=ip').json()['items']
        service=inventory[0]['services'][0]
        self.assertEqual((service['port'],service['service'],service['evidence']),(8443,'https','probed'))
        self.assertEqual(service['product'],'')

    def test_web_candidates_and_preview_have_no_side_effects(self):
        self.load()
        body={'profile':'gowitness-web','targets':['www.example.com'],'add_scope':True,'config':{'web_defaults':False}}
        with patch('vandal.jobs.executable',return_value='/fake/gowitness'),patch('vandal.jobs.shutil.which',return_value='/fake/chromium'):
            r=self.client.post(self.base+'/jobs/preview',json=body)
            self.assertEqual(r.status_code,200,r.text)
            self.assertEqual({c['url'] for c in r.json()['web_candidates']},{'http://www.example.com:443','https://www.example.com:443'})
        self.assertEqual(self.client.get(self.base+'/jobs').json(),[])
        self.assertEqual(self.client.get(self.base+'/scope').json(),[])

    def test_web_report_exclusions_auth_and_path_checks(self):
        self.load()
        with connect() as con:
            aid=con.execute("SELECT id FROM assets WHERE value='192.0.2.1'").fetchone()[0]
            jid=con.execute("INSERT INTO jobs(engagement_id,profile,actor,command,targets,created_at) VALUES (?,?,?,?,?,?)",(self.eid,'gowitness-web','test','[]',dump(['192.0.2.1']),now())).lastrowid
            wid=con.execute("INSERT INTO web_captures(engagement_id,job_id,asset_id,url,host,ips,status,title,screenshot,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",(self.eid,jid,aid,'http://192.0.2.1:80','192.0.2.1',dump(['192.0.2.1']),'captured','Fixture','../secret.png',now())).lastrowid
        self.assertEqual(self.client.get(self.base+'/web').json()['total'],1)
        self.assertEqual(self.client.get(self.base+f'/web/{wid}/screenshot').status_code,404)
        self.assertIn('Fixture',self.client.get(self.base+f'/web/{wid}').text)
        self.client.post(self.base+'/scope',json={'action':'exclude','target':'192.0.2.0/24'})
        self.assertEqual(self.client.get(self.base+'/web').json()['total'],0)
        self.assertEqual(self.client.get(self.base+f'/web/{wid}').status_code,404)
        self.assertEqual(self.client.get(self.base+'/web?export=true').text,'')
        self.client.post('/api/logout')
        self.assertEqual(self.client.get(self.base+f'/web/{wid}/screenshot').status_code,401)

    def test_web_proxy_blocks_off_target_and_excluded_resolution(self):
        from vandal.web_proxy import ScopeProxy
        proxy=ScopeProxy([{'host':'www.example.com','port':443}],['192.0.2.0/24'])
        try:
            with self.assertRaises(ValueError): proxy.destination('elsewhere.example.com',443)
            with patch('vandal.web_proxy.socket.getaddrinfo',return_value=[(2,1,6,'',('192.0.2.1',443))]):
                with self.assertRaises(ValueError): proxy.destination('www.example.com',443)
        finally: proxy.server_close()

    def test_nmap_preserves_uncertainty_and_raw_download(self):
        iid = self.load()
        assets = self.client.get(self.base+'/assets?state=open').json()
        self.assertEqual(assets['total'], 1)
        self.assertEqual(self.client.get(self.base+'/assets?evidence=probed').json()['total'], 0)
        self.assertEqual(self.client.get(self.base+'/assets?state=open%7Cfiltered').json()['total'], 1)
        self.assertEqual(self.client.get(self.base+f'/imports/{iid}/original?download=true').content, NMAP)
        records = self.client.get(self.base+'/records?q=user-set').json()
        self.assertEqual(records['total'], 1)

    def test_partial_xml_recovers_closed_hosts(self):
        incomplete = NMAP.split(b'<runstats>')[0] + b'<host><address'
        iid = self.load(incomplete)
        item = self.client.get(self.base+'/imports').json()[0]
        self.assertEqual(item['status'], 'partial')
        self.assertEqual(item['record_count'], 3)

    def test_tcpwrapped_is_not_a_confirmed_service(self):
        self.load(NMAP.replace(b'name="https" method="table"', b'name="tcpwrapped" method="probed"'))
        self.assertEqual(self.client.get(self.base+'/assets?evidence=probed').json()['total'],0)
        self.assertEqual(self.client.get(self.base+'/overview').json()['services'],[])

    def test_identity_many_to_many_and_idempotence(self):
        data = '\n'.join(json.dumps(x) for x in [
            {'type':'DNS_NAME','data':'www.example.com','data_json':None,'resolved_hosts':['192.0.2.1','192.0.2.2']},
            {'host':'app.example.com','a':['192.0.2.1'],'resolver':'1.1.1.1','rcode':'NOERROR'},
        ]).encode()
        iid = self.load(data, 'bbot.jsonl')
        self.assertEqual(self.load(data, 'again.jsonl'), iid)
        self.assertEqual(self.client.get(self.base+'/assets').json()['total'], 4)
        self.assertEqual(self.client.get(self.base+'/assets?domain=example.com').json()['total'],4)
        with connect() as con:
            self.assertEqual(con.execute('SELECT count(*) FROM relationships').fetchone()[0], 3)
        self.client.post(self.base+f'/imports/{iid}/archive')
        self.assertEqual(self.client.get(self.base+'/assets').json()['total'], 0)
        self.client.post(self.base+f'/imports/{iid}/restore')
        self.assertEqual(self.client.get(self.base+'/assets').json()['total'], 4)

    def test_domain_primary_filter_keeps_cdn_names_in_associations(self):
        data = '\n'.join(json.dumps(x) for x in [
            {'host':'preview.kohler.co.in','cname':['edge.example.net'],'a':['192.0.2.1']},
            {'host':'other.example.com','cname':['edge.example.net'],'a':['192.0.2.1']},
            {'type':'OPEN_TCP_PORT','data':'192.0.2.1:443','module':'shodan_idb'},
        ]).encode()
        self.load(data, 'cdn.jsonl')
        result = self.client.get(self.base+'/assets?primary=domain&domain=kohler.co.in&has_ports=yes').json()
        self.assertEqual([a['value'] for a in result['items']], ['preview.kohler.co.in'])
        self.assertIn('edge.example.net', [a['value'] for a in result['items'][0]['associated']])
        ips = self.client.get(self.base+'/assets?primary=ip&domain=kohler.co.in').json()
        self.assertEqual([a['value'] for a in ips['items']], ['192.0.2.1'])

    def test_primary_views_preserve_associations_and_passive_provenance(self):
        data = '\n'.join(json.dumps(x) for x in [
            {'type':'DNS_NAME','data':'www.example.com','resolved_hosts':['192.0.2.10','192.0.2.2']},
            {'type':'DNS_NAME','data':'app.example.com','resolved_hosts':['192.0.2.2']},
            {'type':'DNS_NAME','data':'unresolved.example.com'},
            {'type':'OPEN_TCP_PORT','data':'192.0.2.2:443','module':'shodan_idb'},
            {'type':'FINDING','data':{'host':'192.0.2.2','description':'CVE provider hint'},'module':'shodan_idb'},
        ]).encode()
        iid = self.load(data, 'passive.jsonl')
        ips = self.client.get(self.base+'/assets?primary=ip').json()['items']
        self.assertEqual([a['value'] for a in ips], ['192.0.2.2','192.0.2.10'])
        self.assertEqual({a['value'] for a in ips[0]['associated']}, {'app.example.com','www.example.com'})
        self.assertEqual(ips[0]['ports'][0]['evidence'], 'passive')
        self.assertEqual(self.client.get(self.base+'/assets?primary=ip&q=app.example.com').json()['total'], 1)
        domains = self.client.get(self.base+'/assets?primary=domain').json()['items']
        self.assertEqual(len(domains), 3)
        self.assertEqual(next(a for a in domains if a['value']=='unresolved.example.com')['associated'], [])
        filtered = self.client.get(self.base+'/assets?primary=domain&port=443&evidence=passive').json()
        self.assertEqual(filtered['total'], 2)
        self.assertTrue(all(p['owner']=='192.0.2.2' for a in filtered['items'] for p in a['ports']))
        self.assertEqual(self.client.get(self.base+'/findings').json(), [])
        self.client.post(self.base+f'/imports/{iid}/archive')
        self.assertEqual(self.client.get(self.base+'/assets?primary=ip').json()['total'], 0)

    def test_shodan_cves_deduplicate_and_preserve_analyst_edits(self):
        claim = {'type':'FINDING','module':'shodan_idb','data':{'host':'192.0.2.5','cves':['CVE-2024-12345','CVE-2024-12345'],'description':'Potential CVE-2024-12345'}}
        self.load(json.dumps(claim).encode(), 'shodan.jsonl')
        findings = self.client.get(self.base+'/findings').json()
        self.assertEqual(len(findings), 1)
        item = findings[0]
        self.assertEqual(item['confirmed'], 0)
        self.assertEqual(item['category'], 'potential CVE')
        self.assertEqual(len(json.loads(item['asset_ids'])), 1)
        body = {**item, 'notes':'Reviewed manually', 'status':'dismissed', 'confirmed':False,
                'evidence':json.loads(item['evidence']), 'asset_ids':json.loads(item['asset_ids'])}
        self.client.patch(self.base+f'/findings/{item["id"]}', json=body)
        claim['timestamp'] = '2026-09-09T00:00:00Z'
        self.load(json.dumps(claim).encode(), 'shodan-again.jsonl')
        from vandal.interests import backfill
        with connect() as con:
            backfill(con)
            backfill(con)
        findings = self.client.get(self.base+'/findings').json()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['status'], 'dismissed')
        self.assertEqual(findings[0]['notes'], 'Reviewed manually')
        self.assertEqual(len(json.loads(findings[0]['evidence'])), 2)
        claim['module'] = 'other'
        claim['data']['cves'] = ['CVE-2024-99999']
        self.load(json.dumps(claim).encode(), 'other.jsonl')
        self.assertEqual(len(self.client.get(self.base+'/findings').json()), 1)

    def test_observed_ports_filter_tracks_related_and_archived_evidence(self):
        iid = self.load(NMAP)
        self.load(b'192.0.2.99\n', 'seed.txt')
        self.assertEqual(self.client.get(self.base+'/assets?primary=ip&has_ports=yes').json()['total'], 1)
        self.assertEqual(self.client.get(self.base+'/assets?primary=ip&has_ports=no').json()['total'], 1)
        self.assertEqual(self.client.get(self.base+'/assets?primary=domain&has_ports=yes').json()['total'], 1)
        self.client.post(self.base+f'/imports/{iid}/archive')
        self.assertEqual(self.client.get(self.base+'/assets?has_ports=yes').json()['total'], 0)

    def test_quick_scan_scopes_ip_unions_ports_and_deduplicates(self):
        self.load(NMAP.replace(b'portid="443"', b'portid="9443"'))
        asset = self.client.get(self.base+'/assets?primary=ip').json()['items'][0]
        with patch('vandal.jobs.executable', return_value='/usr/bin/nmap'):
            response = self.client.post(self.base+f'/assets/{asset["id"]}/scan')
            self.assertEqual(response.status_code, 200, response.text)
            again = self.client.post(self.base+f'/assets/{asset["id"]}/scan').json()
        self.assertEqual(response.json()['id'], again['id'])
        self.assertTrue(again['existing'])
        job = self.client.get(self.base+'/jobs').json()[0]
        config = json.loads(job['config'])
        self.assertEqual(set(config['ports'].split(',')), {'22','80','443','445','3389','8080','8443','9443'})
        self.assertTrue(config['geolocate'])
        self.assertEqual(json.loads(job['targets']), ['192.0.2.1'])
        self.assertEqual(len(self.client.get(self.base+'/scope').json()), 1)

    def test_quick_scan_respects_exclusions_and_rolls_back_missing_tool(self):
        self.load(NMAP)
        asset = self.client.get(self.base+'/assets?primary=ip').json()['items'][0]
        with patch('vandal.jobs.executable', return_value=None):
            self.assertEqual(self.client.post(self.base+f'/assets/{asset["id"]}/scan').status_code, 400)
        self.assertEqual(self.client.get(self.base+'/scope').json(), [])
        self.client.post(self.base+'/scope', json={'action':'exclude','target':'example.com'})
        self.assertEqual(self.client.post(self.base+f'/assets/{asset["id"]}/scan').status_code, 400)
        self.assertEqual(self.client.get(self.base+'/jobs').json(), [])
        other = self.client.post('/api/engagements', json={'name':'Other'}).json()['id']
        self.assertEqual(self.client.post(f'/api/e/{other}/assets/{asset["id"]}/scan').status_code, 404)

    def test_geolocation_updates_only_requested_engagement(self):
        from vandal.geolocation import locate
        from unittest.mock import MagicMock
        self.load(b'8.8.4.4\n', 'geo.txt')
        reply = MagicMock()
        reply.__enter__.return_value.read.return_value = json.dumps({'success':True,'ip':'8.8.4.4','country':'United States','city':'Example','latitude':37,'longitude':-122}).encode()
        with patch.dict(os.environ, {'VANDAL_GEOIP_CITY':''}), patch('vandal.geolocation.urlopen', return_value=reply) as fetch:
            self.assertEqual(locate(self.eid, '8.8.4.4')['status'], 'completed')
            self.assertEqual(locate(self.eid, '192.0.2.1')['status'], 'skipped')
            self.assertEqual(fetch.call_count, 1)
        asset = self.client.get(self.base+'/assets?primary=ip').json()['items'][0]
        self.assertEqual(asset['geo_source'], 'ipwho.is')
        self.assertEqual(asset['latitude'], 37)

    def test_asset_picker_and_confirmed_map_follow_visibility(self):
        self.load(NMAP)
        options=self.client.get(self.base+'/asset-options',params={'q':'www.example'}).json()
        self.assertEqual(len(options),1)
        hostname=options[0]['id']
        self.assertEqual(self.client.get(self.base+'/asset-options',params={'q':'#'+str(hostname)}).json(),options)
        self.assertEqual(len(self.client.get(self.base+'/asset-options',params={'q':'192.0.2.1'}).json()),1)
        self.assertEqual(self.client.get(self.base+'/dashboard').json()['locations'][0]['confirmed'],0)
        response=self.client.post(self.base+'/findings',json={'title':'Analyst confirmed issue','asset_ids':[hostname],'confirmed':True})
        self.assertEqual(response.status_code,200,response.text)
        item=response.json()
        self.assertEqual(self.client.get(self.base+'/dashboard').json()['locations'][0]['confirmed'],1)
        ip=self.client.get(self.base+'/asset-options',params={'q':'192.0.2.1'}).json()[0]['id']
        for aid in (ip,hostname):
            detail=self.client.get(self.base+'/inventory/'+str(aid)).json()
            self.assertEqual([f['id'] for f in detail['confirmed_findings']],[item['id']])
            self.assertEqual(detail['confirmed_findings'][0]['affected_assets'],[{'id':hostname,'value':'www.example.com'}])
        updated=self.client.patch(self.base+'/findings/'+str(item['id']),json={'title':'Analyst confirmed issue','asset_ids':[hostname],'confirmed':False})
        self.assertEqual(updated.status_code,200,updated.text)
        self.assertEqual(self.client.get(self.base+'/inventory/'+str(ip)).json()['confirmed_findings'],[])
        self.assertEqual(self.client.get(self.base+'/dashboard').json()['locations'][0]['confirmed'],0)
        self.client.post(self.base+'/scope',json={'action':'exclude','targets':'example.com'})
        self.assertEqual(self.client.get(self.base+'/asset-options',params={'q':'www.example'}).json(),[])
        self.assertEqual(self.client.get(self.base+'/asset-options',params={'ids':str(hostname)}).json(),[])

    def test_domain_directory_includes_all_pages_and_respects_visibility(self):
        self.load(('\n'.join(f'www.domain{i:02d}.com' for i in range(30))).encode(), 'domains.txt')
        query={'mode':'hostname','domain_summary':'1'}
        data=self.client.get(self.base+'/inventory',params=query).json()
        self.assertEqual(len(data['items']),25)
        self.assertEqual(len(data['facets']['domain']),30)
        self.assertEqual(len(data['domain_groups']),30)
        self.assertTrue(all(g['hostnames']==1 and g['unscanned']==1 for g in data['domain_groups']))
        self.assertEqual(self.client.post(self.base+'/scope',json={'action':'exclude','targets':'domain29.com'}).status_code,200)
        data=self.client.get(self.base+'/inventory',params=query).json()
        self.assertEqual(len(data['domain_groups']),29)
        self.assertNotIn('domain29.com',str(data))
        data=self.client.get(self.base+'/inventory',params={**query,'q':'hostname:domain28.com'}).json()
        self.assertEqual([g['domain'] for g in data['domain_groups']],['domain28.com'])

    def test_domain_directory_deduplicates_ips_and_counts_coverage(self):
        self.load(NMAP)
        self.load(b'{"type":"DNS_NAME","data":"other.example.com","resolved_hosts":["192.0.2.1"]}', 'alias.jsonl')
        self.load(b'pending.example.com', 'pending.txt')
        result=self.client.get(self.base+'/inventory',params={'mode':'hostname','domain_summary':'1'}).json()
        group=result['domain_groups'][0]
        self.assertEqual(group,{'domain':'example.com','hostnames':3,'ips':1,'with_ports':2,'scanned':2,'passive':0,'unscanned':1})

    def test_hide_passive_filters_results_facets_and_preserves_confirmation(self):
        self.load(NMAP)
        self.load(b'{"type":"OPEN_TCP_PORT","data":"192.0.2.1:9999","module":"shodan_idb"}\n{"type":"OPEN_TCP_PORT","data":"192.0.2.99:8888","module":"shodan_idb"}', 'passive.jsonl')
        aid=self.client.get(self.base+'/inventory',params={'q':'ip:192.0.2.99'}).json()['items'][0]['id']
        finding=self.client.post(self.base+'/findings',json={'title':'CVE-2024-12345','asset_ids':[aid],'category':'potential CVE'}).json()['id']
        with connect() as con:
            con.execute("UPDATE interests SET source_key='shodan:192.0.2.99:CVE-2024-12345' WHERE id=?",(finding,))
        base=self.client.get(self.base+'/inventory').json()
        self.assertEqual(base['total'],2)
        query={'hide_passive':'1','sort':'open_ports'}
        data=self.client.get(self.base+'/inventory',params=query).json()
        self.assertEqual(data['total'],1)
        self.assertEqual(data['facets']['port'],[[443,1]])
        self.assertEqual(data['facets']['cve'],[])
        self.assertFalse(any('shodan' in s[0] for s in data['facets']['source']))
        self.assertEqual(self.client.get(self.base+'/inventory',params={**query,'q':'port:9999'}).json()['total'],0)
        self.assertEqual(self.client.get(self.base+'/findings',params=query).json(),[])
        self.client.patch(self.base+'/findings/'+str(finding),json={'title':'CVE-2024-12345','asset_ids':[aid],'confirmed':True})
        self.assertEqual(self.client.get(self.base+'/inventory',params=query).json()['total'],2)
        self.assertEqual(len(self.client.get(self.base+'/findings',params=query).json()),1)
        self.assertEqual(self.client.get(self.base+'/inventory').json()['facets']['port'],base['facets']['port'])

    def test_cve_facet_includes_all_and_sorts_by_highest_score(self):
        self.load(NMAP)
        aid=self.client.get(self.base+'/inventory').json()['items'][0]['id']
        for i in range(10):
            cve=f'CVE-2024-{1000+i}'
            self.client.post(self.base+'/findings',json={'title':cve,'asset_ids':[aid]})
            if i<9:
                with connect() as con:
                    con.execute("INSERT OR REPLACE INTO enrichment(kind,key,status,result) VALUES ('cve',?,'completed',?)",(cve,json.dumps({'scores':[{'baseScore':0},{'baseScore':i}]})))
        result=self.client.get(self.base+'/inventory').json()
        self.assertEqual(len(result['facets']['cve']),10)
        self.assertEqual(result['facets']['cve'][0][0],'CVE-2024-1008')
        self.assertEqual(result['facets']['cve'][-1][0],'CVE-2024-1009')
        self.assertEqual(result['cve_scores']['CVE-2024-1000'],0)

    def test_inventory_ports_are_open_only_and_sort_by_unique_open_ports(self):
        self.load(NMAP)
        self.load(NMAP.replace(b'192.0.2.1',b'192.0.2.2').replace(b'www.example.com',b'two.example.com').replace(b'open|filtered',b'open'),'two.xml')
        self.load(NMAP.replace(b'192.0.2.1',b'192.0.2.3').replace(b'www.example.com',b'three.example.com').replace(b'state="open"',b'state="closed"'),'closed.xml')
        query=lambda q:self.client.get(self.base+'/inventory',params={'mode':'ip','q':q}).json()
        self.assertEqual(query('port:443')['total'],2)
        self.assertEqual(query('port:53')['total'],1)
        self.assertEqual(query('-port:443')['total'],1)
        items=self.client.get(self.base+'/inventory',params={'mode':'ip','sort':'open_ports'}).json()['items']
        self.assertEqual([a['value'] for a in items],['192.0.2.2','192.0.2.1','192.0.2.3'])
        # Historical open evidence must not match after a later closed observation.
        self.load(NMAP.replace(b'1700000010',b'1800000010').replace(b'state="open"',b'state="closed"'),'later.xml')
        self.assertEqual(query('ip:192.0.2.1 port:443')['total'],0)
        self.assertEqual(query('ip:192.0.2.1 -port:443')['total'],1)

    def test_inventory_search_summary_and_same_observation_filters(self):
        self.load(NMAP)
        self.load(b'{"type":"OPEN_TCP_PORT","data":"192.0.2.1:443","module":"shodan_idb"}', 'passive.jsonl')
        self.load(b'192.0.2.99\n', 'extra.txt')
        r = self.client.get(self.base+'/inventory',params={'q':'hostname:example.com port:443 scanned:true'}).json()
        self.assertEqual(r['total'],1)
        a=r['items'][0]
        https=[s for s in a['services'] if s['port']==443]
        self.assertEqual(len(https),1)
        self.assertEqual(https[0]['count'],2)
        self.assertNotEqual(https[0]['evidence'],'passive')
        self.assertEqual(self.client.get(self.base+'/inventory',params={'q':'port:53 service:https'}).json()['total'],0)
        self.assertEqual(self.client.get(self.base+'/inventory',params={'q':'-port:443'}).json()['total'],1)
        self.assertEqual(self.client.get(self.base+'/inventory',params={'q':'scanned:false'}).json()['total'],1)
        self.assertEqual(self.client.get(self.base+'/inventory',params={'q':'madeup:value'}).status_code,400)
        self.assertEqual(self.client.get(self.base+'/inventory',params={'q':'country:"unfinished'}).status_code,400)
        detail=self.client.get(self.base+f'/inventory/{a["id"]}').json()
        self.assertIn('banner',detail['services'][0])
        self.assertEqual(self.client.get(self.base+'/dashboard').json()['hosts'],2)

    def test_inventory_does_not_copy_virtual_host_ports_to_ip(self):
        self.load(b'{"type":"DNS_NAME","data":"www.example.com","resolved_hosts":["192.0.2.1"]}\n{"type":"OPEN_TCP_PORT","data":"www.example.com:9443","module":"shodan_idb"}', 'host.jsonl')
        ip=self.client.get(self.base+'/inventory').json()['items'][0]
        self.assertEqual(ip['services'],[])
        domain=self.client.get(self.base+'/inventory',params={'mode':'hostname','q':'hostname:example.com port:9443'}).json()
        self.assertEqual(domain['total'],1)

    def test_scan_preview_scope_additions_are_explicit_and_transactional(self):
        body={'profile':'nmap-services','targets':['192.0.2.4'],'config':{},'add_scope':True}
        with patch('vandal.jobs.executable',return_value='/usr/bin/nmap'):
            preview=self.client.post(self.base+'/jobs/preview',json=body)
            self.assertEqual(preview.status_code,200)
            self.assertEqual(preview.json()['scope_additions'],['192.0.2.4'])
            self.assertEqual(self.client.get(self.base+'/scope').json(),[])
            self.assertEqual(self.client.post(self.base+'/jobs',json=body).status_code,200)
        self.assertEqual(len(self.client.get(self.base+'/scope').json()),1)

    def test_enrichment_queue_is_cached_and_excludes_private_addresses(self):
        from vandal.enrichment import enqueue, process_one
        self.load(b'8.8.4.4\n192.0.2.1\n', 'geo-seeds.txt')
        with connect() as con:
            enqueue(con);enqueue(con)
            self.assertEqual(con.execute("SELECT count(*) FROM enrichment WHERE kind='geo'").fetchone()[0],2)
            self.assertEqual(con.execute("SELECT status FROM enrichment WHERE key='192.0.2.1'").fetchone()[0],'skipped')
        result={'status':'completed','source':'fixture','response':{'country':'Test','city':'City','latitude':10,'longitude':20}}
        with patch('vandal.enrichment.locate',return_value=result) as lookup:
            self.assertTrue(process_one('geo'))
            self.assertFalse(process_one('geo'))
            self.assertEqual(lookup.call_count,1)
        asset=self.client.get(self.base+'/inventory',params={'q':'ip:8.8.4.4'}).json()['items'][0]
        self.assertEqual(asset['latitude'],10)

    def test_cve_metadata_queue_does_not_confirm_findings(self):
        from vandal.enrichment import enqueue, process_one
        self.load(b'{"type":"FINDING","module":"shodan_idb","data":{"host":"192.0.2.1","cves":["CVE-2024-12345"]}}','cve.jsonl')
        with connect() as con:enqueue(con)
        data={'id':'CVE-2024-12345','description':'Example','scores':[]}
        with patch('vandal.enrichment.fetch_cve',return_value=data):self.assertTrue(process_one('cve'))
        r=self.client.get(self.base+'/cves/CVE-2024-12345').json()
        self.assertEqual(r['status'],'completed')
        self.assertEqual(json.loads(r['result'])['description'],'Example')
        self.assertEqual(self.client.get(self.base+'/findings').json()[0]['confirmed'],0)
        other=self.client.post('/api/engagements',json={'name':'Other'}).json()['id']
        self.assertEqual(self.client.get(f'/api/e/{other}/cves/CVE-2024-12345').status_code,404)

    def test_hostname_first_uses_only_unnamed_ips_as_fallback(self):
        self.load(b'{"type":"DNS_NAME","data":"www.example.com","resolved_hosts":["192.0.2.1"]}', 'names.jsonl')
        self.load(b'192.0.2.1\n192.0.2.2\n2001:db8::1\nunresolved.example.com\n', 'seeds.txt')
        result=self.client.get(self.base+'/inventory',params={'mode':'auto'}).json()
        self.assertEqual([a['value'] for a in result['items']],['unresolved.example.com','www.example.com','192.0.2.2','2001:db8::1'])
        self.assertEqual(self.client.get(self.base+'/inventory',params={'mode':'ip'}).json()['total'],3)
        self.assertEqual(self.client.get(self.base+'/inventory',params={'mode':'auto','q':'hostname:other.example.com'}).json()['total'],0)

    def test_unsupported_record_and_xss_are_retained(self):
        self.load(b'{"custom":"<script>alert(1)</script>"}', 'custom.json')
        records = self.client.get(self.base+'/records').json()
        self.assertEqual(records['items'][0]['kind'], 'unmapped')
        detail = self.client.get(self.base+'/records/'+str(records['items'][0]['id'])).json()
        self.assertIn('<script>', detail['raw'])
        self.assertEqual(self.client.get('/').headers['X-Content-Type-Options'], 'nosniff')

    def test_entity_expansion_is_rejected(self):
        data=b'<!DOCTYPE nmaprun [<!ENTITY x SYSTEM "file:///etc/passwd">]><nmaprun>&x;</nmaprun>'
        self.load(data)
        self.assertEqual(self.client.get(self.base+'/imports').json()[0]['status'], 'failed')
        self.assertEqual(self.client.get(self.base+'/records').json()['total'], 0)

    def test_summary_nessus_has_no_invented_ports(self):
        data=b'<html><div style="font-size: 22px">192.0.2.1</div><table><tr class="plugin-row"><td></td><td>High</td><td></td><td>8.1</td><td></td><td>4</td><td></td><td>0.1</td><td></td><td>123</td><td>Interesting issue</td></tr></table></html>'
        self.load(data, 'nessus.html')
        self.assertEqual(self.client.get(self.base+'/records').json()['total'], 1)
        self.assertEqual(self.client.get(self.base+'/assets?port=443').json()['total'], 0)
        self.assertEqual(self.client.get(self.base+'/findings').json(), [])

    def test_findings_require_explicit_confirmation_and_scoped_evidence(self):
        self.load()
        rid=self.client.get(self.base+'/records').json()['items'][0]['id']
        r=self.client.post(self.base+'/findings',json={'title':'Interesting listener','evidence':[rid]})
        self.assertEqual(r.status_code,200)
        item=self.client.get(self.base+'/findings').json()[0]
        self.assertEqual(item['confirmed'],0)
        r=self.client.post(self.base+'/findings',json={'title':'Missing evidence','evidence':[99999]})
        self.assertEqual(r.status_code,404)

    def test_csrf_and_membership_boundaries(self):
        self.client.headers.pop('X-CSRF-Token')
        self.assertEqual(self.client.post(self.base+'/scope',json={'target':'example.com','action':'include'}).status_code,403)
        with connect() as con:
            con.execute("INSERT INTO users(name,password,role) VALUES ('viewer',?,'viewer')",(hasher.hash('viewer-password-123'),))
        self.client.post('/api/login',json={'name':'viewer','password':'viewer-password-123'})
        self.assertEqual(self.client.get(self.base+'/assets').status_code,403)

    def test_job_is_logged_before_launch_and_queued_cancel(self):
        self.client.post(self.base+'/scope',json={'action':'include','target':'example.com'})
        self.client.post(self.base+'/scope',json={'action':'exclude','target':'no.example.com'})
        r=self.client.post(self.base+'/jobs',json={'profile':'dns-validate','targets':['www.example.com','no.example.com']})
        self.assertEqual(r.status_code,200,r.text)
        jid=r.json()['id'];job=self.client.get(self.base+'/jobs').json()[0]
        self.assertEqual(job['status'],'queued')
        self.assertEqual(json.loads(job['targets']),['www.example.com'])
        self.assertEqual(json.loads(job['excluded']),[])
        with connect() as con:
            self.assertEqual(len(json.loads(con.execute('SELECT excluded FROM jobs WHERE id=?',(jid,)).fetchone()[0])),1)
        self.assertIn(str(jid),job['command'])
        self.client.post(self.base+f'/jobs/{jid}/cancel')
        self.assertEqual(self.client.get(self.base+'/timeline').json()[0]['status'],'cancelled')

    def test_worker_logs_and_ingests_fixture_process(self):
        with connect() as con:
            jid=con.execute('INSERT INTO jobs(engagement_id,profile,actor,command,targets,config,created_at,status) VALUES (?,?,?,?,?,?,?,?)',(self.eid,'dns-validate','test','[]','["www.example.com"]','{}',now(),'running')).lastrowid
            job=dict(con.execute('SELECT * FROM jobs WHERE id=?',(jid,)).fetchone())
        output=Path(self.temp.name)/'jobs'/str(jid)/'output.jsonl'
        script=Path(self.temp.name)/'fixture.py'
        script.write_text(f'import pathlib\nprint("fixture execution")\npathlib.Path({str(output)!r}).write_text(\'{json.dumps({"host":"www.example.com","a":["192.0.2.1"],"rcode":"NOERROR"})}\\n\')\n')
        plan={'command':[sys.executable,str(script)],'targets':['www.example.com'],'excluded':[]}
        with patch('vandal.worker.prepare',return_value=plan):
            execute(job)
        job=self.client.get(self.base+'/jobs').json()[0]
        self.assertEqual(job['status'],'completed',job)
        self.assertEqual(len(json.loads(job['import_ids'])),1)
        self.assertIn('fixture execution',self.client.get(self.base+f'/jobs/{jid}/logs').json()['text'])
        self.assertEqual(self.client.get(self.base+'/assets').json()['total'],2)

    def test_running_job_cancellation_retains_logs_and_status(self):
        with connect() as con:
            jid=con.execute('INSERT INTO jobs(engagement_id,profile,actor,command,targets,config,created_at,status) VALUES (?,?,?,?,?,?,?,?)',(self.eid,'dns-validate','test','[]','["www.example.com"]','{}',now(),'running')).lastrowid
            job=dict(con.execute('SELECT * FROM jobs WHERE id=?',(jid,)).fetchone())
        script=Path(self.temp.name)/'wait.py'
        script.write_text('import time\nprint("started",flush=True)\ntime.sleep(60)\n')
        def cancel_after_start():
            log=Path(self.temp.name)/'jobs'/str(jid)/'stdout.log'
            for _ in range(100):
                if log.exists() and 'started' in log.read_text():
                    break
                time.sleep(.05)
            with connect() as con:
                con.execute('UPDATE jobs SET cancel_requested=1 WHERE id=?',(jid,))
        thread=threading.Thread(target=cancel_after_start)
        thread.start()
        with patch('vandal.worker.prepare',return_value={'command':[sys.executable,str(script)],'targets':['www.example.com'],'excluded':[]}):
            execute(job)
        thread.join()
        job=self.client.get(self.base+'/jobs').json()[0]
        self.assertEqual(job['status'],'cancelled')
        self.assertIsNotNone(job['ended_at'])
        self.assertIn('started',self.client.get(self.base+f'/jobs/{jid}/logs').json()['text'])

    def test_timeline_redacts_imported_credentials(self):
        self.load(NMAP.replace(b'nmap -sV 192.0.2.1', b'nmap --script-args password=example-secret -sV 192.0.2.1'))
        self.assertNotIn('example-secret',self.client.get(self.base+'/timeline').text)
        self.assertIn('[REDACTED]',self.client.get(self.base+'/timeline?export=csv').text)


if __name__=='__main__':
    unittest.main()
