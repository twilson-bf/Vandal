"""Current-state acceptance checks use imported fixtures only; no network scans."""
import json
import unittest
from tests import test_platform as fixtures
from vandal.db import connect


class ProjectionTests(unittest.TestCase):
    setUp = fixtures.PlatformTests.setUp
    tearDown = fixtures.PlatformTests.tearDown
    load = fixtures.PlatformTests.load

    def dns(self, ips, at, rcode='NOERROR', **extra):
        self.load(json.dumps({'host':'www.example.com','a':ips,'query_type':'A',
                             'rcode':rcode,'resolver':'fixture','timestamp':at,**extra}).encode(), 'dns-'+at+'.json')

    def scan(self, ip='192.0.2.1', state='open', at='1700000010'):
        self.load(fixtures.NMAP.replace(b'192.0.2.1',ip.encode()).replace(b'1700000010',at.encode())
                  .replace(b'state="open"',f'state="{state}"'.encode()),ip+at+state+'.xml')

    def hosts(self, **params):
        response=self.client.get(self.base+'/hosts',params={'mode':'auto',**params})
        self.assertEqual(response.status_code,200,response.text)
        return response.json()

    def host(self):
        return next(a for a in self.hosts()['items'] if a['value']=='www.example.com')

    def test_current_addresses_replace_old_mapping_without_losing_history(self):
        self.scan()
        self.dns(['192.0.2.1'],'2025-01-01T00:00:00Z')
        aid=self.host()['id']
        self.scan('192.0.2.2',state='closed')
        self.dns(['192.0.2.2'],'2025-02-01T00:00:00Z')
        host=self.host()
        self.assertEqual(host['id'],aid)
        self.assertEqual(host['address_view']['primary_ip'],'192.0.2.2')
        self.assertEqual(host['open_port_count'],0)
        detail=self.client.get(self.base+'/hosts/'+str(aid)).json()
        self.assertTrue(any(h['owner']=='192.0.2.1' and h['reason']=='Previous hostname address' for h in detail['service_history']))
        # Upload order cannot make an older DNS answer current again.
        self.dns(['192.0.2.1'],'2024-01-01T00:00:00Z')
        self.assertEqual(self.host()['address_view']['primary_ip'],'192.0.2.2')

    def test_multi_address_ports_group_without_invented_banner(self):
        self.scan()
        self.scan('192.0.2.2',state='closed')
        self.dns(['192.0.2.2','192.0.2.1'],'2025-01-01T00:00:00Z')
        host=self.host()
        self.assertEqual(len(host['address_view']['addresses']),2)
        self.assertEqual(len(host['services']),2)  # TCP/443 and UDP/53, once each.
        https=next(s for s in host['services'] if s['port']==443)
        self.assertEqual(len(https['variants']),2)
        self.assertTrue(https['conflict'])
        self.assertEqual(host['open_port_count'],1)
        self.assertEqual(self.hosts()['total'],1)

    def test_failed_validation_retains_mapping_and_reports_staleness(self):
        self.dns(['192.0.2.1'],'2025-01-01T00:00:00Z')
        self.dns([],'2025-02-01T00:00:00Z',rcode='Timeout',error='fixture timeout')
        host=self.host()
        self.assertEqual(host['address_view']['primary_ip'],'192.0.2.1')
        self.assertEqual(host['address_view']['status'],'stale')
        detail=self.client.get(self.base+'/hosts/'+str(host['id'])).json()
        self.assertEqual(detail['address_view']['history'][0]['status'],'validation failed')

    def test_empty_validated_answer_removes_current_mapping(self):
        self.dns(['192.0.2.1'],'2025-01-01T00:00:00Z')
        self.dns([],'2025-02-01T00:00:00Z',rcode='NODATA')
        self.assertEqual(self.host()['address_view']['addresses'],[])

    def test_validation_failure_is_tracked_per_address_family(self):
        self.dns(['192.0.2.1'],'2025-01-01T00:00:00Z')
        self.dns([],'2025-02-01T00:00:00Z',rcode='Timeout',error='fixture timeout')
        self.dns([],'2025-03-01T00:00:00Z',query_type='AAAA',aaaa=['2001:db8::1'])
        view=self.host()['address_view']
        self.assertEqual(view['status'],'stale')
        self.assertEqual({p['value'] for p in view['addresses']},{'192.0.2.1','2001:db8::1'})

    def test_unassigned_analyst_items_remain_browsable(self):
        fid=self.client.post(self.base+'/findings',json={'title':'Interesting certificate','notes':'Investigate issuer','asset_ids':[]}).json()['id']
        data=self.client.get(self.base+'/host-vulnerabilities',params={'state':'interests'}).json()
        self.assertEqual(data['items'][0]['value'],'Unassigned items')
        self.assertEqual(data['items'][0]['other_findings'][0]['id'],fid)
        self.assertEqual(self.client.get(self.base+'/host-vulnerabilities',params={'state':'confirmed'}).json()['total'],0)

    def test_active_winner_excludes_old_and_passive_search_matches(self):
        self.scan()
        self.dns(['192.0.2.1'],'2025-01-01T00:00:00Z')
        self.scan(state='closed',at='1800000010')
        self.load(b'{"type":"OPEN_TCP_PORT","data":"192.0.2.1:443","module":"shodan_idb","timestamp":"2030-01-01T00:00:00Z"}', 'passive.jsonl')
        self.assertEqual(self.hosts(q='hostname:www.example.com port:443')['total'],0)
        host=self.host()
        detail=self.client.get(self.base+'/hosts/'+str(host['id'])).json()
        self.assertTrue(any(r['evidence']=='passive' and not r['current'] for r in detail['service_history']))
        self.assertEqual(host['open_port_count'],0)

    def test_cves_group_claims_without_rewriting_analyst_decisions(self):
        self.dns(['192.0.2.1'],'2025-01-01T00:00:00Z')
        aid=self.host()['id'];ids=[]
        for actor,confirmed in [('analyst',True),('nmap',False),('shodan',False)]:
            fid=self.client.post(self.base+'/findings',json={'title':'CVE-2025-12345','asset_ids':[aid],'confirmed':confirmed,'notes':actor}).json()['id'];ids.append(fid)
            with connect() as con:
                con.execute('UPDATE interests SET source_key=?,actor=? WHERE id=?',(None if actor=='analyst' else actor+':www.example.com:CVE-2025-12345',actor,fid))
        host=self.host()
        self.assertEqual(len(host['vulnerabilities']),1)
        self.assertEqual(len(host['vulnerabilities'][0]['claims']),2)
        self.assertEqual(host['confirmed'],1)
        detail=self.client.get(self.base+'/hosts/'+str(aid)).json()
        self.assertEqual([f['id'] for f in detail['finding_history']],[ids[-1]])
        self.assertEqual(len(self.client.get(self.base+'/findings').json()),3)
        self.assertEqual(self.client.get(self.base+'/host-vulnerabilities').json()['cve_pairs'],1)

    def test_pagination_facets_export_and_stable_ids(self):
        self.load(('\n'.join('host%03d.example.com'%n for n in range(63))).encode(),'hosts.txt')
        page1=self.hosts(size=50);page2=self.hosts(size=50,page=2)
        self.assertEqual(len(page1['items']),50)
        self.assertEqual(len(page2['items']),13)
        self.assertFalse(set(a['id'] for a in page1['items']) & set(a['id'] for a in page2['items']))
        self.assertEqual(page1['facets']['domain'],[['example.com',63]])
        self.assertEqual(self.hosts(q='source:seed-list')['total'],63)
        exported=self.client.get(self.base+'/hosts-export',params={'q':'hostname:example.com'}).text
        self.assertEqual(len(exported.splitlines()),64)
        self.client.post(self.base+'/scope',json={'action':'exclude','targets':'host062.example.com'})
        self.assertEqual(self.hosts()['total'],62)
        self.assertNotIn('host062',self.client.get(self.base+'/hosts-export').text)

    def test_current_dashboard_counts_use_the_host_projection(self):
        self.scan();self.dns(['192.0.2.1'],'2025-01-01T00:00:00Z')
        data=self.client.get(self.base+'/dashboard',params={'view':'current'}).json()
        self.assertEqual(data['hosts'],self.hosts()['total'])
        self.assertEqual(data['services'],1)
        self.assertEqual(data['addresses'],1)

    def test_projection_reads_do_not_change_evidence_or_decisions(self):
        self.scan();self.dns(['192.0.2.1'],'2025-01-01T00:00:00Z')
        def snapshot():
            with connect() as con:
                return {t:[tuple(r) for r in con.execute('SELECT * FROM '+t+' ORDER BY id')] for t in ('assets','records','relationships','observations','interests')}
        before=snapshot()
        self.hosts();self.client.get(self.base+'/host-vulnerabilities');self.client.get(self.base+'/dashboard?view=current')
        self.assertEqual(snapshot(),before)
