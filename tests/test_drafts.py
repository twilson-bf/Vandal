"""Draft and DNS-entry acceptance tests; all network/process activity is mocked."""
import json
import socket
import unittest
from unittest.mock import patch

from tests import test_platform as fixtures
from vandal.db import migrate


class DraftTests(unittest.TestCase):
    setUp = fixtures.PlatformTests.setUp
    tearDown = fixtures.PlatformTests.tearDown
    load = fixtures.PlatformTests.load

    def payload(self):
        return {'profile':'nmap-services','targets':['WWW.Example.com.'],'config':{},'add_scope':True}

    def save(self, **updates):
        body={'title':'Investigate host','payload':self.payload(),'command':'review text only','notes':'Operator notes',**updates}
        response=self.client.post(self.base+'/scan-drafts',json=body)
        self.assertEqual(response.status_code,200,response.text)
        return response.json(),body

    def test_offline_draft_survives_missing_tool_without_dns_or_scope_writes(self):
        with patch('socket.getaddrinfo',side_effect=AssertionError('DNS called')),patch('vandal.drafts.executable',return_value=None):
            response=self.client.post(self.base+'/scan-drafts/preview',json=self.payload())
        self.assertEqual(response.status_code,200,response.text)
        data=response.json()
        self.assertIn('nmap',data['command'])
        self.assertEqual(data['payload']['targets'],['WWW.Example.com.'])
        self.assertIn('not installed',' '.join(data['warnings']))
        self.assertFalse(data['executable'])
        self.assertEqual(self.client.get(self.base+'/jobs').json(),[])
        self.assertEqual(self.client.get(self.base+'/scope').json(),[])

    def test_invalid_options_are_warnings_without_losing_identifiers(self):
        body={**self.payload(),'config':{'ports':'invalid'}}
        data=self.client.post(self.base+'/scan-drafts/preview',json=body).json()
        self.assertIn('options need correction',data['command'])
        self.assertEqual(data['payload']['targets'],body['targets'])

    def test_invalid_identifiers_do_not_break_listing_and_bad_profiles_are_rejected(self):
        result,_=self.save(payload={**self.payload(),'targets':['http://[']})
        self.client.post(self.base+'/scope',json={'action':'exclude','target':'example.com'})
        self.assertEqual(self.client.get(self.base+'/scan-drafts').json()[0]['id'],result['id'])
        for profile in (None,[],{}):
            self.assertEqual(self.client.post(self.base+'/scan-drafts/preview',json={**self.payload(),'profile':profile}).status_code,400)

    def test_timeline_uses_each_revisions_profile(self):
        result,body=self.save()
        update={**body,'payload':{**body['payload'],'profile':'dns-validate'},'base_revision':1}
        self.assertEqual(self.client.put(self.base+'/scan-drafts/'+str(result['id']),json=update).status_code,200)
        events=[e for e in self.client.get(self.base+'/timeline').json() if e['type']=='draft']
        self.assertEqual({e['revision']:e['profile'] for e in events},{1:'nmap-services',2:'dns-validate'})

    def test_revisions_preserve_text_and_reject_stale_updates(self):
        result,body=self.save()
        did=result['id']
        update={**body,'command':'edited review text; never executed','base_revision':1}
        response=self.client.put(self.base+f'/scan-drafts/{did}',json=update)
        self.assertEqual(response.json()['revision'],2)
        self.assertEqual(self.client.put(self.base+f'/scan-drafts/{did}',json=update).status_code,409)
        detail=self.client.get(self.base+f'/scan-drafts/{did}').json()
        self.assertEqual([r['command'] for r in detail['revisions']],[update['command'],body['command']])
        self.assertEqual(detail['payload']['targets'],body['payload']['targets'])
        self.assertEqual(self.client.get(self.base+'/jobs').json(),[])

    def test_drafts_do_not_enter_executor_and_validation_failure_is_retained(self):
        with patch('vandal.jobs.executable',return_value='/usr/bin/nmap'),patch('socket.getaddrinfo',side_effect=socket.gaierror('fixture lookup failure')):
            response=self.client.post(self.base+'/jobs/preview',json=self.payload())
        self.assertEqual(response.status_code,400)
        result,_=self.save(validation_error=response.json()['detail'])
        detail=self.client.get(self.base+'/scan-drafts/'+str(result['id'])).json()
        self.assertIn('fixture lookup failure',' '.join(detail['warnings']))
        self.assertEqual(self.client.post(self.base+'/jobs',json={**self.payload(),'command':'edited command'}).status_code,400)
        self.assertEqual(self.client.post(self.base+'/jobs',json={**self.payload(),'draft_id':result['id']}).status_code,400)
        self.assertEqual(self.client.get(self.base+'/jobs').json(),[])

    def test_timeline_distinguishes_drafts_and_redacts_command_secrets(self):
        result,_=self.save(command='tool --token fixture-secret --password=hidden')
        events=self.client.get(self.base+'/timeline').json()
        event=next(e for e in events if e['type']=='draft')
        self.assertEqual(event['status'],'draft')
        self.assertEqual(event['revision'],1)
        self.assertNotIn('fixture-secret',event['command'])
        self.assertNotIn('hidden',event['command'])
        self.assertNotIn('fixture-secret',self.client.get(self.base+'/timeline?export=csv').text)
        self.assertIn('revision',self.client.get(self.base+'/timeline?export=csv').text.splitlines()[0])
        exported=self.client.get(self.base+'/scan-drafts/'+str(result['id'])+'?export=true')
        self.assertIn('attachment',exported.headers['content-disposition'])
        self.assertEqual(exported.json()['notes'],'Operator notes')

    def test_exclusions_hide_all_revisions_and_other_projects_cannot_read(self):
        result,_=self.save()
        did=result['id']
        other=self.client.post('/api/engagements',json={'name':'Other'}).json()['id']
        self.assertEqual(self.client.get(f'/api/e/{other}/scan-drafts/{did}').status_code,404)
        self.client.post(self.base+'/scope',json={'action':'exclude','target':'example.com'})
        self.assertEqual(self.client.get(self.base+'/scan-drafts').json(),[])
        self.assertEqual(self.client.get(self.base+f'/scan-drafts/{did}').status_code,404)
        self.assertFalse(any(e['type']=='draft' for e in self.client.get(self.base+'/timeline').json()))

    def test_draft_writes_require_csrf_and_migration_is_idempotent(self):
        self.client.headers.pop('X-CSRF-Token')
        self.assertEqual(self.client.post(self.base+'/scan-drafts/preview',json=self.payload()).status_code,403)
        self.client.headers['X-CSRF-Token']=self.csrf
        self.save()
        migrate();migrate()
        self.assertEqual(len(self.client.get(self.base+'/scan-drafts').json()),1)

    def test_all_existing_profiles_can_be_drafted_without_tools_or_dns(self):
        for profile in ('bbot-passive','dns-validate','nmap-services','httpx-web','gowitness-web'):
            with patch('socket.getaddrinfo',side_effect=AssertionError('DNS called')),patch('vandal.drafts.executable',return_value=None):
                response=self.client.post(self.base+'/scan-drafts/preview',json={**self.payload(),'profile':profile})
            self.assertEqual(response.status_code,200,(profile,response.text))

    def test_imported_dns_sync_updates_current_host_without_merging_history(self):
        for at,ip in [('2025-01-01T00:00:00Z','192.0.2.1'),('2025-02-01T00:00:00Z','192.0.2.2')]:
            self.load(json.dumps({'host':'www.example.com','a':[ip],'query_type':'A','rcode':'NOERROR','resolver':'fixture','timestamp':at}).encode(),at+'.jsonl')
        host=self.client.get(self.base+'/hosts?mode=hostname').json()['items'][0]
        self.assertEqual(host['address_view']['primary_ip'],'192.0.2.2')
        detail=self.client.get(self.base+'/hosts/'+str(host['id'])).json()
        self.assertEqual(len(detail['address_view']['history']),2)
