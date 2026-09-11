"""Optional Playwright acceptance check; starts a fixture-only localhost server.

Run with a Python environment containing Playwright. Chromium is already installed
by Vandal's dependencies. This script never sends scan requests to the worker.
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import urllib.request

from playwright.sync_api import sync_playwright, expect

ROOT = Path(__file__).resolve().parents[1]
BASE = 'http://127.0.0.1:8879'
with tempfile.TemporaryDirectory(prefix='vandal-draft-browser-') as folder:
    env = {**os.environ, 'VANDAL_DATA': folder, 'VANDAL_WORKER': '0', 'VANDAL_ADMIN_PASSWORD': 'fixture-password-1234'}
    with open('/tmp/vandal-draft-browser.log', 'w') as log:
        server = subprocess.Popen([str(ROOT/'.venv/bin/python'), str(ROOT/'tests/browser_fixture.py')], env=env, cwd=ROOT, stdout=log, stderr=log)
        try:
            for _ in range(100):
                if server.poll() is not None:
                    raise RuntimeError('Fixture server exited; see /tmp/vandal-draft-browser.log')
                try:
                    urllib.request.urlopen(BASE, timeout=1)
                    break
                except OSError:
                    time.sleep(.1)
            else:
                raise RuntimeError('Fixture server did not start')
            with sync_playwright() as p:
                browser = p.chromium.launch(executable_path='/usr/bin/chromium', args=['--no-sandbox'])
                page = browser.new_page(viewport={'width':1440,'height':1000}, accept_downloads=True)
                errors, previews, launches = [], [], []
                page.on('pageerror', lambda e: errors.append(str(e)))
                def preview(route):
                    body = route.request.post_data_json
                    previews.append(body)
                    if len(previews) == 1:
                        route.fulfill(status=400, json={'detail':'Fixture DNS lookup failed'})
                    else:
                        route.fulfill(json={'command':['fixture-tool','fixture-arguments'], 'command_text':'fixture-tool fixture-arguments', 'targets':body['targets'], 'excluded':[], 'scope_additions':[]})
                def jobs(route):
                    if route.request.method == 'POST':
                        launches.append(route.request.url)
                        route.abort()
                    else:
                        route.continue_()
                page.route('**/api/e/*/jobs/preview', preview)
                page.route('**/api/e/*/jobs', jobs)
                page.goto(BASE+'/#explore')
                page.locator('[name=password]').fill('fixture-password-1234')
                page.locator('#login-form button').click()
                page.wait_for_selector('[data-host-row]')
                page.locator('.topbar [data-action=new-job]').click()
                page.locator('#scan-composer [name=profile]').select_option('nmap-services')
                page.locator('#scan-composer [name=targets]').fill('Unresolved.Example.com.')
                page.locator('#scan-composer button[type=submit]').click()
                expect(page.locator('#draft-command')).to_be_visible()
                assert not previews
                generated = page.locator('#draft-command').input_value()
                page.locator('#validate-scan-profile').click()
                expect(page.locator('#profile-readiness')).to_contain_text('Fixture DNS lookup failed')
                expect(page.locator('#draft-command')).to_have_value(generated)
                edited = generated+'\n# operator review'
                page.locator('#draft-command').fill(edited)
                page.locator('#draft-notes').fill('Keep these notes <literal markup>')
                page.locator('#save-scan-draft').click()
                expect(page.locator('#draft-save-state')).to_contain_text('Revision 1')

                # Profile edits invalidate readiness but must not discard draft text.
                page.locator('#scan-composer [name=ports]').fill('443')
                page.locator('#scan-composer button[type=submit]').click()
                expect(page.locator('#draft-command')).to_have_value(edited)
                expect(page.locator('#draft-notes')).to_have_value('Keep these notes <literal markup>')
                page.locator('#save-scan-draft').click()
                expect(page.locator('#draft-save-state')).to_contain_text('Revision 2')
                with page.expect_download() as download:
                    page.locator('#download-scan-draft').click()
                exported=json.loads(Path(download.value.path()).read_text())
                assert exported['command']==edited and exported['validation_error']=='Fixture DNS lookup failed'

                page.locator('#drawer-close').click()
                page.locator('.rail [data-page=jobs]').click()
                page.locator('#page-actions [data-open-drafts]').click()
                page.locator('#drawer [data-scan-draft]').first.click()
                expect(page.locator('#draft-command')).to_have_value(edited)
                expect(page.locator('#draft-history > div > details')).to_have_count(2)
                expect(page.locator('#draft-notes')).to_have_value('Keep these notes <literal markup>')

                # Another session advances the revision; local edits must remain.
                session = page.request.get(BASE+'/api/session').json()
                prefix=BASE+'/api/e/'+str(session['engagements'][0]['id'])
                item=page.request.get(prefix+'/scan-drafts/1').json()
                response=page.request.put(prefix+'/scan-drafts/1', data={**item,'base_revision':2,'notes':'Other session'}, headers={'X-CSRF-Token':session['csrf']})
                assert response.status==200
                page.locator('#draft-notes').fill('Local unsaved revision')
                page.locator('#save-scan-draft').click()
                expect(page.locator('#draft-save-state')).to_contain_text('another session')
                expect(page.locator('#draft-notes')).to_have_value('Local unsaved revision')
                page.locator('#drawer-close').click()
                page.locator('.rail [data-page=timeline]').click()
                page.locator('#timeline-list [data-scan-draft]').first.click()
                expect(page.locator('#draft-notes')).to_have_value('Other session')
                page.locator('#reset-draft-command').click()
                page.locator('#validate-scan-profile').click()
                expect(page.locator('#run-preview')).to_be_enabled()
                page.locator('#draft-command').fill('review text only')
                expect(page.locator('#run-preview')).to_be_disabled()
                page.locator('#drawer-close').click()

                page.locator('.rail [data-page=explore]').click()
                page.locator('#current-host-search input').fill('hostname:www.example.com')
                page.locator('#current-host-search button').click()
                expect(page.locator('[data-host-row]')).to_have_count(1)
                page.locator('.result-header h2 a').click()
                page.locator('#host-pane [data-sync-dns]').click()
                expect(page.locator('#scan-composer [name=profile]')).to_have_value('dns-validate')
                expect(page.locator('#scan-composer [name=targets]')).to_have_value('www.example.com')
                page.locator('#scan-composer button[type=submit]').click()
                expect(page.locator('#draft-command')).to_contain_text('vandal.probes')
                page.set_viewport_size({'width':650,'height':900})
                assert page.locator('#drawer').evaluate('(e)=>e.scrollWidth<=e.clientWidth+2')
                page.screenshot(path='/tmp/vandal-draft-mobile.png', full_page=True)
                assert not errors, errors
                assert not launches, launches
                assert page.request.get(prefix+'/jobs').json()==[]
                print('PASS: offline draft, retained edits/errors, revisions/conflicts, exports, Timeline, DNS entry, mobile layout; no jobs launched.')
                browser.close()
        finally:
            server.terminate()
            server.wait(timeout=10)
