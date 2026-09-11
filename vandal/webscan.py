"""HTTP validation -> gowitness. Invoked in the normal cancellable worker group."""
import concurrent.futures
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
from urllib.parse import urlsplit
import httpx
from bs4 import BeautifulSoup
from .db import connect, dump, now
from .jobs import executable, scope_targets
from .identity import identity
from .web_inventory import validate_config
from .web_proxy import ScopeProxy


def load(folder):
    with connect() as con:
        job = dict(con.execute('SELECT * FROM jobs WHERE id=?',(int(folder.name),)).fetchone())
        rules = [dict(r) for r in con.execute('SELECT * FROM scope_rules WHERE engagement_id=?',(job['engagement_id'],))]
    return job,json.loads(job['config']),rules


def validate(folder):
    job,config,rules = load(folder)
    limits = validate_config(config)
    candidates = config['_web_candidates']
    def probe(c):
        record = {**c,'status':'unreachable','error':'','status_code':None,'title':''}
        try:
            with httpx.Client(proxy=os.environ['VANDAL_WEB_PROXY'],verify=False,follow_redirects=False,timeout=limits['probe_timeout'],trust_env=False) as client:
                with client.stream('GET',c['url']) as response:
                    if response.headers.get('X-Vandal-Proxy-Error') == '1': raise ValueError('Blocked or unreachable through scope proxy')
                    chunks=[];size=0
                    for chunk in response.iter_bytes():
                        chunks.append(chunk);size+=len(chunk)
                        if size>=200000: break
                    soup=BeautifulSoup(b''.join(chunks),'html.parser')
                    record.update(status='validated',status_code=response.status_code,title=soup.title.get_text(' ',strip=True)[:500] if soup.title else '',headers=dict(response.headers),timestamp=now())
        except Exception as exc: record['error']=str(exc)[:1000]
        return record
    with (folder/'validation.jsonl').open('w') as output, (folder/'responsive-urls.txt').open('w') as urls, (folder/'output.jsonl').open('w') as inventory:
        with concurrent.futures.ThreadPoolExecutor(max_workers=limits['web_threads']) as pool:
            for r in pool.map(probe,candidates):
                output.write(dump(r)+'\n');output.flush()
                if r['status']=='validated':
                    urls.write(r['url']+'\n');urls.flush()
                    inventory.write(dump({'host':r['host'],'url':r['url'],'status_code':r['status_code'],'title':r['title'],'timestamp':r['timestamp'],'headers':r.get('headers',{})})+'\n');inventory.flush()
                print(f"HTTP {r['status']} {r['url']} {r['status_code'] or ''}",flush=True)


def step(job, name, command):
    with connect() as con:
        sid=con.execute('INSERT INTO job_steps(job_id,name,command,status,started_at) VALUES (?,?,?,?,?)',(job['id'],name,dump(command),'running',now())).lastrowid
    print(name+': '+dump(command),flush=True)
    result=subprocess.run(command)
    with connect() as con:
        con.execute('UPDATE job_steps SET status=?,ended_at=?,exit_code=? WHERE id=?',('completed' if result.returncode==0 else 'failed',now(),result.returncode,sid))
    return result.returncode


def persist(folder, job, proxy=None):
    if proxy is None:
        from types import SimpleNamespace
        resolved={}
        if (folder/'resolution-log.jsonl').exists():
            for line in (folder/'resolution-log.jsonl').read_text().splitlines():
                try:
                    r=json.loads(line);resolved.setdefault(r['host'],set()).update(r['ips'])
                except (ValueError,KeyError): pass
        proxy=SimpleNamespace(resolutions=resolved)
    reports={}
    path=folder/'gowitness.jsonl'
    if path.exists():
        for line in path.read_text(errors='replace').splitlines():
            try:
                r=json.loads(line);reports[identity(r['url'])[1]]=r
            except (ValueError,KeyError): continue
    validations=folder/'validation.jsonl'
    if not validations.exists(): return
    with connect() as con:
        for line in validations.read_text().splitlines():
            try: v=json.loads(line)
            except ValueError: continue
            report=reports.get(identity(v['url'])[1],{})
            screenshot=''
            file=report.get('file_name','')
            if file and Path(file).name==file and (folder/'screenshots'/file).is_file(): screenshot=file
            status='captured' if screenshot else 'capture_failed' if v['status']=='validated' else 'unreachable'
            error=report.get('failed_reason','') or v.get('error','') or ('No screenshot returned' if status=='capture_failed' else '')
            asset=v.get('asset_id')
            con.execute('''INSERT INTO web_captures(engagement_id,job_id,asset_id,url,host,ips,status,status_code,title,final_url,technologies,screenshot,error,validation,report,created_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(job_id,url) DO UPDATE SET status=excluded.status,screenshot=excluded.screenshot,error=excluded.error,report=excluded.report''',
                (job['engagement_id'],job['id'],asset,v['url'],v['host'],dump(sorted(proxy.resolutions.get(v['host'],[]))),status,report.get('response_code') or v['status_code'],report.get('title') or v['title'],report.get('final_url',''),dump(report.get('technologies') or []),screenshot,error,dump(v),dump(report),now()))


def run(folder):
    job,config,rules=load(folder)
    if scope_targets(json.loads(job['targets']),rules)[0]!=json.loads(job['targets']): raise ValueError('Scope changed; create a new web scan')
    limits=validate_config(config)
    proxy=ScopeProxy(config['_web_candidates'],[r['target'] for r in rules if r['action']=='exclude'],job['engagement_id'],folder/'resolution-log.jsonl')
    thread=threading.Thread(target=proxy.serve_forever,daemon=True);thread.start()
    os.environ['VANDAL_WEB_PROXY']=f'http://127.0.0.1:{proxy.server_port}'
    try:
        code=step(job,'HTTP/HTTPS validation',[sys.executable,'-m','vandal.webscan','validate',str(folder)])
        if code: return code
        if not (folder/'responsive-urls.txt').read_text().strip():
            print('No HTTP/HTTPS responses; skipping gowitness.',flush=True);return 0
        # Force all browser HTTP(S), including loopback URLs, through the scope proxy.
        chrome=shutil.which('chromium') or shutil.which('google-chrome')
        wrapper=folder/'chrome-wrapper'
        wrapper.write_text('#!'+sys.executable+'\nimport os,sys\nos.execv('+repr(chrome)+', ['+repr(chrome)+', "--proxy-bypass-list=<-loopback>", "--disable-quic", *sys.argv[1:]])\n')
        wrapper.chmod(0o700)
        command=[executable('gowitness'),'scan','file','--file',str(folder/'responsive-urls.txt'),'--chrome-path',str(wrapper),'--chrome-proxy',os.environ['VANDAL_WEB_PROXY'],
            '--threads',str(limits['web_threads']),'--timeout',str(limits['web_timeout']),'--delay',str(limits['web_delay']),
            '--write-jsonl','--write-jsonl-file',str(folder/'gowitness.jsonl'),'--write-db','--write-db-uri','sqlite://'+str(folder/'gowitness.sqlite3'),
            '--screenshot-path',str(folder/'screenshots'),'--log-scan-errors']
        if config.get('full_page'): command.append('--screenshot-fullpage')
        return step(job,'gowitness capture',command)
    finally:
        persist(folder,job,proxy);proxy.shutdown();proxy.server_close()


if __name__=='__main__':
    action,folder=sys.argv[1],Path(sys.argv[2]).resolve()
    if action=='validate': validate(folder)
    elif action=='run': sys.exit(run(folder))
    else: raise ValueError('Unknown web scan stage')
