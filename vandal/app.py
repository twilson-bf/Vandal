from contextlib import asynccontextmanager
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
from urllib.parse import urlsplit

from fastapi import FastAPI, Request, HTTPException, UploadFile, File, Body
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware
from . import auth
from .db import ROOT, connect, data_dir, migrate, now, rows, dump
from .ingest import queue_import, MAX_UPLOAD
from . import query
from .jobs import PROFILES, executable, prepare, DEFAULT_NMAP_PORTS, scope_targets
from .identity import identity, in_rule
from .redact import command as redact_command
from .parsers import timestamp


@asynccontextmanager
async def lifespan(app):
    migrate()
    auth.bootstrap()
    from .interests import backfill
    with connect() as con:
        backfill(con)
    worker = None
    if os.getenv('VANDAL_WORKER', '1') == '1':
        worker = subprocess.Popen([sys.executable, '-m', 'vandal.worker'], cwd=ROOT)
    yield
    if worker and worker.poll() is None:
        worker.terminate()
        try:
            worker.wait(timeout=15)
        except subprocess.TimeoutExpired:
            worker.kill()
            worker.wait()


app = FastAPI(title='vandal', lifespan=lifespan, docs_url=None, redoc_url=None)
from .drafts import router as drafts_router
app.include_router(drafts_router)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=os.getenv('VANDAL_ALLOWED_HOSTS', 'localhost,127.0.0.1,::1,testserver').split(','))
app.mount('/static', StaticFiles(directory=ROOT / 'vandal/static'), name='static')


@app.middleware('http')
async def headers(request, call_next):
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    if not request.url.path.startswith('/static'):
        response.headers['Cache-Control'] = 'no-store'
    return response


@app.exception_handler(ValueError)
async def invalid(request, exc):
    return JSONResponse({'detail': str(exc)}, status_code=400)


def audit(con, engagement, actor, action, detail):
    con.execute('INSERT INTO audit(engagement_id,actor,action,detail,created_at) VALUES (?,?,?,?,?)', (engagement, actor, action, dump(detail), now()))


def scope_tag(value):
    value = str(value or '').strip()
    if not value:
        value = 'untagged'
    if len(value) > 80 or '/' in value or any(ord(c) < 32 for c in value):
        raise ValueError('Tag must be 1–80 printable characters and cannot contain /')
    return value


def cancel_jobs_outside_policy(con, eid, actor, rules, limit_to_included, reason):
    """Stop work that would no longer pass the current scope policy."""
    cancelled = []
    for job in rows(con, "SELECT * FROM jobs WHERE engagement_id=? AND status IN ('queued','running')", (eid,)):
        accepted, rejected = scope_targets(json.loads(job['targets']), rules, limit_to_included)
        if rejected:
            if job['status'] == 'queued':
                con.execute("UPDATE jobs SET status='cancelled',cancel_requested=1,ended_at=? WHERE id=?", (now(), job['id']))
            else:
                con.execute('UPDATE jobs SET cancel_requested=1 WHERE id=?', (job['id'],))
            cancelled.append(job['id'])
            audit(con, eid, actor, 'job.cancel_requested', {'id': job['id'], 'reason': reason, 'rejected': rejected})
    return cancelled


def one(con, table, key, engagement):
    row = con.execute(f'SELECT * FROM {table} WHERE id=? AND engagement_id=?', (key, engagement)).fetchone()
    if not row:
        raise HTTPException(404, 'Not found')
    return dict(row)


@app.get('/', response_class=HTMLResponse)
def index():
    return (ROOT / 'vandal/templates/index.html').read_text()


attempts = {}


@app.post('/api/login')
def login(request: Request, body: dict = Body(...)):
    origin = request.headers.get('origin')
    if origin and urlsplit(origin).netloc != request.headers.get('host'):
        raise HTTPException(403, 'Cross-origin login rejected')
    client = request.client.host if request.client else 'local'
    recent = [t for t in attempts.get(client, []) if t > time.time() - 300]
    if len(recent) >= 10:
        raise HTTPException(429, 'Too many attempts. Try again in five minutes.')
    attempts[client] = recent + [time.time()]
    token = auth.login(str(body.get('name', '')), str(body.get('password', '')))
    attempts.pop(client, None)
    response = JSONResponse({'ok': True})
    response.set_cookie('vandal_session', token, httponly=True, samesite='strict', secure=os.getenv('VANDAL_COOKIE_SECURE') == '1', max_age=43200)
    return response


@app.get('/api/session')
def session(request: Request):
    actor = auth.user(request)
    with connect() as con:
        actor['engagements'] = rows(con, 'SELECT * FROM engagements' if actor['role'] == 'admin' else 'SELECT e.* FROM engagements e JOIN members m ON m.engagement_id=e.id WHERE m.user_id=?', () if actor['role'] == 'admin' else (actor['id'],))
    return actor


@app.post('/api/logout')
def logout(request: Request):
    actor = auth.user(request)
    if not secrets.compare_digest(request.headers.get('X-CSRF-Token', ''), actor['csrf']):
        raise HTTPException(403, 'Invalid CSRF token')
    with connect() as con:
        con.execute('DELETE FROM sessions WHERE token=?', (hashlib.sha256(request.cookies.get('vandal_session', '').encode()).hexdigest(),))
    response = JSONResponse({'ok': True})
    response.delete_cookie('vandal_session')
    return response


@app.post('/api/engagements')
def new_engagement(request: Request, body: dict = Body(...)):
    actor = auth.user(request)
    if actor['role'] != 'admin' or not secrets.compare_digest(request.headers.get('X-CSRF-Token', ''), actor['csrf']):
        raise HTTPException(403, 'Administrator access required')
    name = str(body.get('name', '')).strip()
    if not 1 <= len(name) <= 150:
        raise ValueError('Name must be 1–150 characters')
    with connect() as con:
        eid = con.execute('INSERT INTO engagements(name,created_at) VALUES (?,?)', (name, now())).lastrowid
        audit(con, eid, actor['name'], 'engagement.created', {'name': name})
    return {'id': eid}


@app.get('/api/e/{eid}/overview')
def overview(eid: int, request: Request):
    auth.access(request, eid)
    with connect(visible_eid=eid) as con:
        where, args = query.asset_filter(eid, {})
        counts = rows(con, 'SELECT a.kind,count(*) count FROM assets a WHERE ' + where + ' GROUP BY a.kind', args)
        return {'counts': counts, 'imports': rows(con, 'SELECT id,filename,format,status,record_count,warnings,created_at FROM imports WHERE engagement_id=? ORDER BY id DESC LIMIT 8', (eid,)),
                'records': con.execute('SELECT count(*) FROM records r JOIN imports i ON i.id=r.import_id WHERE r.engagement_id=? AND i.active=1', (eid,)).fetchone()[0],
                'interests': con.execute('SELECT count(*) FROM interests WHERE engagement_id=?', (eid,)).fetchone()[0],
                'open_endpoints': con.execute("SELECT count(DISTINCT ep.id) FROM endpoints ep JOIN assets a ON a.id=ep.asset_id JOIN observations o ON o.endpoint_id=ep.id JOIN records r ON r.id=o.record_id JOIN imports i ON i.id=r.import_id WHERE a.engagement_id=? AND i.active=1 AND o.state='open'", (eid,)).fetchone()[0],
                'services': rows(con, "SELECT o.service,count(DISTINCT ep.id) count FROM observations o JOIN endpoints ep ON ep.id=o.endpoint_id JOIN assets a ON a.id=ep.asset_id JOIN records r ON r.id=o.record_id JOIN imports i ON i.id=r.import_id WHERE a.engagement_id=? AND i.active=1 AND o.evidence='probed' AND o.state='open' AND o.service!='' GROUP BY o.service ORDER BY count DESC LIMIT 10", (eid,)),
                'geo_configured': bool(os.getenv('VANDAL_GEOIP_CITY')) or bool(con.execute('SELECT 1 FROM assets WHERE engagement_id=? AND latitude IS NOT NULL LIMIT 1', (eid,)).fetchone())}


@app.get('/api/e/{eid}/assets')
def assets(eid: int, request: Request):
    auth.access(request, eid)
    with connect(visible_eid=eid) as con:
        return query.assets(con, eid, dict(request.query_params))


@app.get('/api/e/{eid}/inventory')
def inventory_search(eid: int, request: Request):
    auth.access(request, eid)
    from .inventory import search
    with connect(visible_eid=eid) as con:
        return search(con, eid, dict(request.query_params))


@app.get('/api/e/{eid}/enrichment')
def enrichment_status(eid: int, request: Request):
    auth.access(request, eid)
    with connect(visible_eid=eid) as con:
        return rows(con,"""SELECT e.kind,e.status,count(*) count FROM enrichment e WHERE
            (e.kind='geo' AND EXISTS(SELECT 1 FROM assets a WHERE a.engagement_id=? AND a.value=e.key)) OR
            (e.kind='cve' AND EXISTS(SELECT 1 FROM interests i WHERE i.engagement_id=? AND i.title LIKE '%'||e.key||'%'))
            GROUP BY e.kind,e.status""",(eid,eid))


@app.get('/api/e/{eid}/cves/{cve}')
def cve_details(eid: int, cve: str, request: Request):
    auth.access(request,eid)
    from .enrichment import cve_ids
    cve=cve.upper()
    if cve_ids(cve)!=[cve]:raise ValueError('Invalid CVE ID')
    with connect(visible_eid=eid) as con:
        if not con.execute("SELECT 1 FROM interests WHERE engagement_id=? AND title LIKE ?",(eid,'%'+cve+'%')).fetchone():
            raise HTTPException(404,'CVE is not linked to this project')
        con.execute("INSERT OR IGNORE INTO enrichment(kind,key) VALUES ('cve',?)",(cve,))
        return dict(con.execute("SELECT status,result,error,updated_at FROM enrichment WHERE kind='cve' AND key=?",(cve,)).fetchone())


@app.get('/api/e/{eid}/inventory/{aid}')
@app.get('/api/e/{eid}/hosts/{aid}')
def inventory_host(eid: int, aid: int, request: Request):
    auth.access(request, eid)
    from .inventory import build, clean
    projected='/hosts/' in request.url.path
    if projected:
        from .projection import build, public
        clean=lambda a: public(a,detail=True)
    with connect(visible_eid=eid) as con:
        assets = build(con,eid,request.query_params.get('hide_passive')=='1')
        asset = next((a for a in assets if a['id']==aid), None)
        if not asset:
            raise HTTPException(404, 'Host not found in active imports')
        result = clean(asset)
        owners = {aid}
        if asset['kind']=='ip':
            owners.update(n['id'] for n in asset['associated'] if n['kind']=='hostname')
        confirmed = {}
        for owner in assets:
            if owner['id'] not in owners:
                continue
            for finding in owner['findings']:
                if finding['confirmed'] and finding['status']!='dismissed':
                    item = confirmed.setdefault(finding['id'], {**finding, 'affected_assets':[]})
                    item['affected_assets'].append({'id':owner['id'], 'value':owner['value']})
        result['confirmed_findings'] = list(confirmed.values())
        for service in result['services']:
            record = con.execute('SELECT raw FROM records WHERE id=?', (service['record_id'],)).fetchone()
            service['banner'] = record['raw'][:16000] if record else ''
            for variant in service.get('variants',[]):
                record=con.execute('SELECT raw FROM records WHERE id=?',(variant['record_id'],)).fetchone()
                variant['banner']=record['raw'][:16000] if record else ''
        result['detail'] = query.detail(con, one(con,'assets',aid,eid))
        result['jobs'] = [j for j in rows(con,'SELECT * FROM jobs WHERE engagement_id=? ORDER BY id DESC',(eid,)) if asset['value'] in json.loads(j['targets'])]
        return result


@app.get('/api/e/{eid}/hosts')
def current_hosts(eid: int, request: Request):
    auth.access(request,eid)
    from .inventory import search
    with connect(visible_eid=eid) as con:
        return search(con,eid,dict(request.query_params),projected=True)


@app.get('/api/e/{eid}/host-vulnerabilities')
def host_vulnerabilities(eid: int, request: Request):
    auth.access(request,eid)
    from .projection import build,host_rows,cve_groups
    hide=request.query_params.get('hide_passive')=='1'
    q=request.query_params.get('q','').lower()
    state=request.query_params.get('state','all')
    with connect(visible_eid=eid) as con:
        results=[]
        for a in host_rows(build(con,eid,hide),hide):
            groups=[g for g in a['vulnerabilities'] if state=='all' or g['status']==state]
            other=a['other_findings'] if state in ('all','interests') else [f for f in a['other_findings'] if state=='confirmed' and f['confirmed'] and f['status']!='dismissed']
            if state=='interests':groups=[]
            if q and q not in a['value'].lower():
                groups=[g for g in groups if q in g['cve'].lower() or any(q in f['notes'].lower() or q in f['title'].lower() for f in g['claims'])]
                other=[f for f in other if q in f['title'].lower() or q in f['notes'].lower()]
            if groups or other:
                results.append({'id':a['id'],'value':a['value'],'vulnerabilities':groups,'other_findings':other})
        unassigned=rows(con,"SELECT * FROM interests WHERE engagement_id=? AND json_array_length(asset_ids)=0",(eid,))
        if hide:
            from .inventory import passive_finding
            unassigned=[f for f in unassigned if not passive_finding(f)]
        if q:unassigned=[f for f in unassigned if q in f['title'].lower() or q in f['notes'].lower()]
        groups,other=cve_groups(unassigned,0,{})
        groups=[g for g in groups if state=='all' or g['status']==state]
        other=[f for f in other if state in ('all','interests') or state=='confirmed' and f['confirmed'] and f['status']!='dismissed']
        if groups or other:results.append({'id':0,'value':'Unassigned items','vulnerabilities':groups,'other_findings':other})
        results.sort(key=lambda a:(-max((g['score'] if g['score'] is not None else -1 for g in a['vulnerabilities']),default=-1),a['value']))
        return {'items':results,'total':len(results),'cve_pairs':sum(len(a['vulnerabilities']) for a in results)}


@app.get('/api/e/{eid}/hosts-export')
def current_hosts_export(eid: int, request: Request):
    auth.access(request,eid)
    import csv,io
    from .projection import build,host_rows
    from .inventory import matches,tokens
    hide=request.query_params.get('hide_passive')=='1'
    terms=tokens(request.query_params.get('q',''))
    stream=io.StringIO();writer=csv.writer(stream)
    writer.writerow(['Host ID','Host','Primary IP','Address status','Open services','Confirmed vulnerabilities','Potential CVEs'])
    with connect(visible_eid=eid) as con:
        for a in host_rows(build(con,eid,hide),hide,request.query_params.get('mode','auto')):
            if matches(a,terms):
                writer.writerow([a['id'],a['value'],a['address_view']['primary_ip'],a['address_view']['status'],a['open_port_count'],a['confirmed'],a['potential']])
    return Response(stream.getvalue(),media_type='text/csv',headers={'Content-Disposition':'attachment; filename="vandal-hosts.csv"'})


@app.get('/api/e/{eid}/projection-version')
def projection_version(eid: int, request: Request):
    auth.access(request,eid)
    import hashlib
    with connect(visible_eid=eid) as con:
        parts=[rows(con,'SELECT max(id) AS last,count(*) AS count FROM records WHERE engagement_id=?',(eid,)),
               rows(con,'SELECT id,active,status,finished_at FROM imports WHERE engagement_id=? ORDER BY id',(eid,)),
               rows(con,'SELECT id,confirmed,status,updated_at FROM interests WHERE engagement_id=? ORDER BY id',(eid,)),
               rows(con,'SELECT id,action,target,tag,hidden FROM scope_rules WHERE engagement_id=? ORDER BY id',(eid,)),
               rows(con,'SELECT scope_mode FROM engagements WHERE id=?',(eid,)),
               rows(con,"SELECT max(updated_at) AS updated FROM enrichment WHERE kind='cve'")]
    return {'version':hashlib.sha256(json.dumps(parts,sort_keys=True).encode()).hexdigest()}


@app.get('/api/e/{eid}/asset-options')
def asset_options(eid: int, request: Request, q: str = '', ids: str = ''):
    auth.access(request, eid)
    with connect(visible_eid=eid) as con:
        where = 'a.engagement_id=? AND ' + query.VISIBLE
        args = [eid]
        if ids:
            selected = [int(x) for x in ids.split(',') if x.strip()][:200]
            if not selected:
                return []
            where += ' AND a.id IN (' + ','.join('?' for _ in selected) + ')'
            args.extend(selected)
        else:
            q = q.strip()[:250]
            if not q:
                return []
            where += ' AND (instr(lower(a.value),lower(?))>0 OR CAST(a.id AS TEXT)=?)'
            args.extend([q, q.removeprefix('#')])
        return rows(con, 'SELECT a.id,a.value,a.kind FROM assets a WHERE ' + where + ' ORDER BY a.value LIMIT 200', args)


@app.get('/api/e/{eid}/dashboard')
def dashboard(eid: int, request: Request):
    auth.access(request, eid)
    from .inventory import build
    from collections import Counter
    projected=request.query_params.get('view')=='current'
    hide=request.query_params.get('hide_passive')=='1'
    if projected:
        from .projection import build,host_rows
    with connect(visible_eid=eid) as con:
        assets = build(con,eid,hide) if projected else build(con,eid)
        hosts = [a for a in assets if a['kind']=='ip']
        display_hosts=list(host_rows(assets,hide)) if projected else hosts
        if projected and hide:
            shown_ips={p['id'] for a in display_hosts for p in a['address_view']['addresses']}
            hosts=[a for a in hosts if a['id'] in shown_ips]
        byid = {a['id']:a for a in assets}
        for host in hosts:
            owners = [host] + [byid[n['id']] for n in host['associated'] if n['kind']=='hostname']
            host['map_confirmed'] = len({f['id'] for owner in owners for f in owner['findings'] if f['confirmed'] and f['status']!='dismissed'})
        findings = rows(con,'SELECT * FROM interests WHERE engagement_id=?',(eid,))
        if projected:
            findings=[{**g['claims'][0],'title':g['cve']+' · '+a['value'],'confirmed':int(g['confirmed'])} for a in display_hosts for g in a['vulnerabilities']]+[f for a in display_hosts for f in a['other_findings']]
        jobs = rows(con,'SELECT * FROM jobs WHERE engagement_id=? ORDER BY id DESC',(eid,))
        return {'hosts':len(display_hosts),'addresses':len(hosts),'hostnames':sum(a['kind']=='hostname' for a in assets),
            'locations':[{'id':a['id'],'value':a['value'],'country':a['country'],'latitude':a['latitude'],'longitude':a['longitude'],'confirmed':a['map_confirmed'],'hostnames':[{'id':n['id'],'value':n['value']} for n in a['associated'] if n['kind']=='hostname']} for a in hosts],
            'new_services':sorted([{'id':a['id'],'value':a['value'],'port':s['port'],'protocol':s['protocol'],
                'first_seen':min(o['created_at'] for o in s['_observations'])} for a in display_hosts for s in a['services'] if not projected or s['state']=='open'],key=lambda s:s['first_seen'],reverse=True)[:6],
            'services':sum(sum(s['state']=='open' for s in a['services']) if projected else len(a['services']) for a in display_hosts),'coverage':Counter(a['coverage'] for a in display_hosts),
            'potential':sum(a['potential'] for a in display_hosts) if projected else sum(f['category']=='potential CVE' and not f['confirmed'] and f['status']!='dismissed' for f in findings),
            'confirmed':sum(a['confirmed'] for a in display_hosts) if projected else sum(bool(f['confirmed']) for f in findings),
            'review':sum(f['status'] in ('new','reviewing') for f in findings),
            'active_jobs':[j for j in jobs if j['status'] in ('queued','running')], 'jobs':jobs[:6],
            'new_hosts':[{'id':a['id'],'value':a['value'],'first_seen':a['first_seen']} for a in sorted(display_hosts,key=lambda a:a['first_seen'] or '',reverse=True)[:6]],
            'new_findings':findings[-6:][::-1],
            'imports':rows(con,'SELECT id,filename,status,record_count FROM imports WHERE engagement_id=? ORDER BY id DESC LIMIT 6',(eid,))}


@app.get('/api/e/{eid}/facets')
def facets(eid: int, request: Request):
    auth.access(request, eid)
    with connect(visible_eid=eid) as con:
        result = {}
        where, args = query.asset_filter(eid, {})
        for field in ('domain', 'country', 'kind', 'asn'):
            result[field] = rows(con, f'SELECT a.{field} value,count(*) count FROM assets a WHERE {where} AND a.{field}!=\'\' GROUP BY a.{field} ORDER BY count DESC', args)
        result['source'] = rows(con, 'SELECT format value,count(*) count FROM imports WHERE engagement_id=? AND active=1 GROUP BY format', (eid,))
        return result


@app.get('/api/e/{eid}/map')
def map_data(eid: int, request: Request):
    auth.access(request, eid)
    with connect(visible_eid=eid) as con:
        where, args = query.asset_filter(eid, dict(request.query_params))
        return rows(con, 'SELECT a.id,a.value,a.kind,a.domain,a.country,a.latitude,a.longitude FROM assets a WHERE ' + where + ' ORDER BY a.value LIMIT 10000', args)


@app.get('/api/e/{eid}/assets/{aid}')
def asset_detail(eid: int, aid: int, request: Request):
    auth.access(request, eid)
    with connect(visible_eid=eid) as con:
        return query.detail(con, one(con, 'assets', aid, eid))


@app.patch('/api/e/{eid}/assets/{aid}')
def update_asset(eid: int, aid: int, request: Request, body: dict = Body(...)):
    actor = auth.access(request, eid, True)
    with connect() as con:
        one(con, 'assets', aid, eid)
        tags, notes = str(body.get('tags', ''))[:1000], str(body.get('notes', ''))[:20000]
        con.execute('UPDATE assets SET tags=?,notes=? WHERE id=?', (tags, notes, aid))
        audit(con, eid, actor['name'], 'asset.annotated', {'asset': aid, 'tags': tags, 'notes': notes})
    return {'ok': True}


@app.get('/api/e/{eid}/imports')
def imports(eid: int, request: Request):
    auth.access(request, eid)
    with connect(visible_eid=eid) as con:
        return rows(con, 'SELECT * FROM imports WHERE engagement_id=? ORDER BY id DESC', (eid,))


@app.post('/api/e/{eid}/imports')
async def upload(eid: int, request: Request, file: UploadFile = File(...)):
    actor = auth.access(request, eid, True)
    chunks, size = [], 0
    while chunk := await file.read(1024 * 1024):
        size += len(chunk)
        if size > MAX_UPLOAD:
            raise HTTPException(413, 'File exceeds 100 MiB')
        chunks.append(chunk)
    iid, duplicate = queue_import(eid, file.filename or 'upload', b''.join(chunks), actor['name'])
    return {'id': iid, 'duplicate': duplicate}


@app.post('/api/e/{eid}/imports/{iid}/{action}')
def import_action(eid: int, iid: int, action: str, request: Request):
    actor = auth.access(request, eid, True)
    with connect() as con:
        item = one(con, 'imports', iid, eid)
        if action in ('archive', 'restore'):
            con.execute('UPDATE imports SET active=? WHERE id=?', (int(action == 'restore'), iid))
        elif action == 'retry' and item['status'] in ('failed', 'interrupted'):
            con.execute("UPDATE imports SET status='queued' WHERE id=?", (iid,))
        else:
            raise ValueError('Action is unavailable for this import')
        audit(con, eid, actor['name'], 'import.' + action, {'id': iid})
    return {'ok': True}


@app.get('/api/e/{eid}/imports/{iid}/original')
def original(eid: int, iid: int, request: Request, offset: int = 0, download: bool = False):
    auth.access(request, eid)
    with connect(visible_eid=eid) as con:
        item = one(con, 'imports', iid, eid)
        if con.execute('SELECT count(*) FROM main.records WHERE import_id=?', (iid,)).fetchone()[0] != con.execute('SELECT count(*) FROM records WHERE import_id=?', (iid,)).fetchone()[0]:
            raise HTTPException(404, 'Original contains excluded assets; browse visible records instead')
    path = data_dir() / 'artifacts' / item['sha256']
    if download:
        return FileResponse(path, media_type='application/octet-stream', filename=item['filename'])
    with path.open('rb') as stream:
        stream.seek(max(0, offset))
        data = stream.read(100000)
    return {'text': data.decode('utf-8', errors='replace'), 'offset': max(0, offset), 'next': max(0, offset) + len(data), 'total': path.stat().st_size}


@app.get('/api/e/{eid}/records')
def records(eid: int, request: Request, page: int = 1, q: str = '', kind: str = '', import_id: int = 0, asset_id: int = 0):
    auth.access(request, eid)
    conditions, args = ['r.engagement_id=?'], [eid]
    if not import_id:
        conditions.append('i.active=1')
    for key, value in [('r.import_id', import_id), ('r.kind', kind)]:
        if value:
            conditions.append(key + '=?')
            args.append(value)
    if asset_id:
        conditions.append('EXISTS (SELECT 1 FROM record_assets ra WHERE ra.record_id=r.id AND ra.asset_id=?)')
        args.append(asset_id)
    if q:
        conditions.append('(r.title LIKE ? OR r.raw LIKE ? OR r.fields LIKE ?)')
        args.extend(['%' + q + '%'] * 3)
    where = ' AND '.join(conditions)
    with connect(visible_eid=eid) as con:
        total = con.execute('SELECT count(*) FROM records r JOIN imports i ON i.id=r.import_id WHERE ' + where, args).fetchone()[0]
        items = rows(con, 'SELECT r.id,r.title,r.kind,r.observed_at,r.import_id,i.filename FROM records r JOIN imports i ON i.id=r.import_id WHERE ' + where + ' ORDER BY r.id DESC LIMIT 50 OFFSET ?', args + [(max(1, page) - 1) * 50])
    return {'items': items, 'total': total, 'page': page, 'size': 50}


@app.get('/api/e/{eid}/records/{rid}')
def record(eid: int, rid: int, request: Request):
    auth.access(request, eid)
    with connect(visible_eid=eid) as con:
        result = one(con, 'records', rid, eid)
        result['assets'] = rows(con, 'SELECT a.* FROM record_assets ra JOIN assets a ON a.id=ra.asset_id WHERE ra.record_id=?', (rid,))
    return result


@app.get('/api/e/{eid}/findings')
def findings(eid: int, request: Request):
    auth.access(request, eid)
    with connect(visible_eid=eid) as con:
        items=rows(con, 'SELECT * FROM interests WHERE engagement_id=? ORDER BY id DESC', (eid,))
        if request.query_params.get('hide_passive')=='1':
            from .inventory import passive_finding
            items=[f for f in items if not passive_finding(f)]
        return items


@app.post('/api/e/{eid}/findings')
@app.patch('/api/e/{eid}/findings/{fid}')
def save_finding(eid: int, request: Request, body: dict = Body(...), fid: int = 0):
    actor = auth.access(request, eid, True)
    title = str(body.get('title', '')).strip()
    if not 1 <= len(title) <= 300:
        raise ValueError('Finding title must be 1–300 characters')
    if body.get('status', 'new') not in ('new', 'reviewing', 'parked', 'dismissed') or body.get('priority', 'normal') not in ('low', 'normal', 'high'):
        raise ValueError('Invalid workflow state or priority')
    evidence, assets = [int(x) for x in body.get('evidence', [])], [int(x) for x in body.get('asset_ids', [])]
    values = (title, str(body.get('category', 'lead'))[:100], body.get('priority', 'normal'), body.get('status', 'new'), int(body.get('confirmed') is True), str(body.get('notes', ''))[:50000], dump(evidence), dump(assets), now())
    with connect() as con:
        for rid in evidence:
            one(con, 'records', rid, eid)
        for aid in assets:
            one(con, 'assets', aid, eid)
        if fid:
            one(con, 'interests', fid, eid)
            con.execute('UPDATE interests SET title=?,category=?,priority=?,status=?,confirmed=?,notes=?,evidence=?,asset_ids=?,updated_at=? WHERE id=?', values + (fid,))
        else:
            fid = con.execute('INSERT INTO interests(title,category,priority,status,confirmed,notes,evidence,asset_ids,updated_at,engagement_id,actor,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)', values + (eid, actor['name'], now())).lastrowid
        audit(con, eid, actor['name'], 'finding.saved', {'id': fid, **body})
    return {'id': fid}


@app.get('/api/e/{eid}/scope')
def scope(eid: int, request: Request):
    auth.access(request, eid)
    with connect() as con:
        return rows(con, 'SELECT * FROM scope_rules WHERE engagement_id=? ORDER BY tag,target,id', (eid,))


@app.get('/api/e/{eid}/scope/settings')
def scope_settings(eid: int, request: Request):
    auth.access(request, eid)
    with connect() as con:
        mode = con.execute('SELECT scope_mode FROM engagements WHERE id=?', (eid,)).fetchone()['scope_mode']
    return {'mode': mode, 'limit_to_included': mode == 'included'}


@app.patch('/api/e/{eid}/scope/settings')
def update_scope_settings(eid: int, request: Request, body: dict = Body(...)):
    actor = auth.access(request, eid, True)
    if not isinstance(body.get('limit_to_included'), bool):
        raise ValueError('limit_to_included must be true or false')
    mode = 'included' if body['limit_to_included'] else 'open'
    from .scope_rules import policy
    with connect() as con:
        con.execute('UPDATE engagements SET scope_mode=? WHERE id=?', (mode, eid))
        rules, limited = policy(con, eid)
        cancelled = cancel_jobs_outside_policy(con, eid, actor['name'], rules, limited, 'Scope mode changed')
        audit(con, eid, actor['name'], 'scope.mode_changed', {'mode': mode, 'cancelled_jobs': cancelled})
    return {'mode': mode, 'limit_to_included': mode == 'included', 'cancelled_jobs': cancelled}


@app.get('/api/e/{eid}/scope/groups')
def scope_groups(eid: int, request: Request):
    auth.access(request, eid)
    with connect() as con:
        rules = rows(con, 'SELECT * FROM scope_rules WHERE engagement_id=? ORDER BY tag,target,id', (eid,))
        assets = [r['value'] for r in con.execute('SELECT value FROM assets WHERE engagement_id=?', (eid,))]
    groups = {}
    from .scope_rules import matcher
    for rule in rules:
        group = groups.setdefault(rule['tag'], {'tag': rule['tag'], 'rules': [], 'actions': set(), 'hidden_states': set()})
        group['rules'].append(rule)
        group['actions'].add(rule['action'])
        group['hidden_states'].add(bool(rule['hidden']))
    result = []
    for group in groups.values():
        match = matcher([r['target'] for r in group['rules']])
        action = next(iter(group['actions'])) if len(group['actions']) == 1 else 'mixed'
        hidden = next(iter(group['hidden_states'])) if len(group['hidden_states']) == 1 else None
        result.append({**group, 'actions': sorted(group['actions']), 'hidden_states': sorted(group['hidden_states']),
                       'action': action, 'hidden': hidden, 'rule_count': len(group['rules']),
                       'matched_assets': sum(match(value) for value in assets)})
    return result


@app.patch('/api/e/{eid}/scope/groups/{tag}')
def update_scope_group(eid: int, tag: str, request: Request, body: dict = Body(...)):
    actor = auth.access(request, eid, True)
    tag = scope_tag(tag)
    action = body.get('action')
    hidden = body.get('hidden')
    if action is not None and action not in ('include', 'exclude'):
        raise ValueError('Choose include or exclude')
    if hidden is not None and not isinstance(hidden, bool):
        raise ValueError('hidden must be true or false')
    if action is None and hidden is None:
        raise ValueError('Choose a group state to change')
    from .scope_rules import policy
    with connect() as con:
        if not con.execute('SELECT 1 FROM scope_rules WHERE engagement_id=? AND tag=?', (eid, tag)).fetchone():
            raise HTTPException(404, 'Scope group not found')
        if action is not None:
            con.execute('UPDATE scope_rules SET action=? WHERE engagement_id=? AND tag=?', (action, eid, tag))
        if hidden is not None:
            con.execute('UPDATE scope_rules SET hidden=? WHERE engagement_id=? AND tag=?', (int(hidden), eid, tag))
        rules, limited = policy(con, eid)
        cancelled = cancel_jobs_outside_policy(con, eid, actor['name'], rules, limited, 'Scope group changed') if action == 'exclude' else []
        audit(con, eid, actor['name'], 'scope.group_changed', {'tag': tag, 'action': action, 'hidden': hidden, 'cancelled_jobs': cancelled})
    return {'ok': True, 'cancelled_jobs': cancelled}


@app.delete('/api/e/{eid}/scope/groups/{tag}')
def delete_scope_group(eid: int, tag: str, request: Request):
    actor = auth.access(request, eid, True)
    tag = scope_tag(tag)
    with connect() as con:
        count = con.execute('DELETE FROM scope_rules WHERE engagement_id=? AND tag=?', (eid, tag)).rowcount
        if not count:
            raise HTTPException(404, 'Scope group not found')
        from .scope_rules import policy
        rules, limited = policy(con, eid)
        cancelled = cancel_jobs_outside_policy(con, eid, actor['name'], rules, limited, 'Included scope group removed') if limited else []
        audit(con, eid, actor['name'], 'scope.group_removed', {'tag': tag, 'rules': count, 'cancelled_jobs': cancelled})
    return {'ok': True, 'removed': count, 'cancelled_jobs': cancelled}


@app.get('/api/e/{eid}/scope/groups/{tag}/targets')
def scope_group_targets(eid: int, tag: str, request: Request):
    auth.access(request, eid)
    tag = scope_tag(tag)
    with connect() as con:
        rules = rows(con, 'SELECT action,target,hidden FROM scope_rules WHERE engagement_id=? AND tag=? ORDER BY target', (eid, tag))
    if not rules:
        raise HTTPException(404, 'Scope group not found')
    if any(r['action'] == 'exclude' for r in rules):
        raise ValueError('Switch this group to included before scanning it')
    if any(r['hidden'] for r in rules):
        raise ValueError('Unhide this group before scanning it')
    targets = list(dict.fromkeys(r['target'] for r in rules))
    return {'tag': tag, 'targets': targets, 'count': len(targets), 'source': 'scope_group'}


@app.post('/api/e/{eid}/scope')
def add_scope(eid: int, request: Request, body: dict = Body(...)):
    actor = auth.access(request, eid, True)
    action, target = body.get('action'), str(body.get('target', '')).strip()
    if action not in ('include', 'exclude'):
        raise ValueError('Choose include or exclude')
    from .scope_rules import parse_targets, matcher
    targets = parse_targets(body.get('targets', target))
    tag = scope_tag(body.get('tag', body.get('reason', '')))
    hidden = body.get('hidden', action == 'exclude')
    if not isinstance(hidden, bool):
        raise ValueError('hidden must be true or false')
    with connect() as con:
        matches = matcher(targets)
        affected = sum(matches(r['value']) for r in con.execute('SELECT value FROM assets WHERE engagement_id=?', (eid,)))
        if body.get('preview') is True:
            return {'targets': targets, 'matched_assets': affected}
        added = 0
        # A tag is an operational group: new entries adopt one shared state.
        con.execute('UPDATE scope_rules SET action=?,hidden=? WHERE engagement_id=? AND tag=?', (action, int(hidden), eid, tag))
        for value in targets:
            existing = con.execute('SELECT id FROM scope_rules WHERE engagement_id=? AND tag=? AND target=?', (eid, tag, value)).fetchone()
            if not existing:
                con.execute('INSERT INTO scope_rules(engagement_id,action,target,reason,tag,hidden) VALUES (?,?,?,?,?,?)', (eid, action, value, '', tag, int(hidden)))
                added += 1
        from .scope_rules import policy
        rules, limited = policy(con, eid)
        if action == 'exclude':
            cancel_jobs_outside_policy(con, eid, actor['name'], rules, limited, 'Scope exclusion')
        audit(con, eid, actor['name'], 'scope.added', {'action': action, 'targets': targets, 'tag': tag, 'hidden': hidden})
    return {'ok': True, 'added': added, 'matched_assets': affected}


@app.delete('/api/e/{eid}/scope/{sid}')
def delete_scope(eid: int, sid: int, request: Request):
    actor = auth.access(request, eid, True)
    with connect() as con:
        old = one(con, 'scope_rules', sid, eid)
        con.execute('DELETE FROM scope_rules WHERE id=?', (sid,))
        from .scope_rules import policy
        rules, limited = policy(con, eid)
        cancelled = cancel_jobs_outside_policy(con, eid, actor['name'], rules, limited, 'Included scope rule removed') if limited and old['action'] == 'include' else []
        audit(con, eid, actor['name'], 'scope.removed', {**old, 'cancelled_jobs': cancelled})
    return {'ok': True, 'cancelled_jobs': cancelled}


@app.get('/api/e/{eid}/views')
def views(eid: int, request: Request):
    auth.access(request, eid)
    with connect() as con:
        return rows(con, 'SELECT * FROM saved_views WHERE engagement_id=?', (eid,))


@app.post('/api/e/{eid}/views')
def save_view(eid: int, request: Request, body: dict = Body(...)):
    auth.access(request, eid, True)
    with connect() as con:
        con.execute('INSERT INTO saved_views(engagement_id,name,filters) VALUES (?,?,?)', (eid, str(body.get('name', 'Saved view'))[:100], dump(body.get('filters', {}))))
    return {'ok': True}


@app.get('/api/e/{eid}/profiles')
def profiles(eid: int, request: Request):
    auth.access(request, eid)
    return [{'id': key, **value, 'installed': bool(executable(value['tool']))} for key, value in PROFILES.items()]


@app.post('/api/e/{eid}/jobs/preview')
@app.post('/api/e/{eid}/jobs')
def create_job(eid: int, request: Request, body: dict = Body(...)):
    actor = auth.access(request, eid, True)
    if 'command' in body or 'draft_id' in body:
        raise ValueError('Draft text cannot be executed. Submit a structured profile for validation.')
    config = body.get('config', {})
    if not isinstance(config, dict) or any(str(k).startswith('_') for k in config):
        raise ValueError('Invalid scan configuration')
    config = dict(config)
    with connect() as con:
        from .scope_rules import policy
        rules, limited = policy(con, eid)
        additions = []
        if body.get('add_scope') is True:
            for target in body.get('targets', []):
                kind, value = identity(target)
                if kind not in ('ip','hostname','url'):
                    raise ValueError('Enter individual IPs, hostnames or URLs')
                if not any(r['action']=='include' and r['target']==value for r in rules):
                    rule = {'action':'include','target':value,'tag':'scan-added','hidden':0}
                    rules.append(rule)
                    additions.append(rule)
        plan = prepare(body.get('profile'), body.get('targets', []), config, rules, limit_to_included=limited)
        if body.get('profile') == 'gowitness-web':
            from .web_inventory import candidate_snapshot
            with connect(visible_eid=eid) as visible:
                candidates = candidate_snapshot(visible,eid,plan['targets'],config)
            if not request.url.path.endswith('/preview') and body.get('web_candidates') is not None and body['web_candidates'] != candidates:
                raise ValueError('Observed ports changed since preview; preview again')
            config['_web_candidates'] = candidates
            plan['web_candidates'] = candidates
            plan['stages'] = ['HTTP/HTTPS validation', 'gowitness screenshots and report']
        if request.url.path.endswith('/preview'):
            import shlex
            plan['command_text'] = shlex.join(plan['command'])
            plan['scope_additions'] = [r['target'] for r in additions]
            return plan
        if 'resolutions' in plan:
            if 'resolutions' in body and body['resolutions'] != plan['resolutions']:
                raise ValueError('DNS changed since preview; preview again to review the addresses')
            config['_nmap_snapshot'] = plan['resolutions']
        for rule in additions:
            if rule['target'] not in plan['targets']:
                continue
            con.execute('INSERT INTO scope_rules(engagement_id,action,target,reason,tag,hidden) VALUES (?,?,?,?,?,?)', (eid, 'include', rule['target'], '', rule['tag'], 0))
            audit(con,eid,actor['name'],'scope.added',rule)
        jid = con.execute('INSERT INTO jobs(engagement_id,profile,actor,command,targets,excluded,config,created_at) VALUES (?,?,?,?,?,?,?,?)',
                          (eid, body['profile'], actor['name'], dump(plan['command']), dump(plan['targets']), dump(plan['excluded']), dump(config), now())).lastrowid
        folder = data_dir() / 'jobs' / str(jid)
        exact = prepare(body['profile'], plan['targets'], config, rules, folder, limited)
        con.execute('UPDATE jobs SET command=? WHERE id=?', (dump(exact['command']), jid))
        audit(con, eid, actor['name'], 'job.queued', {'id': jid, 'profile': body['profile']})
    return {'id': jid}


@app.get('/api/e/{eid}/jobs')
def jobs(eid: int, request: Request):
    auth.access(request, eid)
    with connect(visible_eid=eid) as con:
        return rows(con, 'SELECT * FROM jobs WHERE engagement_id=? ORDER BY id DESC', (eid,))


@app.post('/api/e/{eid}/assets/{aid}/scan')
def scan_asset(eid: int, aid: int, request: Request):
    actor = auth.access(request, eid, True)
    with connect() as con:
        con.execute('BEGIN IMMEDIATE')
        asset = one(con, 'assets', aid, eid)
        if asset['kind'] != 'ip':
            raise ValueError('Choose a specific IP address to scan')
        from .scope_rules import policy
        rules, limited = policy(con, eid)
        detail = query.detail(con, asset)
        names = [r['value'] for r in detail['relationships'] if r['asset_kind']=='hostname']
        if any(in_rule(value, r['target']) for r in rules if r['action']=='exclude' for value in [asset['value'], *names]):
            raise ValueError('IP or associated hostname matches a scope exclusion')
        for job in rows(con, "SELECT id,targets FROM jobs WHERE engagement_id=? AND profile='nmap-services' AND status IN ('queued','running')", (eid,)):
            if asset['value'] in json.loads(job['targets']):
                return {'id': job['id'], 'existing': True}
        owners = [aid] + [r['id'] for r in detail['relationships'] if r['asset_kind']=='hostname']
        observed = con.execute('''SELECT DISTINCT ep.port FROM endpoints ep JOIN observations ob ON ob.endpoint_id=ep.id
            JOIN records rr ON rr.id=ob.record_id JOIN imports ii ON ii.id=rr.import_id WHERE ii.active=1
            AND ep.protocol='tcp' AND ep.asset_id IN (''' + ','.join('?' for _ in owners) + ')', owners).fetchall()
        ports = sorted(set(map(int, DEFAULT_NMAP_PORTS.split(','))) | {r[0] for r in observed})
        config = {'ports': ','.join(map(str, ports)), 'geolocate': True, 'asset_id': aid}
        plan = prepare('nmap-services', [asset['value']], config, rules, limit_to_included=limited)
        jid = con.execute('INSERT INTO jobs(engagement_id,profile,actor,command,targets,excluded,config,created_at) VALUES (?,?,?,?,?,?,?,?)',
            (eid, 'nmap-services', actor['name'], dump(plan['command']), dump(plan['targets']), '[]', dump(config), now())).lastrowid
        exact = prepare('nmap-services', plan['targets'], config, rules, data_dir() / 'jobs' / str(jid), limited)
        con.execute('UPDATE jobs SET command=? WHERE id=?', (dump(exact['command']), jid))
        audit(con, eid, actor['name'], 'job.queued', {'id':jid, 'asset_id':aid, 'ports':ports, 'geolocate':True})
    return {'id':jid, 'existing':False}


@app.post('/api/e/{eid}/jobs/{jid}/cancel')
def cancel(eid: int, jid: int, request: Request):
    actor = auth.access(request, eid, True)
    with connect() as con:
        job = one(con, 'jobs', jid, eid)
        if job['status'] == 'queued':
            con.execute("UPDATE jobs SET status='cancelled',cancel_requested=1,ended_at=? WHERE id=?", (now(), jid))
        elif job['status'] == 'running':
            con.execute('UPDATE jobs SET cancel_requested=1 WHERE id=?', (jid,))
        audit(con, eid, actor['name'], 'job.cancel_requested', {'id': jid})
    return {'ok': True}


@app.get('/api/e/{eid}/jobs/{jid}/logs')
def logs(eid: int, jid: int, request: Request, stream: str = 'stdout', offset: int = 0, download: bool = False):
    auth.access(request, eid)
    with connect(visible_eid=eid) as con:
        one(con, 'jobs', jid, eid)
    if stream not in ('stdout', 'stderr'):
        raise ValueError('Unknown log stream')
    path = data_dir() / 'jobs' / str(jid) / (stream + '.log')
    if not path.exists():
        return {'text': '', 'next': 0, 'total': 0}
    if download:
        return FileResponse(path, media_type='text/plain', filename=f'job-{jid}-{stream}.log')
    with path.open('rb') as file:
        file.seek(max(0, offset))
        text = file.read(100000)
    return {'text': text.decode(errors='replace'), 'next': max(0, offset) + len(text), 'total': path.stat().st_size}


@app.get('/api/e/{eid}/timeline')
def timeline(eid: int, request: Request, export: str = ''):
    auth.access(request, eid)
    with connect(visible_eid=eid) as con:
        events = [{'type': 'job', **r} for r in rows(con, 'SELECT * FROM jobs WHERE engagement_id=?', (eid,))]
        from .drafts import timeline_events
        events.extend(timeline_events(con, eid))
        for row in rows(con, 'SELECT * FROM imports WHERE engagement_id=?', (eid,)):
            metadata = json.loads(row['metadata'])
            events.append({'type': 'import', 'id': row['id'], 'actor': row['actor'], 'profile': row['format'], 'created_at': row['created_at'], 'started_at': timestamp(metadata.get('start')), 'ended_at': metadata.get('scan_end'), 'ingested_at': row['finished_at'], 'status': row['status'], 'command': redact_command(metadata.get('args', '')), 'filename': row['filename']})
        for event in events:
            event['event_at'] = event.get('started_at') or event['created_at']
        events.sort(key=lambda e: e['event_at'], reverse=True)
    if export == 'csv':
        stream = io.StringIO()
        fields = ['type', 'id', 'actor', 'profile', 'event_at', 'created_at', 'started_at', 'ended_at', 'ingested_at', 'status', 'command', 'exit_code', 'revision']
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction='ignore')
        writer.writeheader()
        for event in events:
            writer.writerow({key: "'" + value if isinstance(value, str) and value.startswith(('=', '+', '-', '@')) else value for key, value in event.items()})
        return Response(stream.getvalue(), media_type='text/csv', headers={'Content-Disposition': 'attachment; filename="vandal-timeline.csv"'})
    if export == 'json':
        return Response(dump(events), media_type='application/json', headers={'Content-Disposition': 'attachment; filename="vandal-timeline.json"'})
    return events


@app.get('/api/e/{eid}/scan-targets')
def scan_target_list(eid: int, request: Request, ids: str = '', q: str = '', mode: str = 'auto', source: str = '', status: str = '', job_id: int = 0):
    auth.access(request,eid)
    from .web_inventory import selection
    selected = [int(x) for x in ids.split(',') if x] if ids else None
    if source == 'web' and not selected:
        from .web_inventory import visible_captures
        with connect() as con: captures=visible_captures(con,eid)
        if job_id: captures=[r for r in captures if r['job_id']==job_id]
        seen=set();captures=[r for r in captures if not (r['url'] in seen or seen.add(r['url']))]
        if status: captures=[r for r in captures if r['status']==status]
        if q: captures=[r for r in captures if q.lower() in ' '.join(str(r[k]) for k in ('url','host','ips','title','technologies','status_code')).lower()]
        targets=list(dict.fromkeys(r['url'] for r in captures))
        if len(targets)>5000: raise ValueError('More than 5,000 matching targets; narrow the filters')
        return {'targets':targets,'count':len(targets),'source':'filters'}
    with connect(visible_eid=eid) as con:
        items=selection(con,eid,{'q':q,'mode':mode},selected)
    if len(items)>5000: raise ValueError('More than 5,000 matching targets; narrow the filters')
    return {'targets':[a['value'] for a in items], 'count':len(items), 'source':'selection' if selected else 'filters'}


@app.get('/api/e/{eid}/web')
def web_results(eid: int, request: Request, q: str = '', status: str = '', job_id: int = 0, page: int = 1, history: bool = False, export: bool = False):
    auth.access(request,eid)
    from .web_inventory import visible_captures
    with connect() as con: items=visible_captures(con,eid)
    if job_id: items=[r for r in items if r['job_id']==job_id]
    if not history:
        seen=set();items=[r for r in items if not (r['url'] in seen or seen.add(r['url']))]
    if status: items=[r for r in items if r['status']==status]
    if q: items=[r for r in items if q.lower() in ' '.join(str(r[k]) for k in ('url','host','ips','title','technologies','status_code')).lower()]
    if export:
        return Response('\n'.join(dump({'url':r['url'],'status':r['status'],'validation':json.loads(r['validation']),'gowitness':json.loads(r['report'])}) for r in items), media_type='application/x-ndjson',headers={'Content-Disposition':'attachment; filename="web-report.jsonl"'})
    page=max(1,page)
    return {'items':[{k:v for k,v in r.items() if k not in ('report','validation')} for r in items[(page-1)*24:page*24]],'total':len(items),'page':page,'size':24}


@app.get('/api/e/{eid}/web/{wid}')
def web_result(eid: int, wid: int, request: Request):
    auth.access(request,eid)
    from .web_inventory import visible_captures
    with connect() as con:
        item=next((r for r in visible_captures(con,eid) if r['id']==wid),None)
    if not item: raise HTTPException(404,'Web capture not found')
    return item


@app.get('/api/e/{eid}/web/{wid}/screenshot')
def web_screenshot(eid: int, wid: int, request: Request):
    item=web_result(eid,wid,request)
    name=item['screenshot']
    if not name or Path(name).name!=name: raise HTTPException(404,'Screenshot not found')
    folder=(data_dir()/'jobs'/str(item['job_id'])/'screenshots').resolve()
    path=(folder/name).resolve()
    if path.parent!=folder or not path.is_file() or path.suffix not in ('.jpeg','.jpg','.png'): raise HTTPException(404,'Screenshot not found')
    return FileResponse(path,media_type='image/png' if path.suffix=='.png' else 'image/jpeg')


@app.get('/api/e/{eid}/jobs/{jid}/steps')
def job_steps(eid: int, jid: int, request: Request):
    auth.access(request,eid)
    with connect(visible_eid=eid) as con:
        one(con,'jobs',jid,eid)
        return rows(con,'SELECT * FROM job_steps WHERE job_id=? ORDER BY id',(jid,))
