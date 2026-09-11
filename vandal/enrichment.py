"""Restartable low-rate metadata enrichment, independent of scan execution."""
import ipaddress
import json
import re
import time
from urllib.error import HTTPError
from urllib.request import urlopen
from .db import connect, now, dump
from .query import VISIBLE
from .geolocation import locate


def cve_ids(text):
    return sorted(set(re.findall(r'\bCVE-\d{4}-\d{4,}\b', text.upper())))


def apply_cached_geo(con, ip, result):
    data=result.get('response',{})
    if result.get('status')!='completed':return
    network=data.get('connection') or {}
    con.execute("""UPDATE assets SET country=?,city=?,latitude=?,longitude=?,geo_source=?,
        asn=CASE WHEN ?!='' THEN ? ELSE asn END,provider=CASE WHEN ?!='' THEN ? ELSE provider END
        WHERE kind='ip' AND value=? AND (latitude IS NULL OR longitude IS NULL)""",
        (data.get('country') or 'Unknown',data.get('city') or '',data['latitude'],data['longitude'],result.get('source',''),
         'AS'+str(network['asn']) if network.get('asn') else '', 'AS'+str(network['asn']) if network.get('asn') else '',
         network.get('org') or '',network.get('org') or '',ip))


def enqueue(con):
    for row in con.execute("SELECT a.value FROM assets a WHERE a.kind='ip' AND (a.latitude IS NULL OR a.longitude IS NULL) AND "+VISIBLE).fetchall():
        ip=row['value'];public=ipaddress.ip_address(ip).is_global
        con.execute('INSERT OR IGNORE INTO enrichment(kind,key,status) VALUES (?,?,?)',('geo',ip,'queued' if public else 'skipped'))
        cached=con.execute("SELECT result FROM enrichment WHERE kind='geo' AND key=? AND status='completed'",(ip,)).fetchone()
        if cached:apply_cached_geo(con,ip,json.loads(cached['result']))
    for row in con.execute("SELECT title FROM interests WHERE category='potential CVE'").fetchall():
        for cve in cve_ids(row['title']):
            con.execute("INSERT OR IGNORE INTO enrichment(kind,key) VALUES ('cve',?)",(cve,))
    con.execute("UPDATE enrichment SET status='queued' WHERE kind='cve' AND status='completed' AND next_attempt<?",(time.time(),))


def fetch_cve(cve):
    if not re.fullmatch(r'CVE-\d{4}-\d{4,}',cve):raise ValueError('Invalid CVE ID')
    with urlopen('https://cveawg.mitre.org/api/cve/'+cve,timeout=12) as response:
        raw=json.loads(response.read(2_000_000))
    meta=raw.get('cveMetadata',{})
    if meta.get('cveId')!=cve:raise ValueError('CVE response identifier mismatch')
    cna=raw.get('containers',{}).get('cna',{})
    containers=[cna,*raw.get('containers',{}).get('adp',[])]
    scores=[]
    for container in containers:
        for metric in container.get('metrics',[]):
            for key in ('cvssV4_0','cvssV3_1','cvssV3_0','cvssV2_0'):
                if key in metric:scores.append({**metric[key],'source':container.get('providerMetadata',{}).get('shortName','CNA')})
    return {'id':cve,'title':cna.get('title',''),'state':meta.get('state'),
        'description':next((d['value'] for d in cna.get('descriptions',[]) if d.get('lang','').startswith('en')),''),
        'scores':scores,'affected':cna.get('affected',[]),'references':[r['url'] for r in cna.get('references',[]) if str(r.get('url','')).startswith(('https://','http://'))],
        'published':meta.get('datePublished'),'modified':meta.get('dateUpdated'),'source':'CVE Program','raw':raw}


def process_one(kind):
    with connect() as con:
        con.execute('BEGIN IMMEDIATE')
        item=con.execute("SELECT * FROM enrichment WHERE kind=? AND status IN ('queued','failed') AND next_attempt<=? ORDER BY attempts,key LIMIT 1",(kind,time.time())).fetchone()
        if not item:return False
        item=dict(item)
        con.execute("UPDATE enrichment SET status='running',attempts=attempts+1 WHERE kind=? AND key=?",(kind,item['key']))
    try:
        if kind=='cve': result=fetch_cve(item['key'])
        else:
            with connect() as con:
                asset=con.execute("SELECT engagement_id FROM assets WHERE kind='ip' AND value=? AND (latitude IS NULL OR longitude IS NULL)",(item['key'],)).fetchone()
            result=locate(asset['engagement_id'],item['key']) if asset else {'status':'skipped','reason':'Already geolocated'}
        status='completed' if result.get('status')!='skipped' else 'skipped'
        with connect() as con:
            if kind=='geo':apply_cached_geo(con,item['key'],result)
            con.execute('UPDATE enrichment SET status=?,result=?,error=?,updated_at=?,next_attempt=? WHERE kind=? AND key=?',
                (status,dump(result),'',now(),time.time()+86400,kind,item['key']))
    except Exception as exc:
        delay=min(86400,300*2**min(item['attempts'],8))
        if isinstance(exc,HTTPError) and exc.code==429:delay=86400
        with connect() as con:
            con.execute("UPDATE enrichment SET status='failed',error=?,updated_at=?,next_attempt=? WHERE kind=? AND key=?",(str(exc),now(),time.time()+delay,kind,item['key']))
            if isinstance(exc,HTTPError) and exc.code==429:
                con.execute("UPDATE enrichment SET next_attempt=MAX(next_attempt,?) WHERE kind=? AND status IN ('queued','failed')",(time.time()+delay,kind))
    return True


def run(stop):
    with connect() as con:
        con.execute("UPDATE enrichment SET status='queued' WHERE status='running'")
    last_queue=0
    while not stop.is_set():
        try:
            if time.monotonic()-last_queue>60:
                with connect() as con:enqueue(con)
                last_queue=time.monotonic()
            process_one('cve')
            if stop.is_set():break
            with connect() as con:
                count=con.execute("SELECT count(*) FROM enrichment WHERE kind='geo' AND updated_at>=date('now') AND status IN ('completed','failed')").fetchone()[0]
            if count<900:process_one('geo')
        except Exception as exc:
            print(f'Enrichment worker: {exc}',flush=True)
        stop.wait(2)
