"""Project host/service summaries and a deliberately small search language."""
from collections import Counter, defaultdict
import ipaddress
import json
import shlex
import re
from .db import rows
from .identity import in_rule, root_domain
from .query import VISIBLE

KEYS = {'hostname','ip','net','port','product','service','country','org','asn','source','has','scanned','scope','scope_tag','coverage','cve'}

def tokens(text):
    try:
        parts = shlex.split(text)
    except ValueError as exc:
        raise ValueError('Search: ' + str(exc))
    result=[]
    for part in parts:
        negative=part.startswith('-'); term=part[1:] if negative else part
        key, sep, value=term.partition(':')
        if not sep: key,value='text',term
        if key not in KEYS | {'text'}: raise ValueError(f'Unknown search filter: {key}')
        if not value: raise ValueError(f'Missing value for {key}')
        if key=='port' and (not value.isdigit() or not 1<=int(value)<=65535): raise ValueError('port requires a number from 1 to 65535')
        choices={'has':{'ports','vuln','pwned'},'scanned':{'true','false'},'scope':{'included','excluded','unassigned'},'coverage':{'scanned','active','passive','unscanned'}}
        if key in choices and value not in choices[key]: raise ValueError(f'{key} accepts: '+', '.join(sorted(choices[key])))
        if key in ('ip','net'):
            try: ipaddress.ip_network(value,strict=False)
            except ValueError: raise ValueError(f'Invalid {key}: {value}')
        result.append({'key':key,'value':value,'negative':negative,'text':part})
    return result


def passive_finding(item):
    return not item['confirmed'] and str(item.get('source_key') or '').startswith('shodan:')


def build(con,eid,hide_passive=False):
    assets=rows(con,'SELECT a.* FROM assets a WHERE a.engagement_id=? AND '+VISIBLE,(eid,))
    byid={a['id']:a for a in assets}; linked=defaultdict(set)
    for r in con.execute('SELECT rel.source_id,rel.target_id FROM relationships rel JOIN records r ON r.id=rel.record_id JOIN imports i ON i.id=r.import_id WHERE r.engagement_id=? AND i.active=1',(eid,)):
        if r[0] in byid and r[1] in byid:
            linked[r[0]].add(r[1]);linked[r[1]].add(r[0])
    sources=defaultdict(set); first={};last={};scanned=set(); lastscan={}
    for r in con.execute('''SELECT ra.asset_id,i.format,i.created_at,r.observed_at,json_extract(r.fields,'$.module') FROM record_assets ra JOIN records r ON r.id=ra.record_id JOIN imports i ON i.id=r.import_id WHERE r.engagement_id=? AND i.active=1''',(eid,)):
        aid,source,created,observed,module=r
        if isinstance(module,str):sources[aid].add(module)
        sources[aid].add(source);first[aid]=min(first.get(aid,created),created)
        when=observed or created;last[aid]=max(last.get(aid,when),when)
        if source.startswith(('nmap','nessus')):
            scanned.add(aid);lastscan[aid]=max(lastscan.get(aid,when),when)
    observations=defaultdict(list)
    for r in rows(con,'''SELECT ep.asset_id,ep.port,ep.protocol,ob.*,r.raw,r.import_id,i.filename,i.format AS source_format,i.created_at FROM observations ob JOIN endpoints ep ON ep.id=ob.endpoint_id JOIN records r ON r.id=ob.record_id JOIN imports i ON i.id=r.import_id WHERE r.engagement_id=? AND i.active=1 ORDER BY COALESCE(ob.observed_at,i.created_at) DESC,ob.id DESC''',(eid,)):
        if hide_passive and r['evidence']=='passive':continue
        observations[r['asset_id']].append(r)
    interests=rows(con,'SELECT * FROM interests WHERE engagement_id=?',(eid,)); assigned=defaultdict(list)
    for item in interests:
        if hide_passive and passive_finding(item):continue
        for aid in json.loads(item['asset_ids']): assigned[aid].append(item)
    rules=rows(con,'SELECT * FROM scope_rules WHERE engagement_id=?',(eid,))
    from .scope_rules import matcher
    is_excluded=matcher([r['target'] for r in rules if r['action']=='exclude'])
    is_included=matcher([r['target'] for r in rules if r['action']=='include'])
    tagged=defaultdict(list)
    for rule in rules:
        tagged[rule.get('tag') or 'untagged'].append(rule['target'])
    tag_matchers={tag:matcher(targets) for tag,targets in tagged.items()}
    for a in assets:
        aid=a['id']; associated=[byid[b] for b in linked[aid] if byid[b]['kind'] in ('hostname','ip')]
        a['associated']=[{'id':b['id'],'value':b['value'],'kind':b['kind']} for b in sorted(associated,key=lambda b:b['value'])]
        # Only hostnames inherit IP summaries; IPs never inherit a different virtual host's ports.
        ownerids=[aid]+([b['id'] for b in associated if b['kind']=='ip'] if a['kind']=='hostname' else [])
        groups=defaultdict(list)
        for owner in ownerids:
            for o in observations[owner]:groups[(owner,o['protocol'],o['port'])].append(o)
        a['services']=[]
        for (owner,protocol,port), obs in groups.items():
            obs.sort(key=lambda o:(o['observed_at'] or o['created_at'],o['id']),reverse=True)
            direct=[o for o in obs if o['evidence']!='passive'];current=(direct or obs)[0]
            a['services'].append({'owner_id':owner,'owner':byid[owner]['value'],'port':port,'protocol':protocol,'state':current['state'],
                'service':current['service'],'product':current['product'],'evidence':current['evidence'],'observed_at':current['observed_at'],
                'count':len(obs),'conflict':len({o['state'] for o in obs})>1,'record_id':current['record_id'],
                '_observations':obs})
        a['services'].sort(key=lambda s:(s['port'],s['protocol'],s['owner']))
        a['findings']=assigned[aid]
        a['potential']=sum(not f['confirmed'] and f['category']=='potential CVE' and f['status']!='dismissed' for f in a['findings'])
        a['confirmed']=sum(bool(f['confirmed']) for f in a['findings'])
        a['sources']=sorted(sources[aid]);a['first_seen']=first.get(aid);a['last_seen']=last.get(aid)
        if hide_passive:
            a['sources']=sorted({o['source_format'] for owner in ownerids for o in observations[owner]} | {s for owner in ownerids for s in sources[owner] if s.startswith(('nmap','nessus'))})
        a['last_scan']=max((lastscan[x] for x in ownerids if x in lastscan),default=None)
        a['coverage']='scanned' if any(x in scanned for x in ownerids) else 'passive' if any(s['evidence']=='passive' for s in a['services']) else 'unscanned'
        scope_values=[a['value'],*(b['value'] for b in associated)]
        a['scope_tags']=sorted(tag for tag,match in tag_matchers.items() if any(match(value) for value in scope_values))
        a['scope']='excluded' if any(is_excluded(value) for value in scope_values) else 'included' if any(is_included(value) for value in scope_values) else 'unassigned'
    return assets


def matches(a,terms):
    names=[a['value']] if a['kind']=='hostname' else [b['value'] for b in a['associated'] if b['kind']=='hostname']
    ips=[a['value']] if a['kind']=='ip' else [b['value'] for b in a['associated'] if b['kind']=='ip']
    def observation(o,t):
        k,v=t['key'],t['value'].lower()
        return str(o['port'])==v and o['state']=='open' and o['_endpoint_open'] if k=='port' else v in str(o.get('product' if k=='product' else 'service','')).lower()
    service_terms=[t for t in terms if t['key'] in ('port','product','service') and not t['negative']]
    # Port searches follow the retained endpoint state, as the port facet does.
    allobs=[{**o,'_endpoint_open':s['state']=='open'} for s in a['services'] for o in s['_observations']]
    if service_terms and not any(all(observation(o,t) for t in service_terms) for o in allobs):return False
    for t in terms:
        k,v=t['key'],t['value'].lower()
        if k in ('port','product','service'):found=any(observation(o,t) for o in allobs)
        elif k=='hostname':found=any(n==v or n.endswith('.'+v.removeprefix('*.')) for n in names)
        elif k in ('ip','net'):found=any(ipaddress.ip_address(ip) in ipaddress.ip_network(v,strict=False) for ip in ips)
        elif k=='has':found=any(s['state']=='open' for s in a['services']) if v=='ports' else bool(a.get('pwned')) if v=='pwned' else bool(a['potential'] or a['confirmed'])
        elif k=='scanned':found=(a['coverage']=='scanned')==(v=='true')
        elif k in ('scope','coverage'):found=a[k]==v
        elif k=='scope_tag':found=any(tag.lower()==v for tag in a.get('scope_tags',[]))
        elif k=='source':found=any(v in s for s in a['sources'])
        elif k=='cve':found=any(v in f['title'].lower() for f in a['findings'])
        elif k in ('country','org','asn'):found=v in str(a.get('provider' if k=='org' else k,'')).lower()
        else:found=v in (' '.join([a['value'],a['provider'],a['tags'],*names,*ips]+[str(o.get('raw','')) for o in allobs])).lower()
        if found==t['negative']:return False
    return True


def clean(a):
    return {**a,'services':[{k:v for k,v in s.items() if not k.startswith('_')} for s in a['services']]}


def search(con,eid,params,projected=False):
    terms=tokens(params.get('q',''));mode=params.get('mode','ip')
    if mode not in ('ip','hostname','auto'):raise ValueError('mode must be ip, hostname or auto')
    def included(a):
        if mode!='auto':return a['kind']==mode
        return a['kind']=='hostname' or (a['kind']=='ip' and not any(b['kind']=='hostname' for b in a['associated']))
    hide_passive=params.get('hide_passive')=='1'
    if projected:
        from .projection import build as project, host_rows, public
        items=[a for a in host_rows(project(con,eid,hide_passive),hide_passive,mode) if matches(a,terms)]
    else:
        items=[a for a in build(con,eid,hide_passive) if included(a) and (not hide_passive or a['coverage']=='scanned' or a['services'] or any(f['status']!='dismissed' for f in a['findings'])) and matches(a,terms)]
    facets={}
    for key in ('country','domain','coverage','scope'):
        facets[key]=Counter(a[key] for a in items if a[key]).most_common(8)
    facets['scope_tag']=Counter(tag for a in items for tag in a.get('scope_tags',[])).most_common()
    facets['domain']=Counter(d for a in items for d in ({a['domain']} if a['kind']=='hostname' else {root_domain(b['value']) for b in a['associated'] if b['kind']=='hostname'}) if d).most_common()
    facets['org']=Counter(a['provider'] for a in items if a['provider']).most_common(8)
    cve_counts=Counter(c for a in items for c in {m for f in a['findings'] for m in re.findall(r'CVE-\d{4}-\d{4,}', f['title'])})
    cve_scores={}
    for entry in con.execute("SELECT key,result FROM enrichment WHERE kind='cve' AND status='completed'"):
        if entry['key'] not in cve_counts:continue
        try:
            scores=[float(s['baseScore']) for s in json.loads(entry['result']).get('scores',[]) if s.get('baseScore') is not None]
            cve_scores[entry['key']]=max((s for s in scores if 0<=s<=10),default=-1)
        except (ValueError,TypeError,KeyError):pass
    facets['cve']=sorted(cve_counts.items(),key=lambda item:(-cve_scores.get(item[0],-1),item[0]))
    facets['port']=Counter(p for a in items for p in {s['port'] for s in a['services'] if s['state']=='open'}).most_common()
    facets['service']=Counter(p for a in items for p in {v['service'] for s in a['services'] for v in s.get('variants',[s]) if v['service']}).most_common()
    facets['source']=Counter(p for a in items for p in set(a['sources'])).most_common(8)
    domain_groups=[]
    if params.get('domain_summary')=='1':
        groups=defaultdict(list)
        for a in items:
            if a['kind']=='hostname' and a['domain']:
                groups[a['domain']].append(a)
        for domain, hosts in sorted(groups.items()):
            coverage=Counter(a['coverage'] for a in hosts)
            domain_groups.append({'domain':domain,'hostnames':len(hosts),
                'ips':len({b['value'] for a in hosts for b in a['associated'] if b['kind']=='ip'}),
                'with_ports':sum(any(s['state']=='open' for s in a['services']) for a in hosts),
                'scanned':coverage['scanned'],'passive':coverage['passive'],'unscanned':coverage['unscanned']})
            if projected:domain_groups[-1]['active']=coverage['active']
    sort=params.get('sort','address')
    if sort not in ('address','hostname','recent','vulns','open_ports'):raise ValueError('Unknown sort order')
    def key(a):
        if sort=='recent':return a['last_seen'] or ''
        if sort=='vulns':return a['potential']+a['confirmed']
        if sort=='open_ports':return (-len({(s['protocol'],s['port']) for s in a['services'] if s['state']=='open'}),a['value'])
        if sort=='hostname':return a['value'] if a['kind']=='hostname' else next((x['value'] for x in a['associated'] if x['kind']=='hostname'),'~'+a['value'])
        if mode=='auto':return (0,a['domain'],a['value']) if a['kind']=='hostname' else (1,ipaddress.ip_address(a['value']).version,int(ipaddress.ip_address(a['value'])))
        return (ipaddress.ip_address(a['value']).version,int(ipaddress.ip_address(a['value']))) if mode=='ip' else (a['domain'],a['value'])
    items.sort(key=key,reverse=sort in ('recent','vulns'))
    page=max(1,int(params.get('page',1)));size=min(100,max(1,int(params.get('size',25))))
    clean_item=public if projected else clean
    return {'items':[clean_item(a) for a in items[(page-1)*size:page*size]],'total':len(items),'page':page,'size':size,'facets':facets,'tokens':terms,'domain_groups':domain_groups,'cve_scores':cve_scores}
