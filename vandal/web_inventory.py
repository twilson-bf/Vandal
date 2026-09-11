"""Inventory selection, web candidate snapshots, and exclusion-aware reports."""
import json
from urllib.parse import urlsplit
from .db import rows
from .identity import identity, in_rule
from .inventory import build, matches, tokens
from .nmap_options import number


def selection(con, eid, params, ids=None):
    assets = build(con,eid)
    if ids:
        wanted = set(ids)
        items = [a for a in assets if a['id'] in wanted and a['kind'] in ('ip','hostname','url')]
        if {a['id'] for a in items} != wanted: raise ValueError('Some selected assets are no longer visible; refresh the selection')
    else:
        mode = params.get('mode','auto')
        if mode not in ('auto','ip','hostname'): raise ValueError('Invalid inventory mode')
        terms = tokens(params.get('q',''))
        items = [a for a in assets if matches(a,terms) and (a['kind']==mode if mode!='auto' else a['kind']=='hostname' or (a['kind']=='ip' and not any(b['kind']=='hostname' for b in a['associated'])))]
    return sorted(items,key=lambda a:a['value'])


def candidate_snapshot(con, eid, targets, config):
    # Keep ports per owner: a hostname may inherit ports only from its linked IPs.
    byvalue = {a['value']:a for a in build(con,eid)}
    result = []
    for target in targets:
        kind,value = identity(target)
        if kind not in ('hostname','ip','url'): raise ValueError('Web capture requires hostnames, IPs, or HTTP(S) origins')
        host = urlsplit(value).hostname if kind=='url' else value
        a = byvalue.get(target) or byvalue.get(host)
        ports = {80,443} if config.get('web_defaults',True) else set()
        if a: ports.update(s['port'] for s in a['services'] if s['protocol']=='tcp' and s['state'] in ('open','open|filtered'))
        if kind=='url': ports.add(urlsplit(value).port)
        if not ports: continue
        formatted = '['+host+']' if ':' in host else host
        for port in sorted(ports):
            for scheme in ('http','https'):
                result.append({'url':f'{scheme}://{formatted}:{port}', 'host':host,'port':port,'asset_id':a['id'] if a else None})
    result = list({r['url']:r for r in result}.values())
    if len(result)>20000: raise ValueError('More than 20,000 candidate URLs; narrow the filters or selection')
    if not result: raise ValueError('No candidate ports. Include ports 80/443 or select hosts with observed TCP ports')
    return result


def validate_config(config):
    if 'web_defaults' in config and not isinstance(config['web_defaults'],bool): raise ValueError('web_defaults must be true or false')
    if 'full_page' in config and not isinstance(config['full_page'],bool): raise ValueError('full_page must be true or false')
    return {k:int(number(config,k,d,lo,hi)) for k,d,lo,hi in [('web_threads',2,1,10),('web_timeout',30,5,120),('web_delay',2,0,15),('probe_timeout',5,1,30)]}


def visible_captures(con,eid):
    rules = rows(con,"SELECT * FROM scope_rules WHERE engagement_id=? AND action='exclude'",(eid,))
    from .scope_rules import matcher
    excluded = matcher([r['target'] for r in rules])
    result = []
    for row in rows(con,'SELECT * FROM web_captures WHERE engagement_id=? ORDER BY id DESC',(eid,)):
        values = [row['host'],*json.loads(row['ips'])]
        if row['final_url']:
            values.append(urlsplit(row['final_url']).hostname or '')
        if any(excluded(v) for v in values): continue
        result.append(row)
    return result
