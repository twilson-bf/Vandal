"""Current host inventory derived from evidence; never mutates source records.

Asset IDs and analyst item IDs remain stable. Group keys are deterministic, so
backfilling means projecting the existing evidence, not merging or deleting it.
"""
from collections import defaultdict
from datetime import datetime, timezone
import ipaddress
import json
import re

from .db import rows
from .inventory import build as evidence_build, passive_finding


def unpack(value, fallback=None):
    if not isinstance(value, str):
        return value if value is not None else fallback
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return fallback


def time_key(value):
    try:
        date = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        return date.replace(tzinfo=date.tzinfo or timezone.utc).timestamp()
    except (TypeError, ValueError, OverflowError):
        return 0


def observation_key(o):
    return (time_key(o.get('observed_at') or o.get('created_at')), o.get('record_id', 0), o.get('id', 0))


def address_views(con, eid, assets):
    byid = {a['id']: a for a in assets}
    byname = {a['value']: a for a in assets if a['kind'] == 'hostname'}
    events = defaultdict(dict)
    links = rows(con, '''SELECT rel.source_id,rel.target_id,rel.kind AS relation,
        r.id AS record_id,r.kind,r.observed_at,r.fields,i.id AS import_id,i.created_at,i.format
        FROM relationships rel JOIN records r ON r.id=rel.record_id
        JOIN imports i ON i.id=r.import_id WHERE r.engagement_id=? AND i.active=1''', (eid,))
    for r in links:
        source, target = byid.get(r['source_id']), byid.get(r['target_id'])
        if not source or not target or {source['kind'], target['kind']} != {'hostname', 'ip'}:
            continue
        host, ip = (source, target) if source['kind'] == 'hostname' else (target, source)
        fields = unpack(r['fields'], {})
        forward = r['relation'] != 'reverse-name'
        validated = r['kind'] == 'dns' and fields.get('rcode') in ('NOERROR', 'NODATA', 0)
        rank = 3 if validated and forward else 2 if r['relation'] == 'scanner-association' else 1 if forward else 0
        event = events[host['id']].setdefault(r['record_id'], {
            'record_id': r['record_id'], 'import_id': r['import_id'], 'at': r['observed_at'] or r['created_at'],
            'time_basis': 'observed' if r['observed_at'] else 'imported', 'rank': rank,
            'source': fields.get('resolver') or fields.get('module') or r['format'],
            'status': 'validated' if validated and forward else 'observed' if forward else 'reverse-name only',
            'ips': [], 'families': [], 'ttl': fields.get('ttl'), 'error': ''})
        if rank > event['rank']:
            event.update(rank=rank, status='validated' if validated else 'observed')
        if not any(old['id'] == ip['id'] for old in event['ips']):
            event['ips'].append({'id': ip['id'], 'value': ip['value']})
        family = ipaddress.ip_address(ip['value']).version
        if family not in event['families']:
            event['families'].append(family)
    # Include failed and empty DNS answers even though they produce no links.
    for r in rows(con, '''SELECT r.id,r.fields,r.observed_at,i.created_at,i.id AS import_id
            FROM records r JOIN imports i ON i.id=r.import_id
            WHERE r.engagement_id=? AND i.active=1 AND r.kind='dns' ''', (eid,)):
        fields = unpack(r['fields'], {})
        host = byname.get(str(fields.get('host', '')).lower().rstrip('.'))
        family = {'A': 4, 'AAAA': 6}.get(fields.get('query_type'))
        if not host or not family:
            continue
        valid = fields.get('rcode') in ('NOERROR', 'NODATA', 0) and not fields.get('error')
        event = events[host['id']].setdefault(r['id'], {
            'record_id': r['id'], 'import_id': r['import_id'], 'at': r['observed_at'] or r['created_at'],
            'time_basis': 'observed' if r['observed_at'] else 'imported', 'source': fields.get('resolver', 'DNS'),
            'ips': [], 'ttl': fields.get('ttl')})
        event.update(rank=3 if valid else -1, status='validated' if valid else 'validation failed',
                     families=[family], error=fields.get('error') or ('' if valid else str(fields.get('rcode', 'Unknown'))))
    result = {}
    for aid, values in events.items():
        history = sorted(values.values(), key=lambda e: (time_key(e['at']), e['record_id']), reverse=True)
        current, selected, family_selected = {}, [], {}
        for family in (4, 6):
            choices = [e for e in history if family in e['families'] and e['rank'] > 0]
            if not choices:
                continue
            # Prefer measured mappings; passive data never replaces a validated mapping.
            best = max(choices, key=lambda e: (e['rank'], time_key(e['at']), e['record_id']))
            selected.append(best)
            family_selected[family] = best
            for ip in best['ips']:
                if ipaddress.ip_address(ip['value']).version == family:
                    current[ip['id']] = ip
        selected_ids = {e['record_id'] for e in selected}
        for e in history:
            e['current'] = e['record_id'] in selected_ids
            e['reason'] = 'Current address evidence' if e['current'] else 'Validation failed; previous mapping retained' if e['rank'] < 0 else 'Reverse-name hint only' if e['rank'] == 0 else 'Superseded address evidence'
        latest = max(selected, key=lambda e: (time_key(e['at']), e['record_id']), default=None)
        failed = any(e['rank'] < 0 and any(family not in family_selected or time_key(e['at']) > time_key(family_selected[family]['at']) for family in e['families']) for e in history)
        expired = any(e['rank'] == 3 and isinstance(e.get('ttl'), (int, float)) and time_key(e['at']) + e['ttl'] < datetime.now(timezone.utc).timestamp() for e in selected)
        status = 'unvalidated' if not latest or latest['rank'] < 3 else 'stale' if failed or expired else 'validated'
        ordered = sorted(current.values(), key=lambda p: (ipaddress.ip_address(p['value']).version, int(ipaddress.ip_address(p['value']))))
        result[aid] = {'addresses': ordered, 'status': status, 'checked_at': latest['at'] if latest else None,
                       'history': history, 'primary_ip': ordered[0]['value'] if ordered else None}
    return result


def cve_groups(findings, host_id, scores):
    groups, other = {}, []
    for f in findings:
        cves = sorted(set(re.findall(r'\bCVE-\d{4}-\d{4,}\b', f['title'].upper())))
        if not cves:
            other.append(f)
        for cve in cves:
            group = groups.setdefault(cve, {'key': f'{host_id}:{cve}', 'cve': cve, 'score': scores.get(cve), 'claims': []})
            if not any(old['id'] == f['id'] for old in group['claims']):
                group['claims'].append(f)
    for group in groups.values():
        live = [f for f in group['claims'] if f['status'] != 'dismissed']
        group['confirmed'] = any(f['confirmed'] for f in live)
        group['status'] = 'confirmed' if group['confirmed'] else 'potential' if live else 'dismissed'
        group['evidence'] = sorted({rid for f in group['claims'] for rid in unpack(f.get('evidence'), [])})
        group['decision_conflict'] = any(f['confirmed'] for f in group['claims']) and any(f['status'] == 'dismissed' for f in group['claims'])
    return sorted(groups.values(), key=lambda g: (-(g['score'] if g['score'] is not None else -1), g['cve'])), other


def build(con, eid, hide_passive=False):
    # Hold one SQLite read snapshot while assembling related evidence. An import
    # committing midway through a request must not mix two inventory versions.
    if not con.in_transaction:
        con.execute('BEGIN')
    assets = evidence_build(con, eid)
    byid = {a['id']: a for a in assets}
    address = address_views(con, eid, assets)
    direct_services = {a['id']: [s for s in a['services'] if s['owner_id'] == a['id']] for a in assets}
    direct_findings = {a['id']: a['findings'] for a in assets}
    direct_scans = {a['id']: a['last_scan'] if any(s.startswith(('nmap', 'nessus')) for s in a['sources']) else None for a in assets}
    identity_sources = defaultdict(set)
    for r in rows(con, '''SELECT ra.asset_id,i.format,r.fields FROM record_assets ra
            JOIN records r ON r.id=ra.record_id JOIN imports i ON i.id=r.import_id
            WHERE r.engagement_id=? AND i.active=1 AND r.kind IN ('seed','host','dns_name','ip_address')''', (eid,)):
        if hide_passive and not r['format'].startswith(('nmap', 'nessus')):
            continue
        identity_sources[r['asset_id']].add(r['format'])
        module = unpack(r['fields'], {}).get('module')
        if isinstance(module, str):
            identity_sources[r['asset_id']].add(module)
    scores = {}
    for entry in con.execute("SELECT key,result FROM enrichment WHERE kind='cve' AND status='completed'"):
        numbers = []
        for metric in unpack(entry['result'], {}).get('scores', []):
            try:
                score = float(metric['baseScore'])
                if 0 <= score <= 10:
                    numbers.append(score)
            except (KeyError, ValueError, TypeError):
                pass
        if numbers:
            scores[entry['key']] = max(numbers)
    current_names = defaultdict(list)
    for a in assets:
        if a['kind'] != 'hostname':
            continue
        view = address.get(a['id'], {'addresses': [], 'primary_ip': None, 'status': 'unvalidated', 'checked_at': None, 'history': []})
        a['address_view'] = view
        for ip in view['addresses']:
            current_names[ip['id']].append({'id': a['id'], 'value': a['value'], 'kind': 'hostname'})
    for a in assets:
        aid = a['id']
        a['historical_associations'] = a['associated']
        if a['kind'] == 'hostname':
            a['associated'] = [{**ip, 'kind': 'ip'} for ip in a['address_view']['addresses']]
        elif a['kind'] == 'ip':
            a['associated'] = sorted(current_names[aid], key=lambda n: n['value'])
            a['address_view'] = {'addresses': [{'id': aid, 'value': a['value']}], 'primary_ip': a['value'], 'status': 'address', 'checked_at': None, 'history': []}
        else:
            a['address_view'] = {'addresses': [], 'primary_ip': None, 'status': 'unvalidated', 'checked_at': None, 'history': []}
        owners = [aid] + ([p['id'] for p in a['associated'] if p['kind'] == 'ip'] if a['kind'] == 'hostname' else [])
        all_groups, history = defaultdict(list), []
        for owner in owners:
            for service in direct_services[owner]:
                obs = sorted(service['_observations'], key=observation_key, reverse=True)
                active = [o for o in obs if o['evidence'] != 'passive']
                winner = (active or obs)[0]
                for o in obs:
                    reason = 'Current active evidence' if o is winner and active else 'Passive fallback' if o is winner else 'Superseded by active evidence' if o['evidence'] == 'passive' and active else 'Older observation'
                    history.append({'owner_id': owner, 'owner': byid[owner]['value'], 'port': service['port'], 'protocol': service['protocol'], 'record_id': o['record_id'], 'state': o['state'], 'service': o['service'], 'product': o['product'], 'evidence': o['evidence'], 'observed_at': o['observed_at'] or o['created_at'], 'current': o is winner, 'reason': reason})
                if hide_passive and winner['evidence'] == 'passive':
                    continue
                all_groups[(service['protocol'], service['port'])].append({**service, **{k: winner[k] for k in ('state', 'service', 'product', 'evidence', 'record_id')},
                    'observed_at': winner['observed_at'] or winner['created_at'], '_observations': [winner], 'history_count': len(obs), 'conflict': False})
        a['services'] = []
        for (protocol, port), variants in sorted(all_groups.items(), key=lambda pair: (pair[0][1], pair[0][0])):
            signatures = {(v['state'], v['service'], v['product']) for v in variants}
            # This is a group, not a synthesized banner. Keep every current owner explicit.
            representative = max(variants, key=lambda v: observation_key(v['_observations'][0]))
            group = {**representative, 'protocol': protocol, 'port': port, 'variants': variants,
                     'count': sum(v['history_count'] for v in variants), 'conflict': len(signatures) > 1,
                     '_observations': [o for v in variants for o in v['_observations']]}
            group['state'] = 'open' if any(v['state'] == 'open' for v in variants) else representative['state']
            if len({v['service'] for v in variants}) > 1:
                group['service'] = 'varies by address'
            if len({v['product'] for v in variants}) > 1:
                group['product'] = ''
            a['services'].append(group)
        historical_owners = {n['id'] for n in a['historical_associations'] if n['kind'] == 'ip'} - set(owners) if a['kind'] == 'hostname' else set()
        for owner in historical_owners:
            for service in direct_services[owner]:
                for o in service['_observations']:
                    history.append({'owner_id': owner, 'owner': byid[owner]['value'], 'port': service['port'], 'protocol': service['protocol'], 'record_id': o['record_id'], 'state': o['state'], 'service': o['service'], 'product': o['product'], 'evidence': o['evidence'], 'observed_at': o['observed_at'] or o['created_at'], 'current': False, 'reason': 'Previous hostname address'})
        a['service_history'] = sorted(history, key=lambda o: (time_key(o['observed_at']), o['record_id']), reverse=True)
        # Preserve direct analyst decisions; address-attributed claims remain attributable.
        findings = {f['id']: f for owner in owners for f in direct_findings[owner]}
        grouped_claims = defaultdict(list)
        for f in findings.values():
            for cve in re.findall(r'CVE-\d{4}-\d{4,}', f['title'].upper()):
                grouped_claims[cve].append(f)
        suppress = {f['id'] for claims in grouped_claims.values() if any(str(c.get('source_key') or '').startswith('nmap:') for c in claims) for f in claims if passive_finding(f)}
        a['finding_history'] = [dict(f, archive_reason='Superseded passive claim' if f['id'] in suppress else 'Passive hidden') for f in findings.values() if f['id'] in suppress or hide_passive and passive_finding(f)]
        a['findings'] = [f for f in findings.values() if f['id'] not in suppress and (not hide_passive or not passive_finding(f))]
        a['vulnerabilities'], a['other_findings'] = cve_groups(a['findings'], aid, scores)
        a['potential'] = sum(g['status'] == 'potential' for g in a['vulnerabilities'])
        a['confirmed'] = sum(g['confirmed'] for g in a['vulnerabilities']) + sum(f['confirmed'] and f['status'] != 'dismissed' for f in a['other_findings'])
        a['last_scan'] = max((direct_scans[o] for o in owners if direct_scans[o]), default=None)
        a['coverage'] = 'scanned' if a['last_scan'] else 'active' if any(v['evidence'] != 'passive' for s in a['services'] for v in s['variants']) else 'passive' if a['services'] else 'unscanned'
        a['sources'] = sorted(identity_sources[aid] | {e['source'] for e in a['address_view']['history'] if e['current'] and (not hide_passive or e['rank'] >= 2)} | {o['source_format'] for s in a['services'] for o in s['_observations']} | {str(f.get('actor') or 'analyst') for f in a['findings']})
        a['open_port_count'] = sum(s['state'] == 'open' for s in a['services'])
        if a['kind'] == 'hostname' and a['address_view']['addresses']:
            primary = byid[a['address_view']['addresses'][0]['id']]
            for key in ('country', 'city', 'latitude', 'longitude', 'geo_source', 'provider', 'asn'):
                a[key] = primary.get(key)
    return assets


def host_rows(assets, hide_passive=False, mode='auto'):
    for a in assets:
        if mode != 'auto' and a['kind'] != mode:
            continue
        if mode == 'auto' and not (a['kind'] == 'hostname' or a['kind'] == 'ip' and not a['associated']):
            continue
        if hide_passive and not (a['coverage'] in ('scanned', 'active') or a['services'] or any(f['status'] != 'dismissed' for f in a['findings'])):
            continue
        yield a


def public(a, detail=False):
    def scrub(value):
        if isinstance(value, dict):
            return {k: scrub(v) for k, v in value.items() if not k.startswith('_')}
        if isinstance(value, list):
            return [scrub(v) for v in value]
        return value
    result = scrub(a)
    if not detail:
        for key in ('service_history', 'finding_history', 'historical_associations'):
            result.pop(key, None)
        result['address_view'] = {k: v for k, v in result['address_view'].items() if k != 'history'}
    return result
