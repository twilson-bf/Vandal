"""Convert Shodan CVE claims into deduplicated, unconfirmed review items."""
import json
import re
from .db import dump, now
from .identity import identity


def shodan_interests(con, engagement, rid, fields):
    if fields.get('module') not in ('shodan_idb', 'shodan_enterprise', 'internetdb', 'nmap_nse'):
        return
    if fields.get('type') not in ('FINDING', 'VULNERABILITY'):
        return
    data = fields.get('data_json') or fields.get('data')
    if not isinstance(data, dict):
        return
    host = data.get('host') or fields.get('host')
    try:
        _, host = identity(host)
    except (ValueError, TypeError, AttributeError):
        return
    # Match only CVE identifiers in claim fields, not unrelated event metadata.
    cves = sorted(set(re.findall(r'\bCVE-\d{4}-\d{4,}\b', json.dumps(
        [data.get('cves', []), data.get('description', ''), data.get('cve', '')]).upper())))
    asset = con.execute('SELECT id FROM assets WHERE engagement_id=? AND value=?', (engagement, host)).fetchone()
    source = 'nmap' if fields.get('module') == 'nmap_nse' else 'shodan'
    label = 'Nmap NSE' if source == 'nmap' else 'Shodan'
    for cve in cves:
        key = f'{source}:{host}:{cve}'
        old = con.execute('SELECT id,evidence FROM interests WHERE engagement_id=? AND source_key=?', (engagement, key)).fetchone()
        if old:
            evidence = json.loads(old['evidence'])
            if rid not in evidence:
                con.execute('UPDATE interests SET evidence=?,updated_at=? WHERE id=?', (dump(evidence + [rid]), now(), old['id']))
            continue
        con.execute('''INSERT INTO interests(engagement_id,title,category,notes,evidence,asset_ids,actor,created_at,updated_at,source_key)
            VALUES (?,?,?,?,?,?,?,?,?,?)''', (engagement, f'Potential CVE: {cve} · {host}', 'potential CVE',
            f'{label} reports {cve} for {host}. Unconfirmed scan claim; review the linked evidence.',
            dump([rid]), dump([asset['id']] if asset else []), source, now(), now(), key))


def backfill(con):
    for record in con.execute('''SELECT r.id,r.engagement_id,r.fields FROM records r JOIN imports i ON i.id=r.import_id
            WHERE i.active=1 AND r.kind IN ('finding','vulnerability')''').fetchall():
        shodan_interests(con, record['engagement_id'], record['id'], json.loads(record['fields']))
