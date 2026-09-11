"""Scope input and reversible, connection-local inventory visibility."""
import ipaddress
import re
from urllib.parse import urlsplit
from .identity import identity


def parse_targets(text):
    if not isinstance(text, str) or len(text.encode()) > 1024 * 1024:
        raise ValueError('Scope input must be text up to 1 MiB')
    result = []
    for line in text.splitlines():
        line = line.split('#', 1)[0].strip()
        line = re.sub(r'\s*-\s*', '-', line)
        for value in re.split(r'[\s,;]+', line):
            if not value:
                continue
            if '-' in value:
                left, _, right = value.partition('-')
                try:
                    first, last = ipaddress.ip_address(left), ipaddress.ip_address(right)
                except ValueError:
                    pass  # Hyphenated hostname.
                else:
                    if first.version != last.version or first > last:
                        raise ValueError('Invalid IP range: ' + value)
                    result.extend(str(n) for n in ipaddress.summarize_address_range(first, last))
                    continue
            kind, normalized = identity(value.removeprefix('*.'))
            if kind not in ('hostname', 'ip', 'network'):
                raise ValueError('Use a hostname, IP, CIDR, or start-end IP range')
            result.append(normalized)
    result = list(dict.fromkeys(result))
    if not result or len(result) > 10000:
        raise ValueError('Provide between 1 and 10,000 scope entries')
    return result


def matcher(targets):
    exact, domains, networks = set(), set(), []
    for target in targets:
        kind, value = identity(target.removeprefix('*.'))
        if kind == 'network':
            networks.append(ipaddress.ip_network(value))
        elif kind == 'hostname':
            domains.add(value)
        else:
            exact.add(value)
    def matches(value):
        if not isinstance(value, str):
            return False
        if value in exact:
            return True
        value = urlsplit(value).hostname if '://' in value else value
        if value in exact:
            return True
        try:
            ip = ipaddress.ip_address(value)
            return any(ip in n for n in networks)
        except ValueError:
            parts = value.split('.')
            return any('.'.join(parts[i:]) in domains for i in range(len(parts)))
    return matches


def install_visibility(con, eid):
    """Read projections leave original evidence intact. Mixed raw records are hidden
    in full so excluded identities cannot leak through banners or evidence links.
    Scope management uses the original tables, making exclusions reversible.
    """
    targets = [r[0] for r in con.execute("SELECT target FROM main.scope_rules WHERE engagement_id=? AND action='exclude'", (eid,))]
    if not targets:
        return
    matches = matcher(targets)
    con.create_function('scope_excluded', 1, lambda value: int(matches(value)), deterministic=True)
    con.execute('CREATE TEMP TABLE hidden_assets(id INTEGER PRIMARY KEY)')
    con.executemany('INSERT INTO hidden_assets VALUES (?)', [(r[0],) for r in con.execute('SELECT id,value FROM main.assets WHERE engagement_id=?', (eid,)) if matches(r[1])])
    con.execute('CREATE TEMP TABLE hidden_records(id INTEGER PRIMARY KEY)')
    con.execute('INSERT INTO hidden_records SELECT DISTINCT record_id FROM main.record_assets WHERE asset_id IN (SELECT id FROM hidden_assets)')
    views = {
        'assets': 'SELECT * FROM main.assets WHERE id NOT IN (SELECT id FROM hidden_assets)',
        'records': 'SELECT * FROM main.records WHERE id NOT IN (SELECT id FROM hidden_records)',
        'record_assets': 'SELECT * FROM main.record_assets WHERE asset_id NOT IN (SELECT id FROM hidden_assets) AND record_id NOT IN (SELECT id FROM hidden_records)',
        'relationships': 'SELECT * FROM main.relationships WHERE source_id NOT IN (SELECT id FROM hidden_assets) AND target_id NOT IN (SELECT id FROM hidden_assets) AND record_id NOT IN (SELECT id FROM hidden_records)',
        'endpoints': 'SELECT * FROM main.endpoints WHERE asset_id NOT IN (SELECT id FROM hidden_assets)',
        'observations': 'SELECT * FROM main.observations WHERE endpoint_id IN (SELECT id FROM endpoints) AND record_id NOT IN (SELECT id FROM hidden_records)',
        'interests': '''SELECT f.* FROM main.interests f WHERE NOT EXISTS (SELECT 1 FROM json_each(f.asset_ids) WHERE value IN (SELECT id FROM hidden_assets)) AND NOT EXISTS (SELECT 1 FROM json_each(f.evidence) WHERE value IN (SELECT id FROM hidden_records))''',
    }
    for name, sql in views.items():
        con.execute(f'CREATE TEMP VIEW {name} AS {sql}')
    job_cols = [r[1] for r in con.execute('PRAGMA main.table_info(jobs)')]
    job_select = ','.join("'[]' AS excluded" if c == 'excluded' else 'j.' + c for c in job_cols)
    con.execute('CREATE TEMP VIEW jobs AS SELECT ' + job_select + ' FROM main.jobs j WHERE j.engagement_id != %d OR NOT EXISTS (SELECT 1 FROM json_each(j.targets) WHERE scope_excluded(value))' % int(eid))
    # Keep mixed imports browsable, but never expose their original raw download or
    # command metadata. Counts describe visible records, not the hidden originals.
    cols = [r[1] for r in con.execute('PRAGMA main.table_info(imports)')]
    selected = []
    mixed = 'EXISTS(SELECT 1 FROM main.records r WHERE r.import_id=i.id AND r.id IN (SELECT id FROM hidden_records))'
    for col in cols:
        if col == 'record_count':
            selected.append('(SELECT count(*) FROM records r WHERE r.import_id=i.id) AS record_count')
        elif col in ('metadata', 'warnings'):
            empty = '{}' if col == 'metadata' else '[]'
            selected.append(f"CASE WHEN {mixed} THEN '{empty}' ELSE i.{col} END AS {col}")
        else:
            selected.append('i.' + col)
    con.execute('CREATE TEMP VIEW imports AS SELECT ' + ','.join(selected) + ' FROM main.imports i WHERE NOT EXISTS(SELECT 1 FROM main.records r WHERE r.import_id=i.id) OR EXISTS(SELECT 1 FROM records r WHERE r.import_id=i.id)')
