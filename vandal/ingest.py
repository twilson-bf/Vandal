import hashlib
import json
import os
from pathlib import Path
from urllib.parse import urlsplit
from .db import connect, data_dir, now, dump
from .identity import identity, root_domain
from .parsers import parse
from .interests import shodan_interests

MAX_UPLOAD = 100 * 1024 * 1024


def queue_import(engagement, filename, content, actor='operator'):
    if len(content) > MAX_UPLOAD:
        raise ValueError('Files must be 100 MiB or smaller')
    digest = hashlib.sha256(content).hexdigest()
    folder = data_dir() / 'artifacts'
    folder.mkdir(exist_ok=True)
    path = folder / digest
    if not path.exists():
        temporary = folder / (digest + '.' + os.urandom(6).hex())
        temporary.write_bytes(content)
        temporary.replace(path)
    with connect() as con:
        old = con.execute('SELECT id FROM imports WHERE engagement_id=? AND sha256=?', (engagement, digest)).fetchone()
        if old:
            return old['id'], True
        cursor = con.execute('INSERT INTO imports(engagement_id,filename,sha256,created_at,actor) VALUES (?,?,?,?,?)',
                             (engagement, Path(filename).name, digest, now(), actor))
        return cursor.lastrowid, False


def get_asset(con, engagement, value, cache):
    kind, normalized = identity(value)
    key = (kind, normalized)
    if key in cache:
        return cache[key]
    domain = root_domain(urlsplit(normalized).hostname) if kind == 'url' else root_domain(normalized) if kind == 'hostname' else ''
    con.execute('INSERT OR IGNORE INTO assets(engagement_id,kind,value,domain) VALUES (?,?,?,?)', (engagement, kind, normalized, domain))
    aid = con.execute('SELECT id FROM assets WHERE engagement_id=? AND kind=? AND value=?', (engagement, kind, normalized)).fetchone()[0]
    cache[key] = aid
    return aid


def ingest(import_id):
    with connect() as con:
        con.execute('BEGIN IMMEDIATE')
        item = dict(con.execute('SELECT * FROM imports WHERE id=?', (import_id,)).fetchone())
        if item['status'] not in ('queued', 'failed', 'interrupted'):
            return
        con.execute("UPDATE imports SET status='parsing' WHERE id=?", (import_id,))
    try:
        parsed = parse((data_dir() / 'artifacts' / item['sha256']).read_bytes(), item['filename'])
        with connect() as con:
            cache = {}
            for i, record in enumerate(parsed.records, 1):
                cur = con.execute('INSERT INTO records(engagement_id,import_id,kind,title,observed_at,fields,raw,locator) VALUES (?,?,?,?,?,?,?,?)',
                                  (item['engagement_id'], import_id, record['kind'], record['title'], record['observed'], dump(record['fields']), record['raw'], f'record:{i}'))
                rid = cur.lastrowid
                def asset(value):
                    aid = get_asset(con, item['engagement_id'], value, cache)
                    con.execute('INSERT OR IGNORE INTO record_assets VALUES (?,?)', (rid, aid))
                    return aid
                for value in record['assets']:
                    try:
                        aid = asset(value)
                        if identity(value)[0] == 'url':
                            host = asset(urlsplit(value).hostname)
                            con.execute('INSERT OR IGNORE INTO relationships(source_id,target_id,kind,record_id) VALUES (?,?,?,?)', (aid, host, 'web-host', rid))
                    except (ValueError, UnicodeError):
                        pass  # Original value remains browsable in the record.
                for source, target, kind in record['links']:
                    try:
                        src, dst = asset(source), asset(target)
                        if src != dst:
                            con.execute('INSERT OR IGNORE INTO relationships(source_id,target_id,kind,record_id) VALUES (?,?,?,?)', (src, dst, kind, rid))
                    except (ValueError, UnicodeError):
                        pass
                for port in record['ports']:
                    try:
                        aid = asset(port['owner'])
                        num = int(port['port'])
                        if not 1 <= num <= 65535 or port.get('protocol', 'tcp') not in ('tcp', 'udp'):
                            continue
                        con.execute('INSERT OR IGNORE INTO endpoints(asset_id,port,protocol) VALUES (?,?,?)', (aid, num, port.get('protocol', 'tcp')))
                        eid = con.execute('SELECT id FROM endpoints WHERE asset_id=? AND port=? AND protocol=?', (aid, num, port.get('protocol', 'tcp'))).fetchone()[0]
                        con.execute('INSERT INTO observations(endpoint_id,record_id,state,service,evidence,product,observed_at) VALUES (?,?,?,?,?,?,?)',
                                    (eid, rid, port.get('state', 'unknown'), port.get('service', ''), port.get('evidence', 'hint'), port.get('product', ''), record['observed']))
                    except (ValueError, UnicodeError):
                        pass
                shodan_interests(con, item['engagement_id'], rid, record['fields'])
            con.execute('UPDATE imports SET format=?,status=?,warnings=?,metadata=?,record_count=?,finished_at=? WHERE id=?',
                        (parsed.format, 'partial' if parsed.partial else 'completed', dump(parsed.warnings), dump(parsed.metadata), len(parsed.records), now(), import_id))
            from .mythic import rematch_engagement
            rematch_engagement(con, item['engagement_id'])
    except Exception as exc:
        with connect() as con:
            con.execute("UPDATE imports SET status='failed',warnings=?,finished_at=? WHERE id=?", (dump([f'{type(exc).__name__}: {exc}']), now(), import_id))


def enrich_geo():
    city_path, asn_path = os.getenv('VANDAL_GEOIP_CITY'), os.getenv('VANDAL_GEOIP_ASN')
    if not city_path and not asn_path:
        return 0
    import geoip2.database
    import geoip2.errors
    count = 0
    with connect() as con:
        for path, mode in [(city_path, 'city'), (asn_path, 'asn')]:
            if not path:
                continue
            with geoip2.database.Reader(path) as reader:
                for row in con.execute("SELECT id,value FROM assets WHERE kind='ip'").fetchall():
                    try:
                        result = getattr(reader, mode)(row['value'])
                        if mode == 'city':
                            con.execute('UPDATE assets SET country=?,city=?,latitude=?,longitude=?,geo_source=? WHERE id=?',
                                        (result.country.name or 'Unknown', result.city.name or '', result.location.latitude, result.location.longitude, Path(path).name, row['id']))
                        else:
                            con.execute('UPDATE assets SET asn=?,provider=? WHERE id=?', ('AS' + str(result.autonomous_system_number), result.autonomous_system_organization or '', row['id']))
                        count += 1
                    except geoip2.errors.AddressNotFoundError:
                        pass
    return count
