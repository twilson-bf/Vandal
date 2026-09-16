"""Optional Mythic callback references and exact asset correlation."""
import hashlib
import ipaddress
import json
import secrets
from collections import defaultdict
from urllib.parse import urlsplit

from fastapi import HTTPException

from .db import dump, now, rows
from .identity import identity


def issue_token():
    token = 'vnd_mythic_' + secrets.token_urlsafe(32)
    return token, hashlib.sha256(token.encode()).hexdigest()


def origin(value):
    value = str(value or '').strip().rstrip('/')
    parsed = urlsplit(value)
    if parsed.scheme not in ('http', 'https') or not parsed.netloc or parsed.username or parsed.password or parsed.path not in ('', '/') or parsed.query or parsed.fragment:
        raise ValueError('Mythic URL must be an HTTP(S) origin without credentials, path, query, or fragment')
    return value


def create_source(con, engagement_id, name, public_url, operation_id):
    name = str(name or '').strip()
    if not 1 <= len(name) <= 100:
        raise ValueError('Integration name must be 1–100 characters')
    public_url = origin(public_url)
    try:
        operation_id = int(operation_id)
    except (TypeError, ValueError):
        raise ValueError('Mythic operation ID must be a positive integer')
    if operation_id < 1:
        raise ValueError('Mythic operation ID must be a positive integer')
    token, token_hash = issue_token()
    source_id = con.execute(
        '''INSERT INTO integration_sources(engagement_id,kind,name,token_hash,public_url,operation_id,created_at)
           VALUES (?,'mythic',?,?,?,?,?)''',
        (engagement_id, name, token_hash, public_url, operation_id, now()),
    ).lastrowid
    return source_id, token


def rotate_token(con, source_id, engagement_id):
    source = con.execute(
        "SELECT id,name,operation_id FROM integration_sources WHERE id=? AND engagement_id=? AND kind='mythic' AND active=1",
        (source_id, engagement_id),
    ).fetchone()
    if not source:
        raise HTTPException(404, 'Active integration not found')
    token, token_hash = issue_token()
    con.execute('UPDATE integration_sources SET token_hash=? WHERE id=?', (token_hash, source_id))
    return dict(source), token


def authenticate(con, source_id, authorization):
    prefix = 'Bearer '
    if not authorization.startswith(prefix):
        raise HTTPException(401, 'Bearer token required')
    token_hash = hashlib.sha256(authorization[len(prefix):].encode()).hexdigest()
    source = con.execute(
        "SELECT * FROM integration_sources WHERE id=? AND kind='mythic' AND active=1",
        (source_id,),
    ).fetchone()
    if not source or not secrets.compare_digest(source['token_hash'], token_hash):
        raise HTTPException(401, 'Invalid or revoked integration token')
    return dict(source)


def _ip(value):
    value = str(value or '').strip()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return ''


def _hostname(value):
    try:
        kind, normalized = identity(value)
        return normalized if kind == 'hostname' else ''
    except ValueError:
        return ''


def _text(value, limit):
    return str(value or '')[:limit]


def _timestamp(value):
    value = str(value or '').strip()
    return value[:80] if value else None


def _callback(item, source):
    if not isinstance(item, dict):
        raise ValueError('Each callback must be an object')
    external_id = _text(item.get('id'), 100).strip()
    try:
        display_id = int(item.get('display_id'))
    except (TypeError, ValueError):
        raise ValueError('Each callback requires an integer display_id')
    if not external_id or display_id < 1:
        raise ValueError('Each callback requires an id and a positive display_id')
    supplied_ips = item.get('ips', item.get('ip', []))
    if isinstance(supplied_ips, str):
        try:
            supplied_ips = json.loads(supplied_ips)
        except json.JSONDecodeError:
            supplied_ips = [supplied_ips]
    if not isinstance(supplied_ips, list):
        supplied_ips = []
    normalized_ips = sorted({_ip(value) for value in supplied_ips if _ip(value)})
    host = _hostname(item.get('host'))
    external_ip = _ip(item.get('external_ip'))
    try:
        operation_id = int(item['operation_id']) if item.get('operation_id') is not None else None
    except (TypeError, ValueError):
        operation_id = None
    if operation_id != source['operation_id']:
        raise ValueError('Callback operation does not match the configured Mythic operation')
    metadata = {
        'description': _text(item.get('description'), 1000),
        'integrity_level': item.get('integrity_level'),
        'pid': item.get('pid'),
        'process_name': _text(item.get('process_name') or item.get('process_short_name'), 300),
    }
    return {
        'external_id': external_id, 'display_id': display_id,
        'operation_id': operation_id, 'operation_name': _text(item.get('operation_name'), 150),
        'host': host, 'user': _text(item.get('user'), 300), 'domain': _text(item.get('domain'), 300),
        'external_ip': external_ip, 'ips': normalized_ips, 'os': _text(item.get('os'), 1000),
        'architecture': _text(item.get('architecture'), 100), 'payload_type': _text(item.get('payload_type'), 100),
        'active': int(bool(item.get('active', True))),
        'first_seen': _timestamp(item.get('first_seen') or item.get('init_callback')),
        'last_seen': _timestamp(item.get('last_seen') or item.get('last_checkin')),
        'source_url': f"{source['public_url']}/new/callbacks/{display_id}", 'metadata': dump(metadata),
    }


def _rematch(con, callback_id, engagement_id, callback):
    con.execute('DELETE FROM mythic_callback_assets WHERE callback_id=?', (callback_id,))
    candidates = []
    if callback['host']:
        candidates.append(('hostname', callback['host'], 'exact hostname'))
    if callback['external_ip']:
        candidates.append(('ip', callback['external_ip'], 'exact external IP'))
    candidates.extend(('ip', value, 'exact callback IP') for value in callback['ips'])
    for kind, value, basis in candidates:
        for asset in con.execute('SELECT id FROM assets WHERE engagement_id=? AND kind=? AND value=?', (engagement_id, kind, value)):
            con.execute(
                'INSERT OR IGNORE INTO mythic_callback_assets(callback_id,asset_id,match_basis,matched_at) VALUES (?,?,?,?)',
                (callback_id, asset['id'], basis, now()),
            )


def ingest(con, source, payload):
    callbacks = payload.get('callbacks') if isinstance(payload, dict) else None
    if not isinstance(callbacks, list) or len(callbacks) > 5000:
        raise ValueError('callbacks must be a list with at most 5000 items')
    full_snapshot = bool(payload.get('full_snapshot', True))
    if full_snapshot:
        con.execute('UPDATE mythic_callbacks SET present=0 WHERE source_id=?', (source['id'],))
    received = now()
    matched = 0
    for item in callbacks:
        callback = _callback(item, source)
        values = (source['engagement_id'], source['id'], callback['external_id'], callback['display_id'],
                  callback['operation_id'], callback['operation_name'], callback['host'], callback['user'],
                  callback['domain'], callback['external_ip'], dump(callback['ips']), callback['os'],
                  callback['architecture'], callback['payload_type'], callback['active'], callback['first_seen'],
                  callback['last_seen'], callback['source_url'], callback['metadata'], received)
        con.execute('''INSERT INTO mythic_callbacks(
                engagement_id,source_id,external_id,display_id,operation_id,operation_name,host,user,domain,
                external_ip,ips,os,architecture,payload_type,active,present,first_seen,last_seen,source_url,metadata,received_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,?,?,?,?,?)
            ON CONFLICT(source_id,external_id) DO UPDATE SET
                display_id=excluded.display_id,operation_id=excluded.operation_id,operation_name=excluded.operation_name,
                host=excluded.host,user=excluded.user,domain=excluded.domain,external_ip=excluded.external_ip,
                ips=excluded.ips,os=excluded.os,architecture=excluded.architecture,payload_type=excluded.payload_type,
                active=excluded.active,present=1,first_seen=COALESCE(mythic_callbacks.first_seen,excluded.first_seen),
                last_seen=excluded.last_seen,source_url=excluded.source_url,metadata=excluded.metadata,received_at=excluded.received_at''', values)
        callback_id = con.execute('SELECT id FROM mythic_callbacks WHERE source_id=? AND external_id=?', (source['id'], callback['external_id'])).fetchone()[0]
        _rematch(con, callback_id, source['engagement_id'], callback)
        matched += con.execute('SELECT count(DISTINCT asset_id) FROM mythic_callback_assets WHERE callback_id=?', (callback_id,)).fetchone()[0]
    con.execute('UPDATE integration_sources SET last_sync_at=? WHERE id=?', (received, source['id']))
    return {'received': len(callbacks), 'asset_matches': matched, 'synced_at': received}


def rematch_engagement(con, engagement_id):
    """Rebuild links after an import adds assets after a callback was received."""
    for row in rows(con, 'SELECT * FROM mythic_callbacks WHERE engagement_id=?', (engagement_id,)):
        callback = dict(row, ips=json.loads(row['ips']))
        _rematch(con, row['id'], engagement_id, callback)


def attach(con, engagement_id, assets):
    by_asset = defaultdict(dict)
    for row in rows(con, '''SELECT c.*,s.name source_name,l.asset_id,l.match_basis
            FROM mythic_callbacks c JOIN integration_sources s ON s.id=c.source_id
            JOIN mythic_callback_assets l ON l.callback_id=c.id
            WHERE c.engagement_id=? ORDER BY COALESCE(c.last_seen,c.first_seen,c.received_at) DESC,c.id DESC''', (engagement_id,)):
        row['ips'] = json.loads(row['ips'])
        row['metadata'] = json.loads(row['metadata'])
        entry = by_asset[row['asset_id']].setdefault(row['id'], {k: v for k, v in row.items() if k not in ('asset_id', 'match_basis', 'token_hash')})
        entry.setdefault('match_basis', []).append(row['match_basis'])
    for asset in assets:
        related_ids = {asset['id']} | {item['id'] for item in asset.get('associated', [])}
        callbacks = {}
        for asset_id in related_ids:
            for callback_id, callback in by_asset[asset_id].items():
                target = callbacks.setdefault(callback_id, dict(callback, match_basis=[]))
                target['match_basis'] = sorted(set(target['match_basis']) | set(callback['match_basis']))
        asset['mythic_callbacks'] = list(callbacks.values())
        asset['pwned'] = bool(callbacks)
        asset['callback_count'] = len(callbacks)
        if callbacks:
            asset['sources'] = sorted(set(asset.get('sources', [])) | {'mythic'} | {callback['source_name'] for callback in callbacks.values()})
