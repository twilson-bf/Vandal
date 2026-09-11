import json
import ipaddress
from .db import rows

VISIBLE = 'EXISTS (SELECT 1 FROM record_assets ra JOIN records r ON r.id=ra.record_id JOIN imports i ON i.id=r.import_id WHERE ra.asset_id=a.id AND i.active=1)'


def related(condition):
    return '''EXISTS (SELECT 1 FROM relationships rel JOIN assets b ON b.id=CASE WHEN rel.source_id=a.id THEN rel.target_id ELSE rel.source_id END
        JOIN records rr ON rr.id=rel.record_id JOIN imports ii ON ii.id=rr.import_id
        WHERE (rel.source_id=a.id OR rel.target_id=a.id) AND ii.active=1 AND ''' + condition + ')'


def asset_filter(engagement, params):
    where, args = ['a.engagement_id=?', VISIBLE], [engagement]
    primary = {'ip': 'ip', 'domain': 'hostname'}.get(params.get('primary'))
    if primary:
        where.append('a.kind=?')
        args.append(primary)
    for key in ('kind', 'domain', 'country', 'asn'):
        if params.get(key):
            values = params[key].split(',')
            marks = ','.join('?' for _ in values)
            if key == 'domain' and (params.get('primary') == 'domain' or params.get('kind') == 'hostname'):
                where.append(f'a.domain IN ({marks})')
                args.extend(values)
            elif key in ('domain', 'country', 'asn'):
                where.append(f'(a.{key} IN ({marks}) OR ' + related(f'b.{key} IN ({marks})') + ')')
                args.extend(values * 2)
            else:
                where.append(f'a.{key} IN ({marks})')
                args.extend(values)
    if params.get('q'):
        where.append('(a.value LIKE ? OR a.tags LIKE ? OR a.provider LIKE ? OR ' + related('b.value LIKE ?') + ')')
        args.extend(['%' + params['q'] + '%'] * 4)
    if params.get('tag'):
        where.append('a.tags LIKE ?')
        args.append('%' + params['tag'] + '%')
    conditions, oargs = [], []
    for key, column in [('port', 'ep.port'), ('protocol', 'ep.protocol'), ('state', 'ob.state'), ('service', 'ob.service'), ('evidence', 'ob.evidence')]:
        if params.get(key):
            values = params[key].split(',')
            conditions.append(f'{column} IN ({",".join("?" for _ in values)})')
            oargs.extend(values)
    if conditions:
        owner = '(ep.asset_id=a.id OR ' + related('b.id=ep.asset_id') + ')' if params.get('primary') else 'ep.asset_id=a.id'
        where.append('EXISTS (SELECT 1 FROM endpoints ep JOIN observations ob ON ob.endpoint_id=ep.id JOIN records rr ON rr.id=ob.record_id JOIN imports ii ON ii.id=rr.import_id WHERE ' + owner + ' AND ii.active=1 AND ' + ' AND '.join(conditions) + ')')
        args.extend(oargs)
    if params.get('source'):
        where.append('EXISTS (SELECT 1 FROM record_assets ra JOIN records rr ON rr.id=ra.record_id JOIN imports ii ON ii.id=rr.import_id WHERE ra.asset_id=a.id AND ii.active=1 AND ii.format=?)')
        args.append(params['source'])
    if params.get('has_ports') in ('yes', 'no'):
        owner = '(ep.asset_id=a.id OR ' + related("b.id=ep.asset_id AND b.kind IN ('ip','hostname')") + ')'
        exists = 'EXISTS (SELECT 1 FROM endpoints ep JOIN observations ob ON ob.endpoint_id=ep.id JOIN records rr ON rr.id=ob.record_id JOIN imports ii ON ii.id=rr.import_id WHERE ' + owner + " AND ii.active=1 AND ob.state='open')"
        where.append(('NOT ' if params['has_ports']=='no' else '') + exists)
    return ' AND '.join(where), args


def assets(con, engagement, params, all_rows=False):
    where, args = asset_filter(engagement, params)
    count = con.execute('SELECT count(*) FROM assets a WHERE ' + where, args).fetchone()[0]
    page = max(1, int(params.get('page', 1)))
    size = min(200, max(1, int(params.get('size', 50))))
    def ip_sort(value):
        try:
            ip = ipaddress.ip_address(value)
            return str(ip.version) + ip.packed.hex()
        except ValueError:
            return value
    con.create_function('ip_sort', 1, ip_sort, deterministic=True)
    order = 'ip_sort(a.value)' if params.get('primary') == 'ip' else 'a.domain,a.value' if params.get('primary') == 'domain' else 'a.value'
    result = rows(con, 'SELECT a.* FROM assets a WHERE ' + where + ' ORDER BY ' + order + ('' if all_rows else ' LIMIT ? OFFSET ?'), args + ([] if all_rows else [size, (page - 1) * size]))
    for asset in result:
        asset['associated'] = rows(con, '''SELECT DISTINCT b.id,b.kind,b.value FROM relationships rel
            JOIN assets b ON b.id=CASE WHEN rel.source_id=? THEN rel.target_id ELSE rel.source_id END
            JOIN records rr ON rr.id=rel.record_id JOIN imports ii ON ii.id=rr.import_id
            WHERE (rel.source_id=? OR rel.target_id=?) AND ii.active=1 AND b.kind IN ('ip','hostname')
            AND b.id!=? ORDER BY b.kind,b.value''', (asset['id'], asset['id'], asset['id'], asset['id']))
        ids = [asset['id']] + [a['id'] for a in asset['associated']]
        asset['ports'] = rows(con, 'SELECT DISTINCT ep.port,ep.protocol,ob.evidence,owner.value AS owner,owner.id AS owner_id FROM endpoints ep JOIN assets owner ON owner.id=ep.asset_id JOIN observations ob ON ob.endpoint_id=ep.id JOIN records rr ON rr.id=ob.record_id JOIN imports ii ON ii.id=rr.import_id WHERE ep.asset_id IN (' + ','.join('?' for _ in ids) + ') AND ob.state=\'open\' AND ii.active=1 ORDER BY ep.port,owner.value,ob.evidence', ids)
        asset['sources'] = [r[0] for r in con.execute('SELECT DISTINCT i.format FROM record_assets ra JOIN records r ON r.id=ra.record_id JOIN imports i ON i.id=r.import_id WHERE ra.asset_id=? AND i.active=1', (asset['id'],))]
    return {'items': result, 'total': count, 'page': page, 'size': size}


def detail(con, asset):
    aid = asset['id']
    asset['relationships'] = rows(con, '''SELECT rel.kind,other.id,other.value,other.kind AS asset_kind,r.observed_at,r.id AS record_id,i.filename
        FROM relationships rel JOIN assets other ON other.id=CASE WHEN rel.source_id=? THEN rel.target_id ELSE rel.source_id END
        JOIN records r ON r.id=rel.record_id JOIN imports i ON i.id=r.import_id WHERE (rel.source_id=? OR rel.target_id=?) AND i.active=1 ORDER BY r.observed_at DESC''', (aid, aid, aid))
    asset['observations'] = rows(con, '''SELECT ep.port,ep.protocol,ob.*,r.import_id,i.filename FROM endpoints ep JOIN observations ob ON ob.endpoint_id=ep.id
        JOIN records r ON r.id=ob.record_id JOIN imports i ON i.id=r.import_id WHERE ep.asset_id=? AND i.active=1 ORDER BY ep.port,ob.observed_at DESC''', (aid,))
    asset['records'] = rows(con, '''SELECT r.id,r.kind,r.title,r.observed_at,i.filename FROM record_assets ra JOIN records r ON r.id=ra.record_id
        JOIN imports i ON i.id=r.import_id WHERE ra.asset_id=? AND i.active=1 ORDER BY r.id DESC LIMIT 200''', (aid,))
    variants = {}
    for o in asset['observations']:
        key = f'{o["protocol"]}/{o["port"]}'
        variants.setdefault(key, set()).add((o['state'], o['service']))
    asset['variations'] = [key for key, values in variants.items() if len(values) > 1]
    return asset
