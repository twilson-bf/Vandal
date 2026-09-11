"""Lossless source retention with conservative, format-specific normalization."""
from dataclasses import dataclass, field
import csv
from datetime import datetime, timezone
import io
import json
import re
from lxml import etree
from bs4 import BeautifulSoup


def timestamp(value):
    if not value:
        return None
    try:
        if isinstance(value, (int, float)) or str(value).isdigit():
            return datetime.fromtimestamp(float(value), timezone.utc).isoformat(timespec='seconds')
        return datetime.fromisoformat(str(value).replace('Z', '+00:00')).astimezone(timezone.utc).isoformat(timespec='seconds')
    except (ValueError, OverflowError, OSError):
        return None


@dataclass
class Result:
    format: str
    records: list = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    warnings: list = field(default_factory=list)
    partial: bool = False

    def add(self, kind, title, raw, fields=None, assets=(), links=(), ports=(), observed=None):
        self.records.append(dict(kind=kind, title=title, raw=raw, fields=fields or {}, assets=list(assets),
                                 links=list(links), ports=list(ports), observed=timestamp(observed)))
        if len(self.records) > 200000:
            raise ValueError('Import exceeds 200,000 normalized records; split the source')


def xmltext(node):
    return etree.tostring(node, encoding='unicode')


def nmap_host(result, host):
    addresses = [x.get('addr') for x in host.findall('address') if x.get('addrtype') in ('ipv4', 'ipv6')]
    names = [(x.get('name'), x.get('type')) for x in host.findall('hostnames/hostname') if x.get('name')]
    assets = addresses + [n for n, _ in names]
    if not assets:
        return
    owner = addresses[0] if addresses else names[0][0]
    links = [(n, addr, 'reverse-name' if kind == 'PTR' else 'scanner-association') for n, kind in names for addr in addresses]
    observed = host.get('endtime') or result.metadata.get('start')
    status = host.find('status')
    result.add('host', owner, xmltext(host), dict(status.attrib) if status is not None else {}, assets, links, observed=observed)
    for port in host.findall('ports/port'):
        state, service = port.find('state'), port.find('service')
        svc = dict(service.attrib) if service is not None else {}
        fields = {'port': int(port.get('portid')), 'protocol': port.get('protocol'),
                  'state': state.get('state', 'unknown') if state is not None else 'unknown', 'service': svc,
                  'scripts': [dict(s.attrib) for s in port.findall('script')]}
        endpoint = dict(owner=owner, port=fields['port'], protocol=fields['protocol'], state=fields['state'],
                        service=svc.get('name', ''), evidence=('probe-response' if svc.get('name') in ('tcpwrapped', 'unknown', '') else 'probed') if svc.get('method') == 'probed' else 'hint',
                        product=' '.join(filter(None, [svc.get('product'), svc.get('version'), svc.get('extrainfo')])) )
        result.add('port', f'{owner} · {fields["protocol"]}/{fields["port"]} · {fields["state"]}', xmltext(port), fields, [owner], ports=[endpoint], observed=observed)

    # Keep NSE evidence intact; promote only version matches or positive script
    # results to unconfirmed CVE review items, never negative script output.
    for script in host.findall('hostscript/script') + host.findall('ports/port/script'):
        raw = xmltext(script)
        output = script.get('output', '')
        positive = script.get('id') == 'vulners' or bool(re.search(r'State:\s*VULNERABLE', output, re.I)) or any(e.get('key') == 'state' and (e.text or '').strip() == 'VULNERABLE' for e in script.iter('elem'))
        if not positive or re.search(r'NOT[ _]VULNERABLE', raw, re.I): continue
        cves = sorted(set(re.findall(r'\bCVE-\d{4}-\d{4,}\b', raw.upper())))
        if cves:
            result.add('vulnerability', f'{owner} · NSE {script.get("id")}', raw,
                       {'module':'nmap_nse','type':'VULNERABILITY','data':{'host':owner,'cves':cves,'description':output}}, [owner], observed=observed)


def parse_xml(data):
    if re.search(br'<!ENTITY|<!DOCTYPE[^>]*\[', data, re.I):
        raise ValueError('XML entities and internal DTD subsets are not supported')
    is_nessus = b'NessusClientData_v2' in data[:4000]
    result = Result('nessus-xml' if is_nessus else 'nmap-xml')
    parser = etree.XMLPullParser(events=('start', 'end'), resolve_entities=False, no_network=True)
    error = None
    try:
        for offset in range(0, len(data), 65536):
            parser.feed(data[offset:offset + 65536])
            for event, node in parser.read_events():
                if event == 'start' and node.tag == 'nmaprun':
                    result.metadata.update(dict(node.attrib))
                if event != 'end':
                    continue
                if node.tag == 'host' and not is_nessus:
                    nmap_host(result, node)
                    node.clear()
                elif node.tag == 'ReportHost' and is_nessus:
                    host = node.get('name')
                    props = {t.get('name'): t.text for t in node.findall('HostProperties/tag')}
                    ip = props.get('host-ip')
                    assets = [host] + ([ip] if ip else [])
                    links = [(host, ip, 'scanner-association')] if ip and ip != host else []
                    result.add('host', host, xmltext(node.find('HostProperties')) if node.find('HostProperties') is not None else '', props, assets, links)
                    for item in node.findall('ReportItem'):
                        fields = dict(item.attrib)
                        for child in item:
                            if child.tag in fields:
                                previous = fields[child.tag]
                                fields[child.tag] = (previous if isinstance(previous, list) else [previous]) + [child.text]
                            else:
                                fields[child.tag] = child.text
                        port = int(item.get('port', 0))
                        ports = [dict(owner=host, port=port, protocol=item.get('protocol', 'tcp'), service=item.get('svc_name', ''), evidence='scanner', state='unknown')] if port else []
                        result.add('plugin', item.get('pluginName', 'Nessus plugin'), xmltext(item), fields, assets, ports=ports)
                    node.clear()
                elif node.tag in ('scaninfo', 'runstats'):
                    result.metadata[node.tag] = xmltext(node)
                    if node.tag == 'runstats':
                        finished = node.find('finished')
                        if finished is not None:
                            result.metadata['scan_end'] = timestamp(finished.get('time'))
        parser.close()
    except etree.XMLSyntaxError as exc:
        error = str(exc)
    if error:
        # Drain completed records emitted before an invalid/truncated tail.
        for event, node in parser.read_events():
            if event == 'end' and node.tag == 'host' and len(node):
                nmap_host(result, node)
                node.clear()
        result.partial = True
        result.warnings.append(f'Incomplete XML. Only fully closed host records recovered. {error}')
    if not result.records and not result.metadata:
        raise ValueError('No supported scan records found in XML')
    if result.format == 'nmap-xml' and 'runstats' not in result.metadata:
        result.partial = True
        result.warnings.append('No final run statistics: scan completion and coverage are unknown.')
    return result


def parse_nessus_html(text):
    soup = BeautifulSoup(text, 'lxml')
    result = Result('nessus-html', warnings=['HTML summary export: plugin output, ports and scan timestamps may be absent. Full supplied HTML is retained.'])
    for row in soup.select('tr.plugin-row'):
        cells = [c.get_text(' ', strip=True) for c in row.find_all('td', recursive=False)]
        if len(cells) < 11 or not cells[9].isdigit():
            continue
        heading = row.find_previous('div', style=lambda s: s and 'font-size: 22px' in s)
        if not heading:
            continue
        host = heading.get_text(' ', strip=True)
        result.add('plugin', cells[10], str(row), {'host': host, 'severity': cells[1], 'cvss_display': cells[3],
                   'vpr': cells[5], 'epss': cells[7], 'pluginID': cells[9]}, [host])
    if not result.records:
        raise ValueError('Unrecognized Nessus HTML layout; original retained for inspection')
    return result


def json_record(result, obj, raw):
    if not isinstance(obj, dict):
        result.add('unmapped', 'Unmapped JSON value', raw, {'value': obj})
        return
    assets, links, ports = [], [], []
    kind = obj.get('type', '')
    value = obj.get('data_json') if obj.get('data_json') is not None else obj.get('data')
    if kind:
        if kind in ('DNS_NAME', 'IP_ADDRESS', 'IP_RANGE', 'URL', 'URL_UNVERIFIED') and isinstance(value, str):
            assets.append(value)
        host = obj.get('host') or (value if kind in ('DNS_NAME', 'IP_ADDRESS') else None)
        if host:
            assets.append(host)
            for target in obj.get('resolved_hosts', []) or []:
                assets.append(target)
                links.append((host, target, 'resolves-to'))
        if kind == 'OPEN_TCP_PORT' and isinstance(value, str):
            host, _, port = value.rpartition(':')
            host = host.strip('[]')
            if port.isdigit():
                assets.append(host)
                evidence = 'passive' if obj.get('module') in ('shodan_idb', 'internetdb') else 'hint'
                ports.append(dict(owner=host, port=int(port), protocol='tcp', state='open', evidence=evidence))
        if isinstance(value, dict):
            for key in ('host', 'url'):
                if value.get(key):
                    assets.append(value[key])
        result.add(kind.lower(), str(value)[:300], raw, obj, assets, links, ports, obj.get('timestamp'))
    elif 'host' in obj and any(k in obj for k in ('a', 'aaaa', 'cname', 'rcode', 'status_code')):
        host = obj['host']
        assets.append(host)
        for key in ('a', 'aaaa', 'cname'):
            values = obj.get(key) or []
            values = [values] if isinstance(values, str) else values
            for target in values:
                assets.append(target)
                links.append((host, target, 'aliases-to' if key == 'cname' else 'resolves-to'))
        if obj.get('url'):
            assets.append(obj['url'])
            links.append((obj['url'], host, 'web-host'))
        if obj.get('url') and str(obj.get('status_code','')).isdigit() and 100 <= int(obj['status_code']) <= 599:
            from urllib.parse import urlsplit
            u=urlsplit(obj['url'])
            if u.scheme in ('http','https'):
                ports.append(dict(owner=host,port=u.port or (443 if u.scheme=='https' else 80),protocol='tcp',state='open',service=u.scheme,evidence='probed',product=str(obj.get('webserver',''))))
        result.add('http' if 'status_code' in obj else 'dns', str(obj.get('url', host)), raw, obj, assets, links, ports=ports, observed=obj.get('timestamp'))
    elif 'url' in obj:
        result.add('web', str(obj['url']), raw, obj, [obj['url']], observed=obj.get('timestamp'))
    elif 'host' in obj and 'port' in obj:
        host = obj['host']
        port = dict(owner=host, port=int(obj['port']), protocol=obj.get('protocol', 'tcp'), state='open', service=obj.get('service_hint', ''), evidence='hint')
        result.add('port', f'{host} · {port["port"]}', raw, obj, [host], ports=[port], observed=obj.get('timestamp'))
    else:
        result.add('unmapped', 'Unmapped JSON record', raw, obj)


def parse_json(text):
    result = Result('json')
    try:
        obj = json.loads(text)
        if isinstance(obj, dict) and isinstance(obj.get('hosts'), dict):
            result.format = 'discovered-ports'
            result.metadata = obj.get('metadata', {})
            for host, ports in obj['hosts'].items():
                for port in ports:
                    record = {**port, 'host': host}
                    json_record(result, record, json.dumps(record))
        else:
            for record in obj if isinstance(obj, list) else [obj]:
                json_record(result, record, json.dumps(record, ensure_ascii=False))
    except json.JSONDecodeError:
        result.format = 'jsonl'
        for i, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                json_record(result, json.loads(line), line)
            except (json.JSONDecodeError, ValueError, TypeError) as exc:
                result.partial = True
                result.add('unparsed', f'Invalid JSON line {i}', line, {'error': str(exc)})
        if all(r['kind'] == 'unparsed' for r in result.records):
            raise ValueError('No valid JSON records')
    return result


def parse(data, filename):
    text = data.decode('utf-8-sig', errors='replace')
    head = text[:4000]
    if '<nmaprun' in head or '<NessusClientData_v2' in head:
        return parse_xml(data)
    if '<html' in head.lower() or '<!doctype html' in head.lower():
        return parse_nessus_html(text)
    if text.lstrip().startswith(('{', '[')):
        return parse_json(text)
    if filename.lower().endswith('.csv'):
        result = Result('csv')
        for row in csv.DictReader(io.StringIO(text)):
            json_record(result, row, json.dumps(row))
        return result
    if filename.lower().endswith(('.nmap', '.gnmap')):
        result = Result('nmap-text', warnings=['Lower-fidelity companion format. Original file retained; XML is preferred.'])
        owner = None
        for line in text.splitlines():
            match = re.match(r'Nmap scan report for (.+)', line)
            if match:
                owner = match[1].rsplit('(', 1)[-1].rstrip(')') if '(' in match[1] else match[1]
            gn = re.match(r'Host: (\S+).*Ports: (.*)', line)
            if gn:
                owner = gn[1]
                for part in gn[2].split(','):
                    fields = part.strip().split('/')
                    if len(fields) >= 5 and fields[0].isdigit():
                        port = dict(owner=owner, port=int(fields[0]), protocol=fields[2], state=fields[1], service=fields[4], evidence='hint')
                        result.add('port', f'{owner} · {port["port"]}', part, port, [owner], ports=[port])
            match = re.match(r'(\d+)/(tcp|udp)\s+(\S+)\s*(.*)', line)
            if match and owner:
                p = dict(owner=owner, port=int(match[1]), protocol=match[2], state=match[3], service=match[4].split(' ')[0], evidence='hint')
                result.add('port', f'{owner} · {p["port"]}', line, p, [owner], ports=[p])
        return result
    result = Result('seed-list')
    from .identity import identity
    for i, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        try:
            identity(line)
            result.add('seed', line, line, assets=[line])
        except ValueError:
            result.partial = True
            result.add('unparsed', f'Unrecognized line {i}', line)
    if not result.records:
        raise ValueError('No records found')
    return result
