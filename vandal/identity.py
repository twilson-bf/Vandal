import ipaddress
from urllib.parse import urlsplit
import tldextract

suffixes = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)


def identity(value):
    value = str(value).strip()
    if not value or len(value) > 2048:
        raise ValueError('Invalid or empty asset')
    if '://' in value:
        u = urlsplit(value)
        if u.scheme not in ('http', 'https') or not u.hostname or u.username or u.password:
            raise ValueError('Expected an HTTP(S) origin without credentials')
        host = identity(u.hostname)[1]
        formatted = f'[{host}]' if ':' in host else host
        port = u.port or (443 if u.scheme == 'https' else 80)
        return 'url', f'{u.scheme}://{formatted}:{port}'
    try:
        return 'ip', str(ipaddress.ip_address(value))
    except ValueError:
        pass
    if '/' in value:
        return 'network', str(ipaddress.ip_network(value, strict=False))
    if value.upper().startswith('AS') and value[2:].isdigit():
        return 'asn', 'AS' + str(int(value[2:]))
    value = value.rstrip('.').encode('idna').decode('ascii').lower()
    if len(value) > 253 or any(not part or len(part) > 63 or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789-_' for c in part) for part in value.split('.')):
        raise ValueError('Invalid hostname')
    return 'hostname', value


def root_domain(name):
    return suffixes(name).top_domain_under_public_suffix or name


def in_rule(target, rule):
    kind, value = identity(target)
    rkind, rvalue = identity(rule.removeprefix('*.'))
    if rkind == 'network':
        return kind == 'ip' and ipaddress.ip_address(value) in ipaddress.ip_network(rvalue)
    if rkind == 'hostname':
        host = urlsplit(value).hostname if kind == 'url' else value
        return host == rvalue or host.endswith('.' + rvalue)
    return kind == rkind and value == rvalue
