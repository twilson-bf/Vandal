"""Validated Nmap controls and DNS snapshots; commands never accept shell text."""
import ipaddress
import re
import socket
from .identity import identity, in_rule


def number(config, key, default, low, high):
    value = config.get(key, default)
    if isinstance(value, bool) or not re.fullmatch(r'\d+', str(value)) or not low <= int(value) <= high:
        raise ValueError(f'{key} must be an integer from {low} to {high}')
    return str(int(value))


def option(config, key, default, choices):
    value = config.get(key, default)
    if value not in choices:
        raise ValueError(f'Invalid {key}; choose ' + ', '.join(choices))
    return value


def arguments(config, default_ports):
    argv = ['-sT', '-n']
    service = option(config, 'service_detection', 'light', ('off','light','standard','thorough'))
    if service != 'off':
        argv += ['-sV', '--version-intensity', {'light':'2','standard':'7','thorough':'9'}[service]]
    discovery = option(config, 'host_discovery', 'skip', ('skip','probe'))
    if discovery == 'skip': argv += ['-Pn']
    mode = option(config, 'port_mode', 'custom', ('custom','top','all'))
    if mode == 'custom':
        ports = str(config.get('ports', default_ports)).replace(' ', '')
        for token in ports.split(','):
            if not re.fullmatch(r'\d{1,5}(-\d{1,5})?', token):
                raise ValueError('Ports must be numbers or ranges separated by commas')
            ends = list(map(int, token.split('-')))
            if min(ends) < 1 or max(ends) > 65535 or ends[0] > ends[-1]:
                raise ValueError('Invalid port range')
        argv += ['-p', ports]
    elif mode == 'top': argv += ['--top-ports', number(config,'top_ports',1000,1,65535)]
    else: argv += ['-p-']
    argv += ['-T'+number(config,'timing',3,0,5), '--max-rate',number(config,'max_rate',100,1,10000),
             '--max-retries',number(config,'max_retries',2,0,10),
             '--host-timeout',number(config,'host_timeout',180,10,3600)+'s']
    scripts = []
    for key in ('service_scripts','tls_checks','safe_vulns','vulners'):
        if key in config and not isinstance(config[key], bool): raise ValueError(f'{key} must be true or false')
    if config.get('service_scripts'): scripts += ['http-title','http-headers','ssl-cert','ssh-hostkey','smb-protocols']
    if config.get('tls_checks'): scripts += ['ssl-enum-ciphers']
    if config.get('safe_vulns'): scripts += ['(vuln and safe) and not (external or intrusive or dos or exploit or brute or broadcast or fuzzer)']
    if config.get('vulners'):
        if service == 'off': raise ValueError('Vulners requires service/version detection')
        scripts += ['vulners']
        argv += ['--script-args','vulners.mincvss='+number(config,'min_cvss',0,0,10)]
    if scripts: argv += ['--script',','.join(scripts),'--script-timeout',number(config,'script_timeout',60,5,600)+'s']
    return argv


def resolve(targets, config, rules):
    kinds = [identity(t)[0] for t in targets]
    if any(k not in ('ip','hostname') for k in kinds): raise ValueError('Enter IP addresses or hostnames for this Nmap profile')
    family = option(config,'address_family','auto',('auto','ipv4','ipv6'))
    version = (6 if all(k=='ip' and ipaddress.ip_address(t).version==6 for k,t in zip(kinds,targets)) else 4) if family=='auto' else (6 if family=='ipv6' else 4)
    addresses, resolutions = [], {}
    for kind, target in zip(kinds,targets):
        if kind == 'ip':
            if ipaddress.ip_address(target).version != version: raise ValueError('Scan IPv4 and IPv6 addresses in separate jobs; choose the address family')
            ips = [target]
        else:
            try:
                ips = sorted({str(ipaddress.ip_address(r[4][0])) for r in socket.getaddrinfo(target,None,socket.AF_INET6 if version==6 else socket.AF_INET,socket.SOCK_STREAM)})
            except socket.gaierror as exc:
                raise ValueError(f'Could not resolve {target} for IPv{version}: {exc}') from exc
            if not ips: raise ValueError(f'No IPv{version} addresses for {target}')
            resolutions[target] = ips
        for ip in ips:
            if any(in_rule(ip,r['target']) for r in rules if r['action']=='exclude'):
                raise ValueError(f'{target} resolves to excluded address {ip}; remove this target or review exclusions')
            if ip not in addresses: addresses.append(ip)
    if len(addresses)>2000: raise ValueError('Resolution exceeds 2,000 IPs; split the job')
    if '_nmap_snapshot' in config and config['_nmap_snapshot'] != resolutions:
        raise ValueError('DNS changed after queuing; preview a new scan to review its addresses')
    return addresses, resolutions, version
