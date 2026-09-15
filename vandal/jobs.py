"""Structured command profiles. No shell expansion and no automatic scan chaining."""
import ipaddress
import json
from pathlib import Path
import re
import shutil
import socket
import sys
from .db import ROOT, data_dir
from .identity import identity, in_rule

DEFAULT_NMAP_PORTS = '22,80,443,445,3389,8080,8443'

PROFILES = {
    'gowitness-web': {'name':'Web inventory & screenshots', 'tool':'gowitness', 'description':'Validate HTTP/HTTPS on observed TCP ports, then capture responding URLs with gowitness.'},
    'bbot-passive': {'name': 'Subdomains + passive ports', 'tool': 'bbot', 'description': 'crt, hackertarget, rapiddns + Shodan InternetDB. DNS resolution enabled; ports are provider observations.'},
    'dns-validate': {'name': 'Independent DNS validation', 'tool': 'python', 'description': 'A / AAAA / CNAME answers from Cloudflare and Google, retained separately.'},
    'nmap-services': {'name': 'Ports & services', 'tool': 'nmap', 'description': 'TCP ports, service versions and optional NSE checks for scoped IPs or hostnames.'},
    'httpx-web': {'name': 'HTTP inventory', 'tool': 'httpx', 'description': 'HTTP metadata and technology hints. No redirect following or automatic TLS-domain expansion.'},
}


def executable(tool):
    if tool == 'python':
        return sys.executable
    local = ROOT / '.tools/bin' / tool
    return str(local) if local.is_file() else shutil.which(tool)


def scope_targets(targets, rules, limit_to_included=False):
    accepted, excluded = [], []
    includes = [r['target'] for r in rules if r['action'] == 'include']
    excludes = [r['target'] for r in rules if r['action'] == 'exclude']
    for value in targets:
        _, normalized = identity(value)
        reason = 'Matches exclusion' if any(in_rule(normalized, x) for x in excludes) else 'No matching include rule' if limit_to_included and not any(in_rule(normalized, x) for x in includes) else ''
        if reason:
            excluded.append({'target': normalized, 'reason': reason})
        elif normalized not in accepted:
            accepted.append(normalized)
    return accepted, excluded


def prepare(profile, targets, config, rules, folder=None, limit_to_included=False):
    if profile not in PROFILES:
        raise ValueError('Unknown scan profile')
    if not isinstance(targets, list) or not all(isinstance(t, str) for t in targets) or not targets or len(targets) > (5000 if profile=='gowitness-web' else 500):
        raise ValueError('Select 1–5,000 targets for web capture, or 1–500 for other scans')
    if not isinstance(config, dict):
        raise ValueError('Profile configuration must be an object')
    if any(len(t) > 2048 or t.startswith('-') for t in targets):
        raise ValueError('Invalid target')
    accepted, excluded = scope_targets(targets, rules, limit_to_included)
    if not accepted:
        suffix = ' Add an included group or disable “limit to included”.' if limit_to_included else ''
        raise ValueError('No targets remain after scope rules.' + suffix)
    if profile in ('bbot-passive', 'dns-validate') and any(identity(t)[0] != 'hostname' for t in accepted):
        raise ValueError('This profile requires hostnames')
    if profile == 'httpx-web' and any(identity(t)[0] not in ('hostname', 'ip', 'url') for t in accepted):
        raise ValueError('HTTP inventory requires hostnames, IPs or HTTP(S) origins')
    tool = executable(PROFILES[profile]['tool'])
    if not tool:
        raise ValueError('Tool is not installed. Run install.sh doctor.')
    folder = Path(folder) if folder else Path('<job-directory>')
    inputs = folder / 'targets.txt'
    if profile == 'gowitness-web':
        from .web_inventory import validate_config
        validate_config(config)
        if not shutil.which('chromium') and not shutil.which('google-chrome'):
            raise ValueError('Chromium is missing; run ./install.sh --system')
        if any(identity(t)[0] not in ('ip','hostname','url') for t in accepted):
            raise ValueError('Web capture requires hostnames, IPs or HTTP(S) origins')
        argv = [sys.executable, '-m', 'vandal.webscan', 'run', str(folder)]
    elif profile == 'nmap-services':
        from .nmap_options import arguments, resolve
        flags = arguments(config, DEFAULT_NMAP_PORTS)
        scan_targets, resolutions, version = resolve(accepted, config, rules)
        argv = [tool, *flags, '-iL', str(inputs), '-oX', str(folder / 'output.xml')]
        if version == 6: argv.append('-6')
    elif profile == 'bbot-passive':
        missing = [name for name in ('unzip', 'zipinfo', 'curl', 'git', 'make', 'gcc', 'bash', 'which', 'tar', 'xz', '7z') if not shutil.which(name)]
        if not any(Path(p).is_file() for p in ('/usr/include/openssl/ssl.h', '/usr/local/include/openssl/ssl.h')):
            missing.append('OpenSSL development headers')
        if missing:
            raise ValueError('Missing BBOT system dependencies: ' + ', '.join(missing) + '. Run ./install.sh --system in a terminal, then preview again.')
        modules = config.get('modules', ['crt','hackertarget','rapiddns','shodan_idb'])
        if not isinstance(modules, list) or not modules or any(m not in ('crt','hackertarget','rapiddns','shodan_idb') for m in modules):
            raise ValueError('Select at least one supported passive discovery source')
        argv = [tool, '-t', *accepted, '-m', *dict.fromkeys(modules), '-rf', 'passive', '-c', 'dns.disable=false', 'deps.behavior=disable', '-om', 'json', '-o', str(folder), '-n', 'bbot', '-y']
        blacklist = [rule['target'] for rule in rules if rule['action'] == 'exclude']
        if blacklist:
            argv.extend(['-b', *blacklist])
    elif profile == 'dns-validate':
        argv = [sys.executable, '-m', 'vandal.probes', 'dns', str(inputs), str(folder / 'output.jsonl')]
    else:
        from .nmap_options import number
        argv = [tool, '-l', str(inputs), '-json', '-o', str(folder / 'output.jsonl'), '-sc', '-title', '-td', '-ip', '-irh', '-rl', number(config,'rate',5,1,100), '-threads', number(config,'threads',5,1,50), '-timeout', number(config,'timeout',10,1,120), '-duc']
    plan = {'command': argv, 'targets': accepted, 'excluded': excluded}
    if profile == 'nmap-services': plan.update(scan_targets=scan_targets, resolutions=resolutions)
    return plan


def validate_resolutions(targets, rules):
    """Check current resolution against exclusions before dispatch; never expand scope."""
    from urllib.parse import urlsplit
    excluded = [r['target'] for r in rules if r['action'] == 'exclude']
    for value in targets:
        host = urlsplit(value).hostname if '://' in value else value
        for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM):
            ip = item[4][0]
            if any(in_rule(ip, rule) for rule in excluded):
                raise ValueError(f'{host} currently resolves to excluded address {ip}')
