#!/usr/bin/env python3
"""Copy configured official distribution sources into an isolated APT source set."""
import argparse
from pathlib import Path
import re
from urllib.parse import urlsplit


HOSTS = {
    'kali': ('kali.org', 'kali.download'),
    'debian': ('debian.org',),
    'ubuntu': ('ubuntu.com',),
}


def official(uri, distro):
    parsed = urlsplit(uri)
    host = parsed.hostname or ''
    return parsed.scheme in ('http', 'https') and any(
        host == suffix or host.endswith('.' + suffix) for suffix in HOSTS[distro])


def select_sources(root, destination, distro):
    lists, stanzas = [], []
    files = [root / 'sources.list', *sorted((root / 'sources.list.d').glob('*.list')),
             *sorted((root / 'sources.list.d').glob('*.sources'))]
    for path in files:
        if not path.is_file():
            continue
        content = path.read_text()
        if path.suffix == '.sources':
            for block in re.split(r'\n\s*\n', content):
                # Keep complete field values, including embedded Signed-By keys.
                fields = {}
                key = None
                for line in block.splitlines():
                    if line.lstrip().startswith('#'):
                        continue
                    if line[:1].isspace() and key:
                        fields[key] += '\n' + line
                    elif ':' in line:
                        key, value = line.split(':', 1)
                        key = key.lower()
                        fields[key] = value.strip()
                if fields.get('enabled', 'yes').lower() == 'no' or 'deb' not in fields.get('types', '').split():
                    continue
                uris = [u for u in fields.get('uris', '').split() if official(u, distro)]
                if uris:
                    fields['uris'] = ' '.join(uris)
                    stanzas.append('\n'.join(f'{k}: {v}' for k, v in fields.items()))
        else:
            for line in content.splitlines():
                match = re.match(r'^\s*deb\s+(?:\[[^\]]*\]\s+)?(\S+)\s+', line)
                if match and official(match[1], distro):
                    lists.append(line)
    if not lists and not stanzas:
        raise ValueError('No configured official distribution source found. Custom mirrors require manual system package installation.')
    destination.mkdir(parents=True, exist_ok=True)
    (destination / 'distribution.list').write_text('\n'.join(lists) + '\n')
    (destination / 'distribution.sources').write_text('\n\n'.join(stanzas) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('distro', choices=HOSTS)
    parser.add_argument('destination', type=Path)
    args = parser.parse_args()
    try:
        select_sources(Path('/etc/apt'), args.destination, args.distro)
    except (OSError, ValueError) as exc:
        parser.exit(1, f'ERROR: {exc}\n')
