import argparse
import getpass
from pathlib import Path
from .db import migrate, connect, now
from .auth import bootstrap, hasher
from .ingest import queue_import, ingest, enrich_geo


def main():
    parser = argparse.ArgumentParser(description='vandal workspace management')
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('init')
    imp = sub.add_parser('import')
    imp.add_argument('path', type=Path)
    imp.add_argument('--engagement', required=True)
    user = sub.add_parser('user')
    user.add_argument('name')
    user.add_argument('--role', choices=['admin', 'operator', 'viewer'], default='operator')
    user.add_argument('--engagement', type=int)
    sub.add_parser('geo')
    args = parser.parse_args()
    migrate()
    bootstrap()
    if args.command == 'import':
        with connect() as con:
            row = con.execute('SELECT id FROM engagements WHERE name=?', (args.engagement,)).fetchone()
            eid = row[0] if row else con.execute('INSERT INTO engagements(name,created_at) VALUES (?,?)', (args.engagement, now())).lastrowid
        files = sorted(p for p in args.path.rglob('*') if p.is_file()) if args.path.is_dir() else [args.path]
        for path in files:
            if path.suffix.lower() not in ('.xml', '.nessus', '.nmap', '.gnmap', '.html', '.json', '.jsonl', '.csv', '.txt'):
                continue
            iid, duplicate = queue_import(eid, path.name, path.read_bytes(), 'CLI import')
            if not duplicate:
                ingest(iid)
            with connect() as con:
                row = con.execute('SELECT status,record_count FROM imports WHERE id=?', (iid,)).fetchone()
            print(f'{path.name}: {row["status"]}, {row["record_count"]} records' + (' (duplicate)' if duplicate else ''))
        enrich_geo()
    elif args.command == 'user':
        password = getpass.getpass('Password: ')
        if len(password) < 12:
            parser.error('Use at least 12 characters')
        with connect() as con:
            uid = con.execute('INSERT INTO users(name,password,role) VALUES (?,?,?)', (args.name, hasher.hash(password), args.role)).lastrowid
            if args.engagement:
                con.execute('INSERT INTO members VALUES (?,?)', (args.engagement, uid))
    elif args.command == 'geo':
        print(f'Updated {enrich_geo()} geolocation/ASN records')


if __name__ == '__main__':
    main()
