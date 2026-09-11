import contextlib
import json
import os
from pathlib import Path
import sqlite3
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]


def now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def data_dir():
    p = Path(os.environ.get('VANDAL_DATA', str(ROOT / 'data'))).resolve()
    p.mkdir(parents=True, exist_ok=True, mode=0o700)
    return p


@contextlib.contextmanager
def connect(visible_eid=None):
    con = sqlite3.connect(data_dir() / 'vandal.db', timeout=30)
    con.row_factory = sqlite3.Row
    con.execute('PRAGMA foreign_keys=ON')
    try:
        if visible_eid is not None:
            from .scope_rules import install_visibility
            install_visibility(con, visible_eid)
        yield con
        con.commit()
    except BaseException:
        con.rollback()
        raise
    finally:
        con.close()


def migrate():
    with connect() as con:
        con.execute('PRAGMA journal_mode=WAL')
        con.execute('CREATE TABLE IF NOT EXISTS migrations(version TEXT PRIMARY KEY, applied_at TEXT NOT NULL)')
        for path in sorted((ROOT / 'vandal/migrations').glob('*.sql')):
            if not con.execute('SELECT 1 FROM migrations WHERE version=?', (path.name,)).fetchone():
                script = path.read_text()
                con.executescript('BEGIN IMMEDIATE;\n' + script)
                con.execute('INSERT INTO migrations VALUES (?,?)', (path.name, now()))
                con.commit()


def rows(con, sql, args=()):
    return [dict(r) for r in con.execute(sql, args)]


def dump(value):
    return json.dumps(value, ensure_ascii=False, default=str)
