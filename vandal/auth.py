import hashlib
import secrets
import time
import os
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from fastapi import HTTPException, Request
from .db import connect, data_dir

hasher = PasswordHasher()


def bootstrap():
    with connect() as con:
        if con.execute('SELECT 1 FROM users LIMIT 1').fetchone():
            return
        password = os.getenv('VANDAL_ADMIN_PASSWORD') or secrets.token_urlsafe(18)
        con.execute("INSERT INTO users(name,password,role) VALUES ('admin',?,'admin')", (hasher.hash(password),))
        if not os.getenv('VANDAL_ADMIN_PASSWORD'):
            path = data_dir() / 'initial-admin-password'
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as stream:
                stream.write(password + '\n')
            print(f'vandal: initial admin password saved to {path}', flush=True)


def user(request: Request):
    token = request.cookies.get('vandal_session', '')
    with connect() as con:
        row = con.execute('SELECT u.id,u.name,u.role,s.csrf FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND s.expires>?',
                          (hashlib.sha256(token.encode()).hexdigest(), int(time.time()))).fetchone()
    if not row:
        raise HTTPException(401, 'Sign in to continue')
    return dict(row)


def access(request, engagement, write=False):
    actor = user(request)
    if write:
        if actor['role'] == 'viewer':
            raise HTTPException(403, 'Read-only account')
        if not secrets.compare_digest(request.headers.get('X-CSRF-Token', ''), actor['csrf']):
            raise HTTPException(403, 'Missing or invalid CSRF token')
    with connect() as con:
        if not con.execute('SELECT 1 FROM engagements WHERE id=?', (engagement,)).fetchone():
            raise HTTPException(404, 'Engagement not found')
        if actor['role'] != 'admin' and not con.execute('SELECT 1 FROM members WHERE engagement_id=? AND user_id=?', (engagement, actor['id'])).fetchone():
            raise HTTPException(403, 'No access to this engagement')
    return actor


def login(name, password):
    with connect() as con:
        row = con.execute('SELECT * FROM users WHERE name=?', (name,)).fetchone()
        try:
            if not row or not hasher.verify(row['password'], password):
                raise HTTPException(401, 'Incorrect username or password')
        except VerificationError:
            raise HTTPException(401, 'Incorrect username or password')
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
        con.execute('DELETE FROM sessions WHERE expires<?', (int(time.time()),))
        con.execute('INSERT INTO sessions VALUES (?,?,?,?)', (hashlib.sha256(token.encode()).hexdigest(), row['id'], csrf, int(time.time()) + 43200))
    return token
