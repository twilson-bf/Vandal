"""Local UI fixture server. Requires an explicit temporary data directory."""
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
assert os.environ.get('VANDAL_DATA') and os.environ.get('VANDAL_WORKER') == '0'
from vandal.db import migrate, connect, now
from vandal.auth import bootstrap
from vandal.ingest import queue_import, ingest
from tests.test_platform import NMAP

migrate()
bootstrap()
with connect() as con:
    eid=con.execute('INSERT INTO engagements(name,created_at) VALUES (?,?)', ('Browser fixture',now())).lastrowid
for name,body in [('scan.xml',NMAP),('dns.json',json.dumps({'host':'www.example.com','a':['192.0.2.1'],'query_type':'A','rcode':'NOERROR','resolver':'fixture','timestamp':'2026-09-10T00:00:00Z'}).encode())]:
    iid,_=queue_import(eid,name,body,'fixture')
    ingest(iid)
import uvicorn
uvicorn.run('vandal.app:app',host='127.0.0.1',port=8879,log_level='warning')
