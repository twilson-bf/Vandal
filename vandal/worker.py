import fcntl
import json
import os
import signal
import subprocess
import threading
import time
from .db import connect, data_dir, dump, now, rows, ROOT
from .ingest import ingest, queue_import, enrich_geo
from .jobs import prepare, validate_resolutions, PROFILES, executable
from .scope_rules import policy

stop = threading.Event()


def terminate(process):
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()


def execute(job):
    folder = data_dir() / 'jobs' / str(job['id'])
    folder.mkdir(parents=True, exist_ok=True)
    process = None
    status, error, code, import_ids = 'failed', '', None, []
    try:
        with connect() as con:
            rules, limited = policy(con, job['engagement_id'])
        plan = prepare(job['profile'], json.loads(job['targets']), json.loads(job['config']), rules, folder, limited)
        if plan['targets'] != json.loads(job['targets']):
            raise ValueError('Scope changed after queuing; review and create a new job')
        (folder / 'targets.txt').write_text('\n'.join(plan.get('scan_targets', plan['targets'])) + '\n')
        if plan.get('resolutions'):
            (folder / 'resolved-targets.jsonl').write_text('\n'.join(dump({'host': host, 'a': ips, 'resolver': 'system DNS at dispatch', 'timestamp': now()}) for host, ips in plan['resolutions'].items()) + '\n')
        if job['profile'] == 'httpx-web':
            validate_resolutions(plan['targets'], rules)
        version_args = ['--version'] if job['profile'] in ('bbot-passive', 'nmap-services', 'dns-validate', 'reverse-dns') else ['-version']
        version_command = [executable('gowitness'), 'version'] if job['profile']=='gowitness-web' else [plan['command'][0], *version_args]
        version = subprocess.run(version_command, capture_output=True, text=True, timeout=20)
        with connect() as con:
            con.execute('UPDATE jobs SET command=?,tool_version=? WHERE id=?', (dump(plan['command']), (version.stdout + version.stderr)[-2000:], job['id']))
            cancelled = con.execute('SELECT cancel_requested FROM jobs WHERE id=?', (job['id'],)).fetchone()[0]
        if cancelled or stop.is_set():
            status = 'cancelled' if cancelled else 'interrupted'
            return
        if json.loads(job['config']).get('geolocate'):
            from .geolocation import locate
            try:
                geo = locate(job['engagement_id'], plan['targets'][0])
            except Exception as exc:
                geo = {'status':'failed', 'error':str(exc), 'looked_up_at':now()}
            (folder / 'geolocation.json').write_text(dump(geo))
            with connect() as con:
                con.execute('UPDATE jobs SET geolocation=? WHERE id=?', (dump(geo), job['id']))
                cancelled = con.execute('SELECT cancel_requested FROM jobs WHERE id=?', (job['id'],)).fetchone()[0]
            if cancelled or stop.is_set():
                status = 'cancelled' if cancelled else 'interrupted'
                return
        with (folder / 'stdout.log').open('wb') as out, (folder / 'stderr.log').open('wb') as err:
            process = subprocess.Popen(plan['command'], cwd=ROOT, stdout=out, stderr=err, start_new_session=True,
                                       env={**os.environ, 'PYTHONUNBUFFERED': '1'})
            start = time.monotonic()
            while process.poll() is None:
                with connect() as con:
                    cancel = con.execute('SELECT cancel_requested FROM jobs WHERE id=?', (job['id'],)).fetchone()[0]
                if cancel or stop.is_set():
                    status = 'cancelled' if cancel else 'interrupted'
                    terminate(process)
                    break
                if time.monotonic() - start > 3600 or sum(p.stat().st_size for p in folder.glob('*.log')) > 20 * 1024 * 1024:
                    error = 'Job exceeded one-hour runtime or 20 MiB log limit'
                    terminate(process)
                    break
                stop.wait(.3)
            code = process.returncode
        if status not in ('cancelled', 'interrupted'):
            status = 'completed' if code == 0 and not error else 'failed'
        if job['profile']=='gowitness-web':
            from .webscan import persist
            persist(folder,job)
        for artifact in [folder / 'resolved-targets.jsonl', folder / 'output.xml', folder / 'output.jsonl', folder / 'bbot/output.json']:
            if artifact.is_file() and artifact.stat().st_size:
                iid, duplicate = queue_import(job['engagement_id'], artifact.name, artifact.read_bytes(), job['actor'])
                if not duplicate:
                    ingest(iid)
                import_ids.append(iid)
        if job['profile']=='gowitness-web':
            with connect() as con:
                con.execute('UPDATE web_captures SET asset_id=(SELECT a.id FROM assets a WHERE a.engagement_id=web_captures.engagement_id AND a.value=web_captures.host LIMIT 1) WHERE job_id=? AND asset_id IS NULL',(job['id'],))
    except Exception as exc:
        error = f'{type(exc).__name__}: {exc}'
    finally:
        if process:
            terminate(process)
        with connect() as con:
            con.execute("UPDATE job_steps SET status=?,ended_at=? WHERE job_id=? AND status='running'",(status,now(),job['id']))
            con.execute('UPDATE jobs SET status=?,ended_at=?,exit_code=?,error=?,import_ids=? WHERE id=?', (status, now(), code, error, dump(import_ids), job['id']))


def main():
    lock = (data_dir() / 'worker.lock').open('w')
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    with connect() as con:
        con.execute("UPDATE jobs SET status='interrupted',ended_at=?,error='Worker restarted; job was not replayed' WHERE status='running'", (now(),))
        con.execute("UPDATE imports SET status='interrupted' WHERE status='parsing'")
    from .enrichment import run as enrich_background
    enrichment_thread = threading.Thread(target=enrich_background, args=(stop,), daemon=True)
    enrichment_thread.start()
    while not stop.is_set():
        with connect() as con:
            item = con.execute("SELECT id FROM imports WHERE status='queued' ORDER BY id LIMIT 1").fetchone()
        if item:
            ingest(item['id'])
            try:
                enrich_geo()
            except Exception as exc:
                print(f'Geolocation unavailable: {exc}', flush=True)
            continue
        with connect() as con:
            con.execute('BEGIN IMMEDIATE')
            job = con.execute("SELECT * FROM jobs WHERE status='queued' ORDER BY id LIMIT 1").fetchone()
            if job:
                con.execute("UPDATE jobs SET status='running',started_at=? WHERE id=?", (now(), job['id']))
        if job:
            execute(dict(job))
        else:
            stop.wait(.75)


if __name__ == '__main__':
    main()
