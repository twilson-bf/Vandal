"""Offline review documents. Draft text has no path to the job executor."""
import json
import shlex
import sys
from pathlib import Path

from fastapi import APIRouter, Body, HTTPException, Request
from fastapi.responses import Response

from . import auth
from .db import connect, dump, now, rows
from .identity import identity
from .jobs import DEFAULT_NMAP_PORTS, PROFILES, executable, scope_targets
from .redact import command as redact_command
from .scope_rules import matcher

router = APIRouter(prefix='/api/e/{eid}/scan-drafts')


def proposal(body, rules):
    if not isinstance(body, dict):
        raise ValueError('Draft payload must be an object')
    profile = body.get('profile')
    if not isinstance(profile, str) or profile not in PROFILES:
        raise ValueError('Unknown scan profile')
    targets, config = body.get('targets'), body.get('config', {})
    if not isinstance(targets, list) or not 1 <= len(targets) <= 5000 or any(not isinstance(t, str) or len(t) > 2048 for t in targets):
        raise ValueError('Drafts require 1–5,000 target identifiers')
    if not isinstance(config, dict) or len(dump(config)) > 20000 or any(k.startswith('_') for k in config):
        raise ValueError('Invalid draft configuration')
    warnings, normalized = [], []
    for target in targets:
        try:
            kind, value = identity(target)
            if target.startswith('-') or kind not in ('ip', 'hostname', 'url'):
                raise ValueError('Expected an individual IP, hostname or HTTP(S) origin')
            if value not in normalized:
                normalized.append(value)
            if profile in ('bbot-passive', 'dns-validate') and kind != 'hostname':
                warnings.append('Hostname required by this profile: ' + target)
            elif profile == 'nmap-services' and kind not in ('hostname', 'ip'):
                warnings.append('Nmap profile requires an IP or hostname: ' + target)
        except ValueError as exc:
            warnings.append(f'{target}: {exc}')
    _, excluded = scope_targets(normalized, rules)
    if excluded:
        warnings.append(f'{len(excluded)} target(s) currently fail scope checks. Drafting does not change scope.')
    if len(targets) > (5000 if profile == 'gowitness-web' else 500):
        warnings.append('This profile allows at most 500 targets per job.')
    tool = executable(PROFILES[profile]['tool'])
    if not tool:
        warnings.append('Tool is not installed; this draft can still be saved.')
        tool = PROFILES[profile]['tool']
    folder = Path('<job-directory>')
    inputs = str(folder / 'targets.txt')
    argv = [tool]
    try:
        if profile == 'nmap-services':
            from .nmap_options import arguments, option
            argv += arguments(config, DEFAULT_NMAP_PORTS) + ['-iL', inputs, '-oX', str(folder / 'output.xml')]
            family = option(config, 'address_family', 'auto', ('auto', 'ipv4', 'ipv6'))
            if family == 'ipv6' or family == 'auto' and normalized and all(':' in t and '://' not in t for t in normalized):
                argv.append('-6')
        elif profile == 'bbot-passive':
            modules = config.get('modules', ['crt', 'hackertarget', 'rapiddns', 'shodan_idb'])
            if not isinstance(modules, list) or not modules or any(m not in ('crt', 'hackertarget', 'rapiddns', 'shodan_idb') for m in modules):
                raise ValueError('Select at least one supported discovery source')
            argv += ['-t', inputs, '-m', *dict.fromkeys(modules), '-rf', 'passive', '-c', 'dns.disable=false', 'deps.behavior=disable', '-om', 'json', '-o', str(folder), '-n', 'bbot', '-y']
            exclusions = [r['target'] for r in rules if r['action'] == 'exclude']
            if exclusions:
                argv += ['-b', *exclusions]
        elif profile == 'dns-validate':
            argv = [sys.executable, '-m', 'vandal.probes', 'dns', inputs, str(folder / 'output.jsonl')]
        elif profile == 'gowitness-web':
            from .web_inventory import validate_config
            validate_config(config)
            argv = [sys.executable, '-m', 'vandal.webscan', 'run', str(folder)]
            warnings.append('Web candidate URLs are calculated during profile validation.')
        else:
            from .nmap_options import number
            argv += ['-l', inputs, '-json', '-o', str(folder / 'output.jsonl'), '-sc', '-title', '-td', '-ip', '-irh', '-rl', number(config, 'rate', 5, 1, 100), '-threads', number(config, 'threads', 5, 1, 50), '-timeout', number(config, 'timeout', 10, 1, 120), '-duc']
    except ValueError as exc:
        warnings.append('Options need correction: ' + str(exc))
        argv = [tool, '<options need correction>', '<targets.txt>']
    warnings.append('DNS was not queried. Hostnames are retained in the draft target list.')
    payload = {'profile': profile, 'targets': targets, 'config': config, 'add_scope': body.get('add_scope') is True}
    return {'payload': payload, 'command': shlex.join(argv), 'warnings': warnings,
            'excluded': excluded, 'normalized_targets': normalized, 'executable': False}


def visible_ids(con, eid):
    excluded = matcher([r[0] for r in con.execute("SELECT target FROM scope_rules WHERE engagement_id=? AND action='exclude'", (eid,))])
    visible = {r[0] for r in con.execute('SELECT id FROM scan_drafts WHERE engagement_id=?', (eid,))}
    for r in con.execute('SELECT r.draft_id,r.payload FROM scan_draft_revisions r JOIN scan_drafts d ON d.id=r.draft_id WHERE d.engagement_id=?', (eid,)):
        for target in json.loads(r['payload'])['targets']:
            try:
                target = identity(target)[1]
            except ValueError:
                continue  # Invalid identifiers remain draft warnings, not inventory subjects.
            if excluded(target):
                visible.discard(r['draft_id'])
                break
    return visible


def read_draft(con, eid, did):
    if did not in visible_ids(con, eid):
        raise HTTPException(404, 'Draft not found')
    result = dict(con.execute('SELECT * FROM scan_drafts WHERE id=? AND engagement_id=?', (did, eid)).fetchone())
    revisions = rows(con, 'SELECT * FROM scan_draft_revisions WHERE draft_id=? ORDER BY revision DESC', (did,))
    for revision in revisions:
        revision['payload'] = json.loads(revision['payload'])
        revision['warnings'] = json.loads(revision['warnings'])
    return {**result, **revisions[0], 'id': did, 'revisions': revisions}


@router.post('/preview')
def preview(eid: int, request: Request, body: dict = Body(...)):
    auth.access(request, eid, True)
    with connect() as con:
        return proposal(body, rows(con, 'SELECT * FROM scope_rules WHERE engagement_id=?', (eid,)))


@router.get('')
def listing(eid: int, request: Request):
    auth.access(request, eid)
    with connect() as con:
        visible = visible_ids(con, eid)
        return [r for r in rows(con, 'SELECT * FROM scan_drafts WHERE engagement_id=? ORDER BY updated_at DESC,id DESC', (eid,)) if r['id'] in visible]


@router.get('/{did}')
def detail(eid: int, did: int, request: Request, export: bool = False):
    auth.access(request, eid)
    with connect() as con:
        item = read_draft(con, eid, did)
    if export:
        return Response(dump(item), media_type='application/json', headers={'Content-Disposition': f'attachment; filename="vandal-draft-{did}.json"'})
    return item


@router.post('')
@router.put('/{did}')
def save(eid: int, request: Request, body: dict = Body(...), did: int = 0):
    actor = auth.access(request, eid, True)
    title, command, notes = body.get('title', ''), body.get('command', ''), body.get('notes', '')
    if not isinstance(title, str):
        raise ValueError('Draft title must be text')
    title = title.strip()
    if not title or len(title) > 150 or not isinstance(command, str) or len(command) > 20000 or not isinstance(notes, str) or len(notes) > 20000:
        raise ValueError('Draft requires a title (150 characters max), command and notes (20,000 characters max each)')
    with connect() as con:
        con.execute('BEGIN IMMEDIATE')
        plan = proposal(body.get('payload', {}), rows(con, 'SELECT * FROM scope_rules WHERE engagement_id=?', (eid,)))
        if did:
            old = read_draft(con, eid, did)
            if body.get('base_revision') != old['revision']:
                raise HTTPException(409, 'Draft changed in another session. Reopen it before saving.')
            revision = old['revision'] + 1
            con.execute('UPDATE scan_drafts SET title=?,profile=?,revision=?,updated_at=? WHERE id=?', (title, plan['payload']['profile'], revision, now(), did))
        else:
            revision = 1
            did = con.execute('INSERT INTO scan_drafts(engagement_id,title,profile,revision,created_at,updated_at) VALUES (?,?,?,?,?,?)', (eid, title, plan['payload']['profile'], revision, now(), now())).lastrowid
        error = body.get('validation_error', '')
        if not isinstance(error, str) or len(error) > 5000:
            raise ValueError('Invalid validation error')
        if error:
            plan['warnings'].append('Last reported profile validation error: ' + error)
        con.execute('INSERT INTO scan_draft_revisions VALUES (?,?,?,?,?,?,?,?)', (did, revision, dump(plan['payload']), command, notes, dump(plan['warnings']), actor['name'], now()))
        con.execute('INSERT INTO audit(engagement_id,actor,action,detail,created_at) VALUES (?,?,?,?,?)', (eid, actor['name'], 'draft.saved', dump({'id': did, 'revision': revision}), now()))
    return {'id': did, 'revision': revision}


def timeline_events(con, eid):
    visible = visible_ids(con, eid)
    return [{'type': 'draft', 'id': r['draft_id'], 'profile': json.loads(r['payload'])['profile'], 'filename': r['title'],
             'actor': r['actor'], 'created_at': r['created_at'], 'status': 'draft', 'revision': r['revision'],
             'command': redact_command(r['command'])}
            for r in rows(con, 'SELECT r.*,d.title,d.profile FROM scan_draft_revisions r JOIN scan_drafts d ON d.id=r.draft_id WHERE d.engagement_id=?', (eid,)) if r['draft_id'] in visible]
