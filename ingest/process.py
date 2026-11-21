#!/usr/bin/env python3
"""Scratch processor: state-based inbox scan, offline attestation verify, store commit."""
import hashlib, json, os, re, subprocess, sys, tempfile, time, shutil

ROOT = os.getcwd()                      # checkout of central main
STORE = os.path.join(ROOT, '_store')    # worktree of branch store
CFG = json.load(open('config.json'))
REG = json.load(open('registry.json'))
ACCEPTED = set(json.load(open('accepted_upload_revisions.json')))
REF_RE = re.compile(r'^inbox/([0-9]{1,20})/([0-9]{6})$')
PATH_RE = re.compile(r'^([0-9]+-[0-9]+-[0-9a-f]{16})/(submission|bundle)\.json$')
ALLOWED = {"schema_version","repo_id","repo","run_id","run_attempt","kind","unit","deployment_id","producer","manifest","facts","evidence"}
META = {"run_id", "run_attempt", "producer", "collected_at"}


def git(*a, cwd=ROOT, check=True):
    r = subprocess.run(['git', *a], cwd=cwd, capture_output=True, text=True)
    if check and r.returncode:
        raise RuntimeError('git %s: %s' % (a, r.stderr))
    return r.stdout


def now():
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())


def load(p, default):
    p = os.path.join(STORE, p)
    return json.load(open(p)) if os.path.exists(p) else default


def save(p, obj):
    p = os.path.join(STORE, p)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    json.dump(obj, open(p, 'w'), sort_keys=True, indent=1)


def no_dupes(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError('duplicate key ' + k)
        d[k] = v
    return d


def depth(o, n=1):
    if n > 8:
        raise ValueError('depth')
    if isinstance(o, dict):
        for v in o.values(): depth(v, n + 1)
    elif isinstance(o, list):
        if len(o) > 2000: raise ValueError('array')
        for v in o: depth(v, n + 1)
    elif isinstance(o, str) and len(o) > 512:
        raise ValueError('string')


def canon(sub):
    def strip(o):
        if isinstance(o, dict):
            return {k: strip(v) for k, v in o.items() if k not in META}
        if isinstance(o, list):
            return [strip(v) for v in o]
        return o
    body = strip({"facts": sub["facts"], "evidence": sub["evidence"]})
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


# ---------- discovery from history ----------
def discover(ref, frontier):
    rng = (frontier + '..' + ref) if frontier else ref
    out = git('log', '--reverse', '--no-renames', '--name-status', '--format=C%H', rng, '--', check=False)
    items, order, cur = {}, [], None
    for line in out.splitlines():
        if line.startswith('C'):
            cur = line[1:]
            order.append(cur)
            continue
        if not line.strip() or cur is None:
            continue
        st, path = line.split('\t', 1)
        m = PATH_RE.match(path)
        key = m.group(1) if m else path.split('/')[0]
        it = items.setdefault(key, {'added': {}, 'tamper': [], 'commit': cur, 'bad': not m})
        if st == 'A' and path not in it['added']:
            it['added'][path] = cur
        elif st in ('M', 'D') or (st == 'A' and path in it['added']):
            it['tamper'].append((st, path, cur))
        if not m:
            it['bad'] = True
    return items, order


def blob_of(commit, path):
    row = git('ls-tree', commit, '--', path).split()
    return row[0], row[2]            # mode, sha


def verify(tmp, repo_name):
    cmd = ['gh', 'attestation', 'verify', os.path.join(tmp, 'submission.json'), '--bundle', os.path.join(tmp, 'bundle.json'),
           '--repo', repo_name, '--signer-workflow', CFG['signer_workflow'],
           '--custom-trusted-root', os.path.join(ROOT, 'trusted_root.jsonl'), '--format', 'json']
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode:
        return None, (r.stderr.strip().splitlines() or ['?'])[-1][:200]
    try:
        return json.loads(r.stdout)[0]['verificationResult']['signature']['certificate'], ''
    except Exception as e:
        return None, 'json ' + str(e)


def process_item(ref, rid, key, it, st):
    """returns (verdict, detail)"""
    d16 = key.split('-')[-1]
    if it['bad']:
        return 'quarantined:bad_path', ','.join(sorted(it['added']))[:100]
    pb, ps = key + '/bundle.json', key + '/submission.json'
    if set(it['added']) != {pb, ps}:
        return 'quarantined:bad_path', 'need exactly two blobs'
    blobs = {}
    for p in (ps, pb):
        mode, sha = blob_of(it['added'][p], p)
        if mode != '100644':
            return 'quarantined:bad_path', 'mode ' + mode
        size = int(git('cat-file', '-s', sha))
        if size > (CFG['max_submission'] if p == ps else CFG['max_bundle']):
            return 'quarantined:oversize', '%s %d' % (p.split('/')[1], size)
        blobs[p] = sha
    sub_b = subprocess.run(['git', 'cat-file', 'blob', blobs[ps]], cwd=ROOT, capture_output=True).stdout
    bun_b = subprocess.run(['git', 'cat-file', 'blob', blobs[pb]], cwd=ROOT, capture_output=True).stdout
    if hashlib.sha256(sub_b + bun_b).hexdigest()[:16] != d16:
        return 'quarantined:bad_digest', ''
    reg = REG.get(rid)
    if not reg or not reg.get('enabled'):
        return 'quarantined:repo_not_enabled', rid
    tmp = tempfile.mkdtemp()
    open(tmp + '/submission.json', 'wb').write(sub_b)
    open(tmp + '/bundle.json', 'wb').write(bun_b)
    cert, err = verify(tmp, reg['name'])
    if cert is None:
        shutil.rmtree(tmp)
        return 'quarantined:unverifiable', err
    run_m = re.search(r'/runs/([0-9]+)/attempts/([0-9]+)$', cert['runInvocationURI'])
    if cert['sourceRepositoryIdentifier'] != rid or cert['sourceRepositoryOwnerIdentifier'] != CFG['owner_id'] \
            or cert['runnerEnvironment'] != 'github-hosted' or not run_m or '%s-%s' % run_m.groups() != '-'.join(key.split('-')[:2]):
        return 'quarantined:identity_mismatch', ''
    if cert['buildSignerDigest'] not in ACCEPTED:
        return 'quarantined:workflow_not_approved', cert['buildSignerDigest'][:12]
    if cert['buildTrigger'] not in CFG['accepted_triggers']:
        return 'quarantined:bad_trigger', cert['buildTrigger']
    if cert['sourceRepositoryRef'] != 'refs/heads/' + reg['default_branch']:
        return 'quarantined:bad_ref', cert['sourceRepositoryRef']
    try:
        sub = json.loads(sub_b, object_pairs_hook=no_dupes)
        depth(sub)
        if not isinstance(sub, dict) or set(sub) - ALLOWED or any(k not in sub for k in ALLOWED):
            raise ValueError('keys')
        if sub['kind'] not in ('official', 'watermark') or not re.match(r'^kaas-prd/[a-z0-9-]{1,63}$', sub['unit']) \
                or sub['unit'] not in reg['units'] or not isinstance(sub['deployment_id'], int):
            raise ValueError('values')
    except Exception as e:
        return 'quarantined:schema', str(e)[:80]
    if sub['repo_id'] != cert['sourceRepositoryIdentifier'] or sub['repo'] != reg['name']:
        return 'quarantined:foreign_assertion', 'claims %s/%s' % (sub['repo_id'], sub['repo'])
    if str(sub['run_id']) != run_m.group(1) or str(sub['run_attempt']) != run_m.group(2) \
            or sub['producer'].get('workflow_sha') != cert['sourceRepositoryDigest']:
        return 'quarantined:sha_mismatch', ''
    # trust rules: replay / ordering
    keys = st['keys']
    k = '%s|%s|%s' % (rid, sub['unit'], sub['deployment_id'])
    dg = canon(sub)
    if k in keys:
        return ('duplicate' if keys[k] == dg else 'quarantined:conflict'), k
    keys[k] = dg
    hw = st['hw'].get(rid + '|' + sub['unit'], -1)
    base = 'snap/%s/prd/%s/%s' % (rid, sub['unit'].split('/')[1], sub['deployment_id'])
    os.makedirs(os.path.join(STORE, base), exist_ok=True)
    for n, b in (('submission.json', sub_b), ('bundle.json', bun_b)):
        open(os.path.join(STORE, base, n), 'wb').write(b)
    save(base + '/provenance.json', cert)
    if sub['deployment_id'] < hw:
        return 'superseded', 'hw %d' % hw
    st['hw'][rid + '|' + sub['unit']] = sub['deployment_id']
    save('current/%s/%s.json' % (rid, sub['unit'].split('/')[1]), {"deployment_id": sub['deployment_id'], "snap": base, "run": cert['runInvocationURI']})
    return 'accepted', k


def main():
    t0 = time.time()
    git('fetch', '-q', 'origin', '+refs/heads/inbox/*:refs/remotes/origin/inbox/*')
    has_store = subprocess.run(['git', 'fetch', '-q', 'origin', '+refs/heads/store:refs/remotes/origin/store'], cwd=ROOT).returncode == 0
    if os.path.exists(STORE): shutil.rmtree(STORE)
    if has_store:
        git('worktree', 'add', '-q', '--detach', STORE, 'refs/remotes/origin/store')
    else:
        git('worktree', 'add', '-q', '--detach', STORE, 'HEAD')
        git('checkout', '-q', '--orphan', 'store', cwd=STORE)
        git('rm', '-rqf', '.', cwd=STORE)
    git('config', 'user.name', 'processor', cwd=STORE); git('config', 'user.email', 'p@invalid', cwd=STORE)
    ledger = {}
    lp = os.path.join(STORE, 'ledger/items.jsonl')
    if os.path.exists(lp):
        for l in open(lp):
            e = json.loads(l); ledger[e['item']] = e
    st = {'keys': load('ledger/keys.json', {}), 'hw': load('ledger/hw.json', {})}
    frontier = load('frontier.json', {})
    refs = [r.split('/', 3)[3] for r in git('for-each-ref', '--format=%(refname)', 'refs/remotes/origin/inbox/').split()]
    budget = CFG['max_items']; new_lines = []; counts = {}
    for short in sorted(refs):
        ref = 'refs/remotes/origin/' + short
        m = REF_RE.match(short)
        if not m:
            ledger_line = {'item': short, 'verdict': 'quarantined:bad_path', 'detail': 'ref name', 'at': now()}
            if short not in ledger: new_lines.append(ledger_line); ledger[short] = ledger_line
            continue
        rid = m.group(1)
        items, order = discover(ref, frontier.get(short))
        done_all = True
        for key, it in items.items():
            iid = short + '/' + key
            for (s, p, c) in it['tamper']:
                tid = '%s#tamper:%s:%s' % (iid, s, c[:8])
                if tid not in ledger:
                    e = {'item': tid, 'verdict': 'inbox_tamper', 'detail': '%s %s' % (s, p), 'at': now()}
                    new_lines.append(e); ledger[tid] = e
            if iid in ledger:
                continue
            if budget <= 0:
                done_all = False; continue
            budget -= 1
            v, dtl = process_item(ref, rid, key, it, st)
            e = {'item': iid, 'verdict': v, 'detail': dtl, 'at': now(), 'commit': it['commit'][:10]}
            new_lines.append(e); ledger[iid] = e
            counts[v] = counts.get(v, 0) + 1
        if done_all and order:
            frontier[short] = order[-1]
    with open(lp, 'a') if os.path.exists(lp) else _mk(lp) as f:
        for e in new_lines: f.write(json.dumps(e, sort_keys=True) + '\n')
    save('ledger/keys.json', st['keys']); save('ledger/hw.json', st['hw']); save('frontier.json', frontier)
    save('state/last_run.json', {'at': now(), 'event': os.environ.get('GITHUB_EVENT_NAME'), 'run_id': os.environ.get('GITHUB_RUN_ID'),
                                 'handled': len(new_lines), 'counts': counts, 'seconds': round(time.time() - t0, 1)})
    git('add', '-A', cwd=STORE)
    git('commit', '-q', '-m', 'store: %d ledger lines %s' % (len(new_lines), json.dumps(counts, sort_keys=True)), cwd=STORE)
    for i in range(5):
        r = subprocess.run(['git', 'push', '-q', 'origin', 'HEAD:refs/heads/store'], cwd=STORE, capture_output=True, text=True)
        if r.returncode == 0:
            break
        print('store push rejected, redo from state', r.stderr[-200:])
        sys.exit(1)     # whole run is redone from state (design rule 6)
    print(json.dumps(counts), 'handled', len(new_lines), 'elapsed', round(time.time() - t0, 1))


def _mk(p):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    return open(p, 'w')


main()
