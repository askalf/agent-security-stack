// Fuzz the composed gate's fail-closed guarantee. guardedCall runs an arbitrary
// tool call through truecopy -> redstamp -> strongroom; the stack's headline
// promise is that it sits in the agent's hot path and (a) NEVER throws into the
// agent on arbitrary input and (b) FAILS CLOSED — it proceeds (ok:true) only when
// redstamp itself would ALLOW the action. A blocked/gray action that reaches
// ok:true would be a fail-OPEN composition bug, which this target hunts for.
//
// The isolated vault + one clean, pinned tool + a reusable lease are built ONCE at
// module load; fuzz() only varies the action, so each exec stays fast (no
// per-iteration grant churn) and the fuzzer covers the orchestration, not setup.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { check } from '@askalf/redstamp';
import { pin } from '@askalf/truecopy';
import { addSecret, grant } from '@askalf/strongroom';
import { guardedCall, AuditLog } from '../audit-trail.mjs';

const HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'oys-fuzz-'));
process.env.KEEPER_HOME = HOME;
const lock = path.join(HOME, 'truecopy.lock');
const policy = { egressAllow: ['api.example.com'] };

const cleanManifest = path.join(HOME, 'clean.json');
fs.writeFileSync(cleanManifest, JSON.stringify({ name: 'fetcher', tools: [{ name: 'http_get', description: 'GET a URL.' }] }));
pin(cleanManifest, { lockPath: lock, name: 'fetcher' });

addSecret('API_KEY', 'sk-live-FUZZ');
// one high-use lease reused across execs — keeps the leases store single-entry
// (O(1) redeem) instead of accumulating a fresh grant every iteration.
const leaseId = grant('API_KEY', { uses: Number.MAX_SAFE_INTEGER, host: 'api.example.com' }).id;

export function fuzz(data) {
  const s = data.toString('utf8');
  // treat the bytes as a JSON action when possible, else as a shell command payload
  let action;
  try { action = JSON.parse(s); } catch { action = { tool: 'shell', input: { command: s } }; }
  if (action === null || typeof action !== 'object' || Array.isArray(action)) {
    action = { tool: 'fetch', input: { url: s } };
  }

  let res;
  try {
    res = guardedCall(
      { manifest: cleanManifest, name: 'fetcher', action, leaseId, host: 'api.example.com', lock, policy },
      new AuditLog(),
    );
  } catch (e) {
    throw new Error(`composed gate THREW on arbitrary action ${JSON.stringify(s).slice(0, 200)}: ${e.stack}`);
  }

  if (!res || typeof res.ok !== 'boolean') {
    throw new Error(`gate returned a malformed result: ${JSON.stringify(res)}`);
  }

  // fail-closed: a proceed is legitimate only if redstamp's own verdict is ALLOW.
  // (deterministic + non-throwing — guardedCall already ran the same check to reach ok:true.)
  if (res.ok) {
    const v = check(action, policy);
    if (v.decision !== 'allow') {
      throw new Error(`gate PROCEEDED (fail-open) on a ${v.decision}/${v.tier} action: ${JSON.stringify(action).slice(0, 200)}`);
    }
  }
}
