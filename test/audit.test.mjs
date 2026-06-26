/**
 * Beat #4 — the composed gate leaves ONE tamper-evident audit trail.
 *
 * stack.test.mjs proves each layer STOPS a bad call. This proves the sequence is
 * also PROVABLE after the fact: every layer's decision is recorded into a single
 * hash-chained log (warden's shipped audit primitive, reused across the gate), the
 * untouched chain verifies, and any edit / deletion / splice of a past verdict
 * breaks verification and pinpoints where.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { runTrilogy, verifyAuditFile, forgeEntry, findEntry, AuditLog } from '../audit-trail.mjs';

test('the gate records every layer decision into one chain, in order', () => {
  const { audit, results } = runTrilogy({ home: path.join(os.tmpdir(), 'oys-audit-order-' + process.pid) });
  // the four beats produced the expected verdicts (same as stack.test.mjs)
  assert.ok(results.proceed.ok, 'beat 0: clean call proceeds');
  assert.equal(results.canon.by, 'canon', 'beat 1: canon stops the poisoned tool');
  assert.equal(results.warden.by, 'warden', 'beat 2: warden stops curl|bash');
  assert.equal(results.keeper.by, 'keeper', 'beat 3: keeper denies the spent lease');
  assert.equal(results.keeper.reason, 'exhausted');

  // every consulted layer left a record, never out of order (canon before warden before keeper)
  const layers = audit.entries.map((e) => e.layer);
  assert.ok(layers.includes('canon') && layers.includes('warden') && layers.includes('keeper') && layers.includes('gate'));
  // the proceed beat must record canon→warden→keeper→gate as a contiguous prefix
  assert.deepEqual(layers.slice(0, 4), ['canon', 'warden', 'keeper', 'gate']);
});

test('the untouched chain verifies, on disk', () => {
  const { audit, trailPath } = runTrilogy({ home: path.join(os.tmpdir(), 'oys-audit-intact-' + process.pid) });
  // in-memory verify
  assert.equal(audit.verify(), true);
  // durable verify (the daemon-grade path)
  audit.flush(trailPath);
  const v = verifyAuditFile(trailPath);
  assert.equal(v.ok, true);
  assert.equal(v.entries, audit.entries.length);
});

test('editing a past verdict breaks verification and pinpoints the entry', () => {
  const { audit, trailPath } = runTrilogy({ home: path.join(os.tmpdir(), 'oys-audit-edit-' + process.pid) });
  audit.flush(trailPath);
  assert.equal(verifyAuditFile(trailPath).ok, true);

  // attacker rewrites canon's block on the poisoned tool to look like a pass
  const at = findEntry(trailPath, (e) => e.layer === 'canon' && e.decision === 'block');
  assert.ok(at >= 0, 'precondition: a canon block was recorded');
  forgeEntry(trailPath, at, { decision: 'pass', verdict: 'clean' });

  const broken = verifyAuditFile(trailPath);
  assert.equal(broken.ok, false, 'a silent edit must break the chain');
  assert.equal(broken.at, at, 'verification must point at the tampered entry');
});

test('deleting an entry (truncating the chain mid-log) is also caught', () => {
  const { audit, trailPath } = runTrilogy({ home: path.join(os.tmpdir(), 'oys-audit-del-' + process.pid) });
  audit.flush(trailPath);
  const lines = fs.readFileSync(trailPath, 'utf8').split('\n').filter((l) => l.trim());
  // drop a middle entry: the NEXT entry's `prev` no longer matches the new predecessor's hash
  const drop = 1;
  fs.writeFileSync(trailPath, lines.filter((_, i) => i !== drop).join('\n') + '\n');
  const v = verifyAuditFile(trailPath);
  assert.equal(v.ok, false, 'removing a link must break the chain');
});

test('a fresh, untampered AuditLog roots at GENESIS and chains forward', () => {
  // smallest possible unit, independent of the trilogy scenario
  const a = new AuditLog();
  const e0 = a.record({ layer: 'canon', decision: 'pass' });
  const e1 = a.record({ layer: 'warden', decision: 'allow' });
  assert.equal(e0.prev, '0'.repeat(64), 'first entry roots at GENESIS');
  assert.equal(e1.prev, e0.hash, 'each entry seals the previous one');
  assert.equal(a.verify(), true);
});
