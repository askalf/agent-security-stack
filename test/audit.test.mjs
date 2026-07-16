/**
 * Beat #4 — the composed gate leaves ONE tamper-evident audit trail.
 *
 * stack.test.mjs proves each layer STOPS a bad call. This proves the sequence is
 * also PROVABLE after the fact: every layer's decision is recorded into a single
 * hash-chained log (redstamp's shipped audit primitive, reused across the gate), the
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
  const { audit, results } = runTrilogy({ home: fs.mkdtempSync(path.join(os.tmpdir(), 'oys-audit-order-')) });
  // the four beats produced the expected verdicts (same as stack.test.mjs)
  assert.ok(results.proceed.ok, 'beat 0: clean call proceeds');
  assert.equal(results.truecopy.by, 'truecopy', 'beat 1: truecopy stops the poisoned tool');
  assert.equal(results.redstamp.by, 'redstamp', 'beat 2: redstamp stops curl|bash');
  assert.equal(results.strongroom.by, 'strongroom', 'beat 3: strongroom denies the spent lease');
  assert.equal(results.strongroom.reason, 'exhausted');

  // every consulted layer left a record, never out of order (truecopy before redstamp before strongroom)
  const layers = audit.entries.map((e) => e.layer);
  assert.ok(layers.includes('truecopy') && layers.includes('redstamp') && layers.includes('strongroom') && layers.includes('gate'));
  // the proceed beat must record truecopy→redstamp→strongroom→gate as a contiguous prefix
  assert.deepEqual(layers.slice(0, 4), ['truecopy', 'redstamp', 'strongroom', 'gate']);
});

test('the untouched chain verifies, on disk', () => {
  const { audit, trailPath } = runTrilogy({ home: fs.mkdtempSync(path.join(os.tmpdir(), 'oys-audit-intact-')) });
  // in-memory verify
  assert.equal(audit.verify(), true);
  // durable verify (the daemon-grade path)
  audit.flush(trailPath);
  const v = verifyAuditFile(trailPath);
  assert.equal(v.ok, true);
  assert.equal(v.entries, audit.entries.length);
});

test('editing a past verdict breaks verification and pinpoints the entry', () => {
  const { audit, trailPath } = runTrilogy({ home: fs.mkdtempSync(path.join(os.tmpdir(), 'oys-audit-edit-')) });
  audit.flush(trailPath);
  assert.equal(verifyAuditFile(trailPath).ok, true);

  // attacker rewrites truecopy's block on the poisoned tool to look like a pass
  const at = findEntry(trailPath, (e) => e.layer === 'truecopy' && e.decision === 'block');
  assert.ok(at >= 0, 'precondition: a truecopy block was recorded');
  forgeEntry(trailPath, at, { decision: 'pass', verdict: 'clean' });

  const broken = verifyAuditFile(trailPath);
  assert.equal(broken.ok, false, 'a silent edit must break the chain');
  assert.equal(broken.at, at, 'verification must point at the tampered entry');
});

test('deleting an entry (truncating the chain mid-log) is also caught', () => {
  const { audit, trailPath } = runTrilogy({ home: fs.mkdtempSync(path.join(os.tmpdir(), 'oys-audit-del-')) });
  audit.flush(trailPath);
  const lines = fs.readFileSync(trailPath, 'utf8').split('\n').filter((l) => l.trim());
  // drop a middle entry: the NEXT entry's `prev` no longer matches the new predecessor's hash
  const drop = 1;
  fs.writeFileSync(trailPath, lines.filter((_, i) => i !== drop).join('\n') + '\n');
  const v = verifyAuditFile(trailPath);
  assert.equal(v.ok, false, 'removing a link must break the chain');
});

test('tail-truncation (dropping the NEWEST verdicts) is caught against the gate\'s checkpoint', () => {
  // A plain hash chain catches an edit or a MIDDLE deletion, but a valid PREFIX
  // still verifies — so lopping off the most-recent entries (an attacker hiding
  // the verdict that just stopped them) slips a bare verify(). redstamp 0.5.1
  // pins the chain head: the gate holds { head, count } in memory as it records
  // (a checkpoint an attacker who only rewrites the on-disk log cannot reach),
  // and verifying against it catches the truncation.
  const { audit, trailPath } = runTrilogy({ home: fs.mkdtempSync(path.join(os.tmpdir(), 'oys-audit-trunc-')) });
  audit.flush(trailPath);
  const checkpoint = { head: audit.entries.at(-1).hash, count: audit.entries.length };

  const lines = fs.readFileSync(trailPath, 'utf8').split('\n').filter((l) => l.trim());
  assert.ok(lines.length >= 3, 'precondition: several entries to truncate');
  fs.writeFileSync(trailPath, lines.slice(0, -2).join('\n') + '\n'); // drop the newest two

  // the chain alone still passes the surviving prefix — this is the gap the checkpoint closes
  assert.equal(verifyAuditFile(trailPath).ok, true, 'a truncated prefix passes the bare chain');
  // against the trusted checkpoint, the truncation is caught and named
  const caught = verifyAuditFile(trailPath, checkpoint);
  assert.equal(caught.ok, false, 'tail-truncation must be caught against the checkpoint');
  assert.equal(caught.reason, 'truncated');
});

test('a fresh, untampered AuditLog roots at GENESIS and chains forward', () => {
  // smallest possible unit, independent of the trilogy scenario
  const a = new AuditLog();
  const e0 = a.record({ layer: 'truecopy', decision: 'pass' });
  const e1 = a.record({ layer: 'redstamp', decision: 'allow' });
  assert.equal(e0.prev, '0'.repeat(64), 'first entry roots at GENESIS');
  assert.equal(e1.prev, e0.hash, 'each entry seals the previous one');
  assert.equal(a.verify(), true);
});
