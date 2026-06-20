/**
 * Own Your Stack — one MCP server, the whole agent-security suite as callable
 * tools. An MCP client (Claude Desktop, Claude Code, any agent runtime) gets:
 *
 *   warden_check   — contain it:   is this tool action safe to run? (firewall)
 *   canon_scan     — vet it:        scan an MCP/skill manifest for poisoning
 *   keeper_lease   — key it:        lease a credential — opaque handle, no secret
 *   cordon_redact  — sanitize it:   strip PII/secrets out of text before an LLM sees it
 *   picket_observe — read safely:   firewall an untrusted web page (injection withheld)
 *
 * warden and canon ALSO ship transparent stdio proxies (`warden-mcp`,
 * `canon-mcp`) that enforce mandatorily in front of a downstream server — the
 * deployment-grade mode. These callable tools are the on-demand surface: an
 * agent can ask the stack to vet content/actions/secrets mid-task.
 *
 * Each tool wraps the real library (no reimplementation): @askalf/warden,
 * @askalf/canon, @askalf/keeper, @askalf/picket, and cordon's detector. cordon
 * is TypeScript, loaded lazily via tsx's programmatic loader so this stays a
 * plain-Node, npx-able server.
 */

import { z } from 'zod';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { guardMcpCall } from '@askalf/warden/mcp';
import { scan as canonScan } from '@askalf/canon';
import { grant as keeperGrant } from '@askalf/keeper';
import { GovernedBrowser } from '@askalf/picket';

const err = (text) => ({ isError: true, content: [{ type: 'text', text }] });
const json = (obj) => ({ content: [{ type: 'text', text: JSON.stringify(obj, null, 2) }] });

/** cordon is TS-only; load its detector once, lazily, through tsx's loader so
 *  the rest of the server needs no build step and stays npx-able. */
let _runAll;
async function cordonRunAll() {
  if (!_runAll) {
    const { register } = await import('tsx/esm/api');
    register();
    ({ runAll: _runAll } = await import('cordon/src/detect/index.ts'));
  }
  return _runAll;
}

/** Replace cordon's detected PII/secret spans with stable, typed placeholders.
 *  Detection is cordon's; the placeholder substitution is a thin, reversible-by-
 *  position wrapper (the gateway's Vault does the same with its own tokens). */
function redactWithSpans(text, spans) {
  const ordered = [...spans].sort((a, b) => a.start - b.start);
  const ph = new Map(); // value → placeholder (dedup: same value, same token)
  const counters = {};
  const tally = {};
  for (const s of ordered) {
    if (!ph.has(s.value)) { counters[s.type] = (counters[s.type] || 0) + 1; ph.set(s.value, `[${s.type}_${counters[s.type]}]`); }
    tally[s.type] = (tally[s.type] || 0) + 1;
  }
  let out = text;
  for (const s of [...ordered].reverse()) out = out.slice(0, s.start) + ph.get(s.value) + out.slice(s.end);
  return { redacted: out, tally, count: spans.length };
}

async function bridgeEndpoint(base) {
  const res = await fetch(`${base}/json/version`);
  const v = await res.json();
  const u = new URL(v.webSocketDebuggerUrl);
  u.host = new URL(base).host;
  return u.toString();
}

/**
 * @param {Object} [opts]
 * @param {string}   [opts.version]
 * @param {Object}   [opts.wardenPolicy]   warden policy (egressAllow/writeRoots/allow/deny)
 * @param {string}   [opts.picketCdp]      CDP base for live URL reads (also PICKET_CDP)
 * @param {string[]} [opts.picketAllowlist]
 * @param {string}   [opts.picketTask]
 * @param {*}        [opts.picketJudge]    "dario" | "claude" | LLMJudge | null
 */
export function createOysServer(opts = {}) {
  const wardenPolicy = opts.wardenPolicy || {};
  const picketCdp = opts.picketCdp ?? process.env.PICKET_CDP ?? null;
  const picket = new GovernedBrowser({
    allowlist: opts.picketAllowlist,
    task: opts.picketTask,
    judge: opts.picketJudge,
  });

  const server = new McpServer({ name: 'own-your-stack', version: opts.version || '0.1.0' });

  // ── warden: contain it ────────────────────────────────────────────────────
  server.registerTool('warden_check', {
    title: 'Is this action safe to run? (action firewall)',
    description:
      'Submit a tool action — { tool, input } — and get warden\'s verdict: decision (allow / approve / block), risk tier, and the reasons. Catches shell/exec, SSRF + cloud-metadata, secret exfiltration, dangerous writes/deletes, and prompt-injection in the arguments. Call this BEFORE executing any consequential tool call.',
    inputSchema: {
      tool: z.string().describe('the tool/action name, e.g. fetch, shell, write, delete, read'),
      input: z.record(z.any()).optional().describe('the arguments the tool would run with (url, command, path, content, …)'),
    },
    annotations: { readOnlyHint: true },
  }, async ({ tool, input }) => {
    // Route through warden's MCP-call firewall (guardMcpCall), not a bare check, so a
    // shell payload buried under ANY argument key — not just command/cmd — is caught
    // via the all-keys leaf scan, matching the in-path warden-mcp proxy's defense.
    const { verdict: v } = guardMcpCall({ name: tool, arguments: input || {} }, wardenPolicy);
    return json({ decision: v.decision, tier: v.tier, gray: !!v.gray, why: v.why });
  });

  // ── canon: vet it ─────────────────────────────────────────────────────────
  server.registerTool('canon_scan', {
    title: 'Scan an MCP/skill manifest for supply-chain poisoning',
    description:
      'Paste an MCP server or skill manifest (JSON) and canon scans its tool names/descriptions for hidden instructions, exfiltration lures, and other poisoned-skill / tool-poisoning attacks. Returns a verdict (clean / flagged) and the findings. Vet a third-party tool BEFORE you trust it.',
    inputSchema: {
      manifest: z.string().describe('the MCP/skill manifest as JSON text'),
    },
    annotations: { readOnlyHint: true },
  }, async ({ manifest }) => {
    let parsed;
    try { parsed = JSON.parse(manifest); } catch (e) { return err(`manifest is not valid JSON: ${e.message}`); }
    const tmp = path.join(os.tmpdir(), `oys-canon-${process.pid}-${Math.abs(hashStr(manifest))}.json`);
    try {
      fs.writeFileSync(tmp, JSON.stringify(parsed));
      const r = canonScan(tmp);
      return json({ verdict: r.verdict, findings: r.findings ?? r.flags ?? [], skill: r.skill?.name ?? null });
    } catch (e) {
      return err(`canon scan failed: ${e.message}`);
    } finally {
      try { fs.unlinkSync(tmp); } catch { /* noop */ }
    }
  });

  // ── keeper: key it (never hands over the secret) ──────────────────────────
  server.registerTool('keeper_lease', {
    title: 'Lease a credential — you get an opaque handle, never the secret',
    description:
      'Request a short-lived, scoped lease for a credential held in the keeper vault. You receive a lease handle (id + scope + ttl); the secret itself is materialized only at the egress point when the lease is redeemed, and never enters your context. The named secret must already be in the vault.',
    inputSchema: {
      name: z.string().describe('the vault secret name to lease'),
      host: z.string().optional().describe('restrict the lease to this destination host'),
      ttlS: z.number().int().positive().optional().describe('lease lifetime in seconds (default 300)'),
      uses: z.number().int().positive().optional().describe('max redemptions (default 1)'),
    },
  }, async ({ name, host, ttlS, uses }) => {
    try {
      const lease = keeperGrant(name, { host, ttlS, uses });
      // defensive: never surface secret material even if a future lease shape carried it
      const { value, secret, ...handle } = lease || {};
      return json({ lease: handle, note: 'opaque handle — no secret material; redeem happens at egress, not here' });
    } catch (e) {
      return err(`keeper could not lease "${name}": ${e.message}`);
    }
  });

  // ── cordon: sanitize it ───────────────────────────────────────────────────
  server.registerTool('cordon_redact', {
    title: 'Redact PII / secrets out of text',
    description:
      'Run text through cordon\'s deterministic detector and replace emails, phone numbers, SSNs, cards, IBANs, API keys and other secrets with typed placeholders. Sanitize untrusted or sensitive text BEFORE you put it in a prompt, a log, or an outbound message.',
    inputSchema: {
      text: z.string().describe('the text to sanitize'),
      sets: z.array(z.enum(['pii', 'phi', 'pci', 'secrets'])).optional().describe('which entity sets to redact (default: pii, pci, secrets)'),
    },
    annotations: { readOnlyHint: true },
  }, async ({ text, sets }) => {
    try {
      const runAll = await cordonRunAll();
      const spans = runAll(text, sets && sets.length ? sets : ['pii', 'pci', 'secrets']);
      return json(redactWithSpans(text, spans));
    } catch (e) {
      return err(`cordon redaction unavailable: ${e.message}`);
    }
  });

  // ── picket: read the web safely ───────────────────────────────────────────
  server.registerTool('picket_observe', {
    title: 'Read a web page through the injection firewall',
    description:
      'Read an UNTRUSTED web page safely. Returns the instruction-stripped view you may act on — prompt-injection payloads (hidden text, lethal-trifecta lures, role spoofs) are withheld. Pass `url` to fetch live (needs PICKET_CDP) or `html` to analyze inline. The raw text of a blocked node is never returned.',
    inputSchema: {
      url: z.string().url().optional().describe('URL to read through the governed browser (needs a CDP endpoint)'),
      html: z.string().optional().describe('inline HTML to analyze instead of fetching'),
      task: z.string().optional().describe('the trusted task you are doing — fenced into the safe view'),
    },
    annotations: { readOnlyHint: true, openWorldHint: true },
  }, async ({ url, html, task }) => {
    if (!url && html == null) return err('picket_observe needs either `url` or `html`.');
    const input = { url, html };
    if (picketCdp) {
      try { input.browserWSEndpoint = await bridgeEndpoint(picketCdp); }
      catch (e) { if (url) return err(`CDP browser unreachable at ${picketCdp}: ${e.message}`); }
    } else if (url) {
      return err('Reading a live URL needs a CDP browser (set PICKET_CDP). Pass `html` to analyze inline.');
    }
    const prevTask = picket.task;
    if (task != null) picket.task = task;
    try {
      const r = await picket.observe(input);
      const d = r.detection;
      const findings = d.findings.map((f) => ({ action: f.action, severity: f.severity, categories: f.categories, hidden: !!f.hidden }));
      const banner =
        `picket verdict: ${d.verdict.toUpperCase()} · decision: ${r.decision.action} · ` +
        `${r.safe.redactions.length} item(s) withheld · captured: ${r.observation.capturedBy}` +
        (d.trifecta ? ' · LETHAL TRIFECTA' : '');
      return { content: [{ type: 'text', text: banner }, { type: 'text', text: r.safe.text }, { type: 'text', text: `findings: ${JSON.stringify(findings)}` }] };
    } catch (e) {
      return err(`observe failed: ${e.message}`);
    } finally {
      picket.task = prevTask;
    }
  });

  return { server, picket };
}

/** Tiny stable string hash for temp filenames (not security-sensitive). */
function hashStr(s) {
  let h = 0;
  for (let i = 0; i < s.length; i++) { h = (h << 5) - h + s.charCodeAt(i); h |= 0; }
  return h;
}
