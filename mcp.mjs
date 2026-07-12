/**
 * Own Your Stack — one MCP server, the agent-security trilogy as callable
 * tools. An MCP client (Claude Desktop, Claude Code, any agent runtime) gets:
 *
 *   warden_check   — contain it:   is this tool action safe to run? (firewall)
 *   canon_scan     — vet it:        scan an MCP/skill manifest for poisoning
 *   keeper_lease   — key it:        lease a credential — opaque handle, no secret
 *
 * redstamp and truecopy ALSO ship transparent stdio proxies (`redstamp-mcp`,
 * `truecopy-mcp`) that enforce mandatorily in front of a downstream server — the
 * deployment-grade mode. These callable tools are the on-demand surface: an
 * agent can ask the stack to vet content/actions/secrets mid-task.
 *
 * Each tool wraps the real library (no reimplementation): @askalf/redstamp,
 * @askalf/truecopy, @askalf/strongroom.
 */

import { z } from 'zod';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { guardMcpCall } from '@askalf/redstamp/mcp';
import { scan as truecopyScan } from '@askalf/truecopy';
import { grant as strongroomGrant } from '@askalf/strongroom';

const err = (text) => ({ isError: true, content: [{ type: 'text', text }] });
const json = (obj) => ({ content: [{ type: 'text', text: JSON.stringify(obj, null, 2) }] });

/**
 * @param {Object} [opts]
 * @param {string}   [opts.version]
 * @param {Object}   [opts.wardenPolicy]   redstamp policy (egressAllow/writeRoots/allow/deny)
 */
export function createOysServer(opts = {}) {
  const wardenPolicy = opts.wardenPolicy || {};

  const server = new McpServer({ name: 'own-your-stack', version: opts.version || '0.1.0' });

  // ── redstamp: contain it ──────────────────────────────────────────────────
  server.registerTool('warden_check', {
    title: 'Is this action safe to run? (action firewall)',
    description:
      'Submit a tool action — { tool, input } — and get redstamp\'s verdict: decision (allow / approve / block), risk tier, and the reasons. Catches shell/exec, SSRF + cloud-metadata, secret exfiltration, dangerous writes/deletes, and prompt-injection in the arguments. Call this BEFORE executing any consequential tool call.',
    inputSchema: {
      tool: z.string().describe('the tool/action name, e.g. fetch, shell, write, delete, read'),
      input: z.record(z.any()).optional().describe('the arguments the tool would run with (url, command, path, content, …)'),
    },
    annotations: { readOnlyHint: true },
  }, async ({ tool, input }) => {
    // Route through redstamp's MCP-call firewall (guardMcpCall), not a bare check, so a
    // shell payload buried under ANY argument key — not just command/cmd — is caught
    // via the all-keys leaf scan, matching the in-path redstamp-mcp proxy's defense.
    const { verdict: v } = guardMcpCall({ name: tool, arguments: input || {} }, wardenPolicy);
    return json({ decision: v.decision, tier: v.tier, gray: !!v.gray, why: v.why });
  });

  // ── truecopy: vet it ──────────────────────────────────────────────────────
  server.registerTool('canon_scan', {
    title: 'Scan an MCP/skill manifest for supply-chain poisoning',
    description:
      'Paste an MCP server or skill manifest (JSON) and truecopy scans its tool names/descriptions for hidden instructions, exfiltration lures, and other poisoned-skill / tool-poisoning attacks. Returns a verdict (clean / flagged) and the findings. Vet a third-party tool BEFORE you trust it.',
    inputSchema: {
      manifest: z.string().describe('the MCP/skill manifest as JSON text'),
    },
    annotations: { readOnlyHint: true },
  }, async ({ manifest }) => {
    let parsed;
    try { parsed = JSON.parse(manifest); } catch (e) { return err(`manifest is not valid JSON: ${e.message}`); }
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'oys-truecopy-'));
    const tmp = path.join(dir, 'manifest.json');
    try {
      fs.writeFileSync(tmp, JSON.stringify(parsed));
      const r = truecopyScan(tmp);
      return json({ verdict: r.verdict, findings: r.findings ?? r.flags ?? [], skill: r.skill?.name ?? null });
    } catch (e) {
      return err(`truecopy scan failed: ${e.message}`);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  // ── strongroom: key it (never hands over the secret) ──────────────────────
  server.registerTool('keeper_lease', {
    title: 'Lease a credential — you get an opaque handle, never the secret',
    description:
      'Request a short-lived, scoped lease for a credential held in the strongroom vault. You receive a lease handle (id + scope + ttl); the secret itself is materialized only at the egress point when the lease is redeemed, and never enters your context. The named secret must already be in the vault.',
    inputSchema: {
      name: z.string().describe('the vault secret name to lease'),
      host: z.string().optional().describe('restrict the lease to this destination host'),
      ttlS: z.number().int().positive().optional().describe('lease lifetime in seconds (default 300)'),
      uses: z.number().int().positive().optional().describe('max redemptions (default 1)'),
    },
  }, async ({ name, host, ttlS, uses }) => {
    try {
      const lease = strongroomGrant(name, { host, ttlS, uses });
      // defensive: never surface secret material even if a future lease shape carried it
      const { value, secret, ...handle } = lease || {};
      return json({ lease: handle, note: 'opaque handle — no secret material; redeem happens at egress, not here' });
    } catch (e) {
      return err(`strongroom could not lease "${name}": ${e.message}`);
    }
  });

  return { server };
}
