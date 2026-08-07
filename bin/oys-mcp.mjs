#!/usr/bin/env node
/**
 * Own Your Stack MCP server (stdio). One server, the whole agent-security suite:
 * redstamp_check · truecopy_scan · strongroom_lease (renamed August 2026; the
 * pre-rename codenames warden_check, canon_scan, keeper_lease stay registered
 * as deprecated aliases, so existing configs keep working).
 *
 * Wire into an MCP client (Claude Desktop / Claude Code `.mcp.json`):
 *
 *   { "mcpServers": { "own-your-stack": {
 *       "command": "npx", "args": ["-y", "agent-security-stack", "oys-mcp"],
 *       "env": {
 *         "KEEPER_HOME": "/path/to/strongroom/vault",
 *         "PICKET_CDP": "http://127.0.0.1:9222",
 *         "PICKET_ALLOWLIST": "example.com",
 *         "OYS_WARDEN_POLICY": "{\"egressAllow\":[\"api.example.com\"]}"
 *       } } } }
 *
 * Env: KEEPER_HOME (vault for strongroom_lease), PICKET_CDP/PICKET_ALLOWLIST/
 * PICKET_TASK/PICKET_JUDGE (fieldpass), OYS_WARDEN_POLICY (JSON policy for
 * redstamp_check). stdout is the MCP channel — logging goes to stderr.
 */
import { readFileSync } from 'node:fs';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createOysServer } from '../mcp.mjs';

const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
const allowlist = (process.env.PICKET_ALLOWLIST || '').split(',').map((s) => s.trim()).filter(Boolean);

let wardenPolicy = {};
if (process.env.OYS_WARDEN_POLICY) {
  try { wardenPolicy = JSON.parse(process.env.OYS_WARDEN_POLICY); }
  catch (e) { console.error(`oys-mcp: ignoring invalid OYS_WARDEN_POLICY (${e.message})`); }
}

const { server } = createOysServer({
  version: pkg.version,
  wardenPolicy,
  picketCdp: process.env.PICKET_CDP || null,
  picketAllowlist: allowlist,
  picketTask: process.env.PICKET_TASK || '',
  picketJudge: process.env.PICKET_JUDGE || null,
});

const transport = new StdioServerTransport();
await server.connect(transport);

console.error(
  `Own Your Stack MCP server ready (v${pkg.version}) · tools: ` +
  `redstamp_check, truecopy_scan, strongroom_lease (+ deprecated aliases ` +
  `warden_check, canon_scan, keeper_lease) · ` +
  `strongroom=${process.env.KEEPER_HOME ? 'vault set' : 'no KEEPER_HOME'} · ` +
  `fieldpass cdp=${process.env.PICKET_CDP || 'html-only'}`
);
