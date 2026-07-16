/**
 * Dump the composed server's live tool surface — the exact `tools/list`
 * wire response, via a real MCP client over an in-memory transport — to
 * mcp-manifest.json, where truecopy pins it (see truecopy.lock).
 *
 *   node support/dump-tools.mjs           regenerate mcp-manifest.json
 *   node support/dump-tools.mjs --check   exit 1 if the committed manifest
 *                                         no longer matches the code
 *
 * The chain this enables in CI: code -> manifest (--check) -> lock
 * (truecopy verify). Changing the tool surface — or bumping a dep that
 * changes the generated schemas — fails the gate until the manifest is
 * regenerated and consciously re-pinned.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createOysServer } from '../mcp.mjs';

const MANIFEST = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'mcp-manifest.json');

const { server } = createOysServer();
const [clientT, serverT] = InMemoryTransport.createLinkedPair();
const client = new Client({ name: 'oys-dump-tools', version: '0' });
await Promise.all([server.connect(serverT), client.connect(clientT)]);

const { tools } = await client.listTools();
const manifest = {
  name: 'own-your-stack',
  tools: tools.slice().sort((a, b) => a.name.localeCompare(b.name)),
};
const rendered = JSON.stringify(manifest, null, 2) + '\n';
await client.close();

if (process.argv.includes('--check')) {
  const committed = fs.existsSync(MANIFEST) ? fs.readFileSync(MANIFEST, 'utf8').replace(/\r\n/g, '\n') : '';
  if (committed !== rendered) {
    console.error('mcp-manifest.json is stale: the server\'s tool surface changed.');
    console.error('Regenerate with `node support/dump-tools.mjs`, review the diff, and re-pin (`truecopy add mcp-manifest.json`).');
    process.exit(1);
  }
  console.log('mcp-manifest.json matches the live tool surface');
} else {
  fs.writeFileSync(MANIFEST, rendered);
  console.log(`wrote ${MANIFEST} (${manifest.tools.length} tools)`);
}
