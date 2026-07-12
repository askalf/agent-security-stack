// `npm run fuzz` — run every Jazzer.js target in ./fuzz for a short burst.
// Continuous fuzzing runs in CI via ClusterFuzzLite (.github/workflows/
// cflite.yml); this is the fast local repro loop. Override the per-target budget
// with FUZZ_SECONDS (default 30).
//
// Jazzer is a fuzz-only dependency (hash-pinned under .clusterfuzzlite/ for CI);
// locally it is fetched on demand with `npx`, so nothing is added to the project
// manifest.
import { spawnSync } from 'node:child_process';
import { readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const dir = path.dirname(fileURLToPath(import.meta.url));
const targets = readdirSync(dir).filter((f) => f.endsWith('.fuzz.js')).sort();
const secs = process.env.FUZZ_SECONDS || '30';
const npx = process.platform === 'win32' ? 'npx.cmd' : 'npx';

for (const t of targets) {
  const target = `fuzz/${t.replace(/\.js$/, '')}`;
  console.log(`\n=== fuzzing ${t} (${secs}s) ===`);
  const r = spawnSync(
    npx,
    ['--yes', '--package', '@jazzer.js/core@^4', 'jazzer', target, '--sync', '--', `-max_total_time=${secs}`],
    { stdio: 'inherit' },
  );
  if (r.status !== 0) process.exit(r.status || 1);
}
