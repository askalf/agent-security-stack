// Fuzz the egress-host binding. egressHost() derives, from arbitrary tool-call
// input (action.input.url), the single destination a strongroom secret may be
// redeemed toward — so a throw here would crash the composed gate on a malformed
// URL, and a non-string return would corrupt the host comparison that keeps a
// secret from egressing to an unintended host. Invariant: on arbitrary bytes it
// never throws and always returns a string hostname or null.
import { egressHost } from '../audit-trail.mjs';

export function fuzz(data) {
  const s = data.toString('utf8');
  // exercise every shape the field can take: well-formed action, url-only, junk
  for (const action of [
    { tool: 'fetch', input: { url: s } },
    { input: { url: s } },
    { tool: s },
    { tool: 'fetch', input: { url: s, method: s } },
  ]) {
    const h = egressHost(action);
    if (h !== null && typeof h !== 'string') {
      throw new Error(`egressHost returned non-string/non-null for ${JSON.stringify(s)}: ${JSON.stringify(h)}`);
    }
  }
}
