# Security Policy

agent-security-stack composes redstamp, truecopy, and strongroom into one
layered defense exposed as a single MCP server. A vulnerability *here* means a
composition or configuration flaw that weakens the layers — e.g. the combined
MCP server dropping a verdict, mis-wiring a tool's gate, or leaking between
layers.

## Reporting a vulnerability

Please **do not open a public issue** for security reports.

- **Preferred:** [GitHub private vulnerability reporting](https://github.com/askalf/agent-security-stack/security/advisories/new) — creates a private advisory visible only to maintainers.
- **Email:** support@askalf.org with `agent-security-stack security` in the subject.

You'll get an acknowledgement within 72 hours. Please include a minimal
reproduction where possible.

## Scope

- **This repo:** the composition — the combined MCP server, suite wiring, audit
  trail plumbing, demo/config defaults that would weaken the stack.
- **The individual tools:** report vulnerabilities in the layers themselves to
  their own repos — [redstamp](https://github.com/askalf/redstamp/security/policy)
  (runtime firewall), [truecopy](https://github.com/askalf/truecopy/security/policy)
  (supply-chain gate), [strongroom](https://github.com/askalf/strongroom/security/policy)
  (secrets). Each has its own threat model.

## Supported versions

Pre-1.0: only the latest release receives security fixes; there are no
maintenance branches.
