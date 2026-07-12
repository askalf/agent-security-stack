# Contributing to agent-security-stack

Thanks for your interest in improving **agent-security-stack** — the
open-source agent-security stack (redstamp + truecopy + strongroom) composed
into one layered defense and exposed as a single MCP server: vet the tool,
contain the call, give it a key it never holds. Part of
[Own Your Stack](https://sprayberrylabs.com).

## Ground rules

- Be respectful. This project follows our [Code of Conduct](CODE_OF_CONDUCT.md).
- Found a security issue? **Do not open a public issue** — report it privately
  by email to **support@askalf.org**.

## Development setup

agent-security-stack is a Node.js package that composes the stack's component
packages into one MCP server. You need Node.js **20 or later**; CI runs on
Node **22**.

```bash
git clone https://github.com/askalf/agent-security-stack.git
cd agent-security-stack
npm install   # component packages are git-hosted, so this uses `npm install`, not `npm ci`
npm test      # run the test suite (node --test)
```

## Making a change

1. Branch off `master`.
2. Keep the change focused — one concern per PR.
3. Add or update tests for any behavior change. Because this repo wires the
   security components together, changes to the composed MCP server or the
   audit trail must be covered by tests.
4. Run `npm test` locally before pushing.
5. Open a pull request against `master`.

## What CI requires

Every PR must pass this check to merge:

- `test` (ubuntu-latest, Node **22**)

OpenSSF Scorecard also runs on the repo; a new high-severity finding will block
the change.

## Conventions

- GitHub Actions are **pinned to a commit SHA**, never a mutable tag. New or
  updated workflow steps must keep this.
- Commit messages: short imperative subject, with a wrapped body explaining the
  *why* when it isn't obvious.
- PRs are squash-merged, so your PR title becomes the commit subject on `master`.
