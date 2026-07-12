#!/bin/bash -eu
# Build the Jazzer.js fuzz targets for ClusterFuzzLite / OSS-Fuzz.
#
# Unlike the individual tools (redstamp/truecopy/strongroom are zero-dependency),
# this repo is the COMPOSITION layer: the fuzz targets import the composed gate,
# which pulls the three @askalf/* packages (git-hosted, pinned) plus the MCP SDK.
# So the fuzz build installs the project's own runtime deps first, then merges the
# fuzz-only Jazzer.js on top — Jazzer is never added to the project manifest.
#
# The invariants under test (see fuzz/*.fuzz.js): the composed gate sits in the
# agent's hot path and must NEVER throw into the agent on arbitrary input, and
# must FAIL CLOSED — it proceeds only when redstamp itself would allow the action.
cd "$SRC/agent-security-stack"

# 1. project runtime deps — npm ci verifies every integrity hash in the committed
#    root lockfile (the @askalf/* deps are git-pinned there; the MCP SDK is on npm).
npm ci --no-audit --no-fund

# 2. fuzz-only Jazzer.js, hash-pinned by .clusterfuzzlite/package-lock.json, merged
#    into the project's node_modules without touching the project's package.json.
(cd .clusterfuzzlite && npm ci --no-audit --no-fund)
cp -a .clusterfuzzlite/node_modules/. node_modules/

# compile_javascript_fuzzer executes node_modules/@jazzer.js/core/dist/cli.js
# relative to the project root, so the merge above puts it where it expects.
for target in composed_gate egress_host; do
  compile_javascript_fuzzer agent-security-stack "fuzz/${target}.fuzz.js" --sync
done
