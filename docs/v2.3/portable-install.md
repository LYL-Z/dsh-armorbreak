# V2.3 portable package installation contract

The V2.3 `.tar.gz` archive contains the application sources and its `package.json`; it does not bundle `node_modules`. It is portable in the sense that it can be extracted and run from a user-selected directory, but it is **not a zero-install/self-contained runtime**.

Requirements: Node.js 22 or newer, npm, and network access (or a pre-populated npm cache) for the pinned runtime dependency. After extracting the archive, run `npm install --omit=dev --ignore-scripts --no-audit --no-fund` in the extracted directory. This installs the declared TypeScript `5.9.3` production dependency required by `source.symbols` for both JavaScript and TypeScript. Then invoke the CLI from `packages/cli/index.js`. Do not copy `node_modules` from a development checkout.

The package builder deliberately excludes `node_modules`, tests, and M3 binary fixtures. Its archive member manifest and SHA-256 cover the extracted source package; the installed npm dependency tree is a separate installation result and must be included in any final SBOM/license review. This document describes the actual candidate packaging contract and does not imply a signed or release-ready artifact.
