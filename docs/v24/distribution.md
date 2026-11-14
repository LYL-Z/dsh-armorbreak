# v2.4 candidate distribution and installation contract

The supported v2.4 Node distribution path is an actual npm TGZ installed through npm in a new application directory. The root plugin, tools/skills, Core, engine, CLI, MCP and read-only Workbench ship together. This is a development candidate contract, not permission to publish, merge or replace a historical release. Existing package version metadata remains 2.3.1 for compatibility in this development stack; the full Git commit and TGZ SHA-256 identify a candidate. No v2.3.1 Tag, Release or original asset is rebuilt or changed.

From a committed checkout with Node >=22 and npm installed:

```
npm ci --ignore-scripts --no-audit --no-fund
node scripts/v24/verify-npm-distribution.mjs --out <new-absolute-evidence-directory>
```

This freezes Git HEAD, runs actual `npm pack --ignore-scripts`, installs the TGZ in a new consumer, imports every declared module export in its supported context and exercises installed CLI, Core, MCP, configuration and Workbench. Acceptance installs from the public npm registry with exact versions/integrity; network access is recorded explicitly. Optional `--offline` requires a matching cache of both package metadata and tarballs; `npm ci` alone need not warm metadata, so it is not an offline guarantee. The result records platform, Node, source SHA, TGZ SHA, member inventory, command exit codes and actual runtime checks. It refuses an existing output directory. It does not run installation scripts or publish anything.

An end user installs an approved TGZ (after separately checking its SHA-256) using:

```
npm install --ignore-scripts --omit=dev --no-audit --no-fund /absolute/path/to/approved-candidate.tgz
```

The package includes `npm-shrinkwrap.json`, with exact runtime versions and integrity metadata for `typescript@5.9.3` and `yaml@2.9.1`. Those dependencies are installed separately by npm; the TGZ is not an offline dependency bundle. `package-lock.json` alone is not the distributable dependency lock. Public registry access or a pre-populated matching npm cache is necessary. npm behavior reference: [npm-shrinkwrap.json](https://docs.npmjs.com/cli/v11/configuring-npm/npm-shrinkwrap-json/) and [package files](https://docs.npmjs.com/cli/v11/configuring-npm/package-json/#files).

## Supported entrypoints

- `dsh-armorbreak`, `/tools`, `/skills`: Node plugin modules. Actual DSH registration and host compatibility remain independently unverified.
- `/client`: the browser-side DSH module loader script; importing in a plain Node process without that browser API is unsupported. Packaging acceptance imports it with a simulated loader to verify registration, not actual DSH embedding.
- `/core`, `/engine-node`, `/cli`, `/mcp`, `/workbench`: Node API imports.
- `/configuration-lab`, `/plugin-lifecycle`, `/plugin-lab`: dedicated trusted-host composition APIs. Their availability does not authenticate a caller or permit real host writes.
- `/package.json`, `/locale/*.json`, `/icon`: metadata/assets; JSON is loaded as JSON, SVG read as an asset rather than executed as JavaScript.
- npm bin `armorbreak`: the native CLI; `armorbreak-mcp`: stdio MCP; `armorbreak-workbench`: loopback Workbench. Configure `ARMORBREAK_STATE_ROOT`, `ARMORBREAK_WORKSPACE` and the principal before CLI/MCP use. Workbench native mode requires `--workspace <absolute> --state-root <absolute>`; choose its port explicitly when needed.

Configuration `config stage/status` can run in the standalone CLI; `config apply/revert` require a trusted host-injected one-use approval provider and act only on fresh sealed synthetic labs. No terminal flag, MCP request or local panel issues approval. Package acceptance checks actual installed YAML conversion and approved synthetic apply/restore, preserving original bytes. It never writes to a real DSH installation.

Workbench remains `authentication=NONE`, `tokenPurpose=CSRF_ONLY`; production secrets, L2 host writes and approval signing remain unavailable. Optional adapters requiring another host's SDK are not evidence of that host's runtime support.

## Runtime contents and legacy builders

The npm `files` allowlist contains the runtime directories and selected public metadata/documentation. Historical acceptance records, tests, binary fixtures, Git metadata, `.armorbreak` state, release scripts, private keys and development `node_modules` are not distributed. Acceptance audits the actual packed/installed members and key material, rather than a dry-run count alone.

The existing `scripts/v2/build-portable-artifact.mjs` and `build-release.mjs` retain their historical development/release-test contracts. Their successful tests do not establish complete v2.4 npm distribution. They are not the v2.4 runtime TGZ admission path, and no legacy archive is promoted by this change. Formal v2.4 publication, production signing, redistribution rights and release readiness still require their separate, presently blocked gates. The npm candidate and this validation are not release assets.
