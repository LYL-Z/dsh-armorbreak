# v2.4 candidate distribution and installation contract

## Windows experience ZIP

The Windows package-validation job assembles `ArmorBreak-Windows-Preview.zip` from an actually installed frozen TGZ. It includes the application, locked TypeScript/YAML runtime dependencies, launcher, file hashes, source build record and license texts. It excludes acceptance state and requires an existing Node.js 22+ installation; Node itself and a graphical installer are not included.

After verifying the download's SHA-256, extract the **entire** ZIP into a new user-writable folder and open `Start ArmorBreak.cmd`. No npm command, administrator elevation, model key or DSH installation is required. Keep the console open while using the local browser. Run the safe example, then place **copies** of files/projects in `workspace` and choose a relative target. Reports are downloadable from the task list. Stop with Ctrl+C. Preserve `workspace` and `state` when replacing an application folder; no automatic upgrade or data-deleting uninstaller is provided.

Acceptance extracts the real ZIP to a new path containing spaces, Unicode and `&`, runs the actual CMD launcher, executes a Core task over HTTP and reads evidence/report results. It also rejects changed launchers and ZIP traversal members. This is not a fresh Explorer double-click or browser usability study, OS authentication, real DSH compatibility, self-contained Node distribution or Stable release approval. Hosted CI artifacts expire after seven days and are development downloads, not GitHub Release assets.

## First local result

With Node 22+ and npm, install a verified candidate TGZ, then run `armorbreak start --workspace "/absolute/project/path"`. On Windows, quote paths such as `"D:\My Project"`. The default browser opens the loopback Workbench. No environment variables or model credentials are needed for its file/code/dependency checks. Run **运行安全示例** for real Core evidence and a downloadable report without reading project files. Current project tasks are separate from historical host acceptance. A missing target can be corrected and retried.

`--no-open` prints the URL; `--port 0` chooses an available port; `--state-root <absolute-directory>` selects Core state. Ctrl+C stops the server. DSH/model connection is not inferred from a running Workbench. The panel is still CSRF-only, with no OS authentication, L2 writes, production keys or approval issuance. A graphical installer, real DSH onboarding and independent novice-user timing are not yet verified.

## Multi-tool checks and a combined report

The function center also provides **项目综合审查** (code, secret indicators, dependencies and SBOM), **分析离线抓包** (seven PCAP/PCAPNG checks) and **文件综合取证** (six file checks). These run existing registered Core workflows and produce one task, per-step states, evidence and a combined downloadable report. The browser does not supply custom plans, tool options or approvals. All selected steps must currently be registered L0; input remains confined to the selected workspace. No live packet capture, target scanning, program execution or model credential is used. Indicators and heuristics do not establish a verified vulnerability.

For a configured CLI workspace, run `armorbreak workflow start --workflow PCAPInvestigation --target /absolute/workspace/capture.pcap --json`. The MCP `armorbreak_workflow` start action uses the same Engine entry. A malformed input records an actual failed step and transitively skips blocked descendants, then finalizes the failed report. Independent DAG branches continue according to the existing Core policy; a failed step does not fabricate success.

## Configuration presentation

Trusted configuration staging uses the existing strict data importer, then reconciles the private YAML document tree. Supported YAML/Cordis/Purge-preset changes preserve existing comments, map order, compatible scalar quoting, and uniform CRLF. An unchanged document returns its original bytes. Changed arbitrary whitespace is not guaranteed; comments on deleted nodes can be removed. Cordis component comments follow stable IDs during reorder; generic arrays use positional annotations. Tags, anchors, aliases, merge keys, duplicate keys and unsafe values remain rejected. The exact serialized candidate is reparsed and compared to intended data before approval. Source bytes and keys remain private; no value digest or comment is added to public previews.

This uses the locked YAML document API ([upstream documentation](https://eemeli.org/yaml/#documents)), not a second configuration engine. The transaction still writes only a fresh synthetic lab and restores the original raw bytes through a separately approved rollback. It does not modify real DSH configuration or establish complete host schema compatibility.

The supported v2.4 Node distribution path is an actual npm TGZ installed through npm in a new application directory. The root plugin, tools/skills, Core, engine, CLI, MCP and read-only Workbench ship together. The package now declares **2.4.0-preview.1**, separately from the frozen v2.3.1 release. The full Git commit and TGZ SHA-256 identify a candidate. No v2.3.1 Tag, Release or original asset is rebuilt or changed. Successful development validation does not approve Stable publication.

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

## Restoring quarantine selection after disable

The trusted-host `/isolated-plugin-store` API accepts `planIsolatedPluginInstall(runtime, {operation:'enable', current:disabledStore, reviewer, operator, sessionId})`. It creates a **new isolated transaction** using the sealed historical closure; caller-supplied replacement packages or receipts are rejected. The returned `store.apply(trustedApprovalProvider)` needs a fresh one-use approval and rechecks current source/rights trust after delayed approval. Revoked keys/authorities cannot regain selection. `store.rollback(trustedApprovalProvider)` separately restores DISABLED with the original bytes.

Here, enable means restoring **quarantine file selection only**. `activationAuthorized=false`, `hostWrites=false` and `productionInstallation=false` remain enforced. No JavaScript is imported or executed, no DSH is modified, and older transaction roots are independent snapshots. The local HTTP panel and MCP cannot invoke this trusted-host approval API. Tests cover planning/approval, reopen, rejection, revocation races and byte-exact return to disabled.

Workbench remains `authentication=NONE`, `tokenPurpose=CSRF_ONLY`; production secrets, L2 host writes and approval signing remain unavailable. Optional adapters requiring another host's SDK are not evidence of that host's runtime support.

## Runtime contents and legacy builders

The npm `files` allowlist contains the runtime directories and selected public metadata/documentation. Historical acceptance records, tests, binary fixtures, Git metadata, `.armorbreak` state, release scripts, private keys and development `node_modules` are not distributed. Acceptance audits the actual packed/installed members and key material, rather than a dry-run count alone.

The existing `scripts/v2/build-portable-artifact.mjs` and `build-release.mjs` retain their historical development/release-test contracts. Their successful tests do not establish complete v2.4 npm distribution. They are not the v2.4 runtime TGZ admission path, and no legacy archive is promoted by this change. Formal v2.4 publication, production signing, redistribution rights and release readiness still require their separate, presently blocked gates. The npm candidate and this validation are not release assets.
