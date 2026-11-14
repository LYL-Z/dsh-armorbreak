# Configuration format lifecycle (Draft)

`configuration.convert` and `node packages/cli/index.js config convert --bundle <file> --json`
accept a bounded import envelope inside the configured workspace:

```json
{"schema":"armorbreak.configuration-import/v1","format":"yaml","source":"enabled: false\nunknown: null\n"}
```

Formats: JSON object; YAML 1.2 object; Cordis composition array (unique string IDs,
plugin names or nested groups, boolean disabled); Purge two-file preset. The last
uses `source: {"preset":"name: inert\n", "agent":"- id: inert\n  name: example/inert\n"}`.
The files remain data: no host install, imports, templates, plugin evaluation or authority.
No upstream prompts, patches or executable functions are copied.

Private in-memory API `importConfiguration` returns a typed document and a public
preview. `exportConfiguration(document)` round-trips the JSON data into its original
format. These private results contain plaintext configuration and must be protected
like the input. CLI/MCP export only the preview through Core, including persisted
evidence/report. No field/value/name/input digest is exported. Comments, quoting,
formatting and YAML presentation are intentionally not retained. Unknown JSON fields,
explicit false/zero/null/empty values and multiline strings are retained as data.

Duplicate keys, non-string keys, aliases/anchors, explicit tags, merge keys, multiple
documents, YAML 1.1, prototype keys, non-finite/unsafe numbers and excessive nesting
fail closed. Errors do not include parser source excerpts. There is no host apply
operation. Compatibility with real DSH loaders, profile registration, authorization
for writes and production recovery remain unverified/unimplemented here.

## Sources and dependency

Behavior research only: mmparko/dsh-purge commit 033e6bd1e0f101352b39075ecd0d758ffef26b76,
`presets/*/preset.yml`, `presets/*/agent.cordis.yml`, `lib/rules.js`;
kingcharleslzy-ai/dsh-purge commit 411f98c676e5ff5f400df78316c9bd056416a46d,
`lib/preset-diagnostic.js`, `lib/presets.js`, `lib/preset-compat.js`.
This implements safe format behavior, not the upstream unrestricted preset or host patches.

Runtime dependency `yaml` 2.9.1 is exact-pinned in package/lock with SHA-512 npm
integrity and official registry URL. Upstream: https://github.com/eemeli/yaml,
documentation https://eemeli.org/yaml/. ISC copyright/permission notice retained
in `docs/v2.4/licenses/yaml-2.9.1.txt`. No external runtime dependencies of yaml.
As with the existing portable contract, install locked runtime dependencies using
`npm ci --omit=dev --ignore-scripts --no-audit --no-fund` before using analysis;
the source archive does not bundle node_modules. This is not an offline standalone
Node binary. Package generation is not publication or legal certification.

Tests: `node --test tests/config-formats.test.mjs`. Real synthetic filesystem and
CLI/MCP/Core evidence tests; no real DSH host mutation.
