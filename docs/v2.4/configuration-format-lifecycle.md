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

## Edit a configuration copy and rehearse changes

Save an edit bundle in the authorized workspace. The bundle carries the original
configuration text and an ordered list of operations. This bundle edits a YAML
copy.

```json
{
  "schema": "armorbreak.configuration-edit-request/v1",
  "configuration": {
    "schema": "armorbreak.configuration-import/v1",
    "format": "yaml",
    "source": "settings:\n  enabled: false\n  retired: 0\n"
  },
  "operations": [
    {"op": "replace", "path": ["settings", "enabled"], "expected": false, "value": true},
    {"op": "remove", "path": ["settings", "retired"], "expected": 0},
    {"op": "add", "path": ["settings", "labels"], "value": ["local"]}
  ]
}
```

Run `armorbreak config edit --bundle <file> --json` for a Core preview. On MCP,
call `armorbreak_analyze` with capability `configuration.preview`, the bundle as
`target` and `options: {"mode":"edit"}`. The report gives the format, status and
operation counts. The bundle, field names, values, paths within the configuration
and content hashes stay out of the report.

In Workbench, open the project in advanced mode, choose **预览配置变更** and set
**配置预览方式** to **结构化编辑**. Enter the existing bundle path inside the
workspace and choose **预览编辑**. If validation fails, correct the bundle and
submit it again. Successful previews offer a Markdown report and leave the
original file untouched.

Map keys are strings. Array indices are numbers and are evaluated after prior
operations. A map add requires an absent key. An array add inserts a new element
at the index, including at the end. Replace and remove require the exact expected
JSON value from the supplied copy. A mismatch or an invalid finished document
rejects the entire batch. For Cordis, paths start at the composition array. For
Purge, paths start with `metadata` or `composition`. JSON and YAML paths start
at the root map. Changed YAML preserves compatible comments and scalar style.
Deleted nodes may remove associated comments. An unchanged Purge file retains
its original bytes even when the other file changes.

The same bundle works with `armorbreak config stage --bundle <file> --json` to
create a fresh isolated rehearsal. An unchanged result shows `NO_CHANGES` in
the preview and creates no lab. In a trusted CLI host, `config apply` and
`config revert` use that lab and plan and each require a separate one-time
approval. The source bundle remains unchanged and successful rollback restores
the exact original bytes of the lab files. The edit preconditions refer to the
supplied copy. Live host apply, upstream preset equivalence and automatic
production recovery remain unverified.

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
