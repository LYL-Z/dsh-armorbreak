# Offline assessment evidence review (Draft)

This is an original ArmorBreak implementation of a data-review subset of
PO-REDTEAM-SAFE-DATA-003 and PC-REDTEAM-SAFE-DATA-011. Research references:
Purge Original 033e6bd1e0f101352b39075ecd0d758ffef26b76 (report/assessment
concepts) and Community 411f98c676e5ff5f400df78316c9bd056416a46d,
`lib/redteam/evidence-ledger.mjs`, `lib/redteam/report-replay.js` (source labels,
claim provenance and the distinction between supplied and observed evidence).
No upstream source, command synthesis, SQLite database or active execution
module is imported. Source permissions and redistribution rights remain separate
from technical tests; no claim of complete upstream behavior equivalence.

Use `node packages/cli/index.js assessment review --bundle ABSOLUTE_JSON --json`
with the normal Core workspace/state environment, or `armorbreak_analyze` with
`assessment.review`. The L0 capability persists the normal task, evidence,
JSON/SARIF correlation artifacts and report. Input schema:

```json
{"schema":"armorbreak.assessment-review-input/v1","artifactSha256":"64 lower-case hex digits","evidence":[{"id":"record-1","confidence":"claimed","authority":"operator-input","content":"synthetic observation","sha256":"SHA256 of exact UTF-8 content","supportingIds":[]}],"findings":[{"id":"claim-1","ruleId":"CWE-79","severity":"high","evidenceIds":["record-1"]}]}
```

Each evidence hash and reference graph is verified, with bounded strict data
shapes and no command hooks. Identifiers are digested in output. Raw content,
targets, secrets and imported commands are not copied into reports. The existing
`security.correlate` implementation produces normal correlation artifacts.
Even a caller's `observed` / `tool-output` label remains `UNVERIFIED_INPUT`:
matching a content digest proves neither truth, authority, authorization nor a
reproduced vulnerability. Vulnerability status stays `not_tested`.

Deterministic repeated review is supported; HTTP/tool replay is not. Scoring,
active scanning, screenshot authenticity, independent evidence verification,
third-party database migration and actual host integration remain unimplemented
or unverified. No network or attack executes. This subset is not a complete
red-team feature migration and does not weaken L3 denial.
