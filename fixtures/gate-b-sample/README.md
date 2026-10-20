# Gate B sample project (intentionally vulnerable)

This directory is a **deliberately vulnerable fixture** used by
`scripts/verify-gate-b.mjs` to prove the Stage B external adapters against the
real Semgrep and Trivy CLIs. Do not deploy it, do not copy it into a real
service, and do not treat its dependency versions as suggestions.

## What it contains

| Path | Purpose |
|---|---|
| `package.json` / `package-lock.json` | Old npm dependencies with known CVEs (lodash, minimist, axios, node-fetch, express, ejs, jsonwebtoken, tar). The lockfile was generated with `npm install --package-lock-only`, so no `node_modules/` is needed. |
| `requirements.txt` | Old Python pins (Django, Jinja2, PyYAML, requests) for Trivy's pip analyzer. |
| `src/app.js` | Dynamic `eval`, `child_process.exec` string concatenation, SQL string concatenation, and an AWS *documentation example* key. |
| `src/crypto.js` | MD5 use for the local Semgrep weak-hash rule. |
| `src/config.js` | Random fake credential-shaped values so Trivy's secret scanner has a positive match. They are not live credentials. |
| `.env` | AWS documentation example values; Trivy allowlists the `AKIAIOSFODNN7EXAMPLE` value, so it produces no finding. |
| `Dockerfile` | Unpinned base image and root user (future config-scanner fixture). |

The local Semgrep rules live in `../gate-b-rules/armorbreak-local.yml` and are
passed through `options.config`; ArmorBreak never fetches rules from the network.

## Expected results (Gate B, 2026-10-20)

- Semgrep 1.181.0 with the local rule set: 6 findings across 5 rules
  (2 critical + 4 high, all `verification=hypothesis`).
- Trivy 0.76.0 with the offline vulnerability DB, `--scanners vuln,secret`,
  `--severity HIGH,CRITICAL`: 67 findings (65 dependency CVEs + 2 secrets;
  53 high + 14 critical).
- The runner task must end `COMPLETED` with a verified evidence chain.

Exact tool versions, paths, result counts and artifact hashes are recorded in
`docs/acceptance/gate-b-summary.json`.
