# Contributing / 贡献指南

Thanks for helping improve ArmorBreak. This project is intentionally **zero
runtime dependencies** and ships as source that DeepSeek Harness loads directly.

## Ground rules

1. **No runtime dependencies.** Only Node builtins (`node:*`) in `lib/`,
   `tools.js`, `skills.js`, `index.js`, `client.js`. Tests use `node:test`.
2. **No fake results.** Analyzers must not fabricate findings, test output, or
   compatibility claims. Missing tools are reported with install guidance.
3. **Contract first.** New analysis capabilities implement the adapter contract
   in [`docs/CONTRACT.md`](docs/CONTRACT.md): `run(input)` → `Result`, JSON-Schema
   `params`, honest `verification` levels, bounded processing, deterministic output.
4. **Policy gates live in core.** Analyzer code never decides authorization;
   it declares `riskLevel` + `targetKind` and the runner enforces L0–L3.
5. **No shell strings.** External commands use argv arrays via `execFile` and
   are only reachable through an approved capability.
6. **UTF-8 only.** All text files must be valid UTF-8 (`tests/hardening.test.mjs`).

## Development loop

```bash
node --test                     # full suite (zero install)
node --test --experimental-test-coverage
node benchmarks/bench.mjs       # reproducible micro-benchmarks
```

Optional live verification of the composition (non-desktop test profile):

```powershell
$dsh = "$env:LOCALAPPDATA\Programs\DeepSeek Harness\resources\runtime\cli\bin\dsh.cmd"
& $dsh --profile abmtest --from-default-profile web --dump-config
& $dsh plugin --profile abmtest add link:"<path-to-repo>"
& $dsh --profile abmtest --port 3099 --no-open
```

## Submitting a capability

1. Create `lib/analyzers/<domain>/manifest.js` + helper modules.
2. Declare `id`, `title`, `description`, `riskLevel`, `targetKind` (`file`,
   `directory`, `network`, `none`), optional `externalTools`, closed `params`.
3. Cover: normal input, malformed/truncated input, empty input, determinism,
   output budget (< 256 KiB), redaction of secrets.
4. Add `tests/<domain>.test.mjs`; run the full suite; include actual results in
   the PR description.
5. Update `docs/compatibility-matrix.md` and `docs/file-changes.md`
   (`node scripts/file-changes.mjs`).

## Commit / PR conventions

- Conventional commits: `feat(domain):`, `fix(core):`, `docs:`, `test:`, `chore:`.
- PRs must state: problem, root cause, fix, verification commands and results,
  remaining limitations. "Works on my machine" is not verification.
- Security fixes: follow [`SECURITY.md`](SECURITY.md) instead of a public PR.

## Code style

- ESM, 2-space indent, single quotes, no semicolon policy is not enforced —
  match the surrounding file.
- Prefer small pure modules; keep `lib/core/*` free of Cordis imports so it
  stays unit-testable outside the Harness process.
- Every exported function carries a JSDoc type block.

## Localization

UI strings live in `locale/{en,zh}.json`; user-facing report text is currently
Chinese (see known issues). English translations for reports are welcome.
