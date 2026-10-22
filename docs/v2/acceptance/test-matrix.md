# V2 Test Matrix (M4-05)

Base: `feature/abu-universal` 路 2026-10-21

| Gate | Scope | Evidence | Status |
|---|---|---|---|
| Unit / integration | `node --test` 327 tests, 326 pass / 1 skipped (external-tool guidance) | `test-report.json` + raw `test-report.tap` | PASS |
| Ubuntu 24 Node 24 | full suite, offline-core, benchmark | GitHub Actions | PASS |
| Windows Node 24 | full suite, offline-core, benchmark | GitHub Actions | PASS |
| Docker L1 | real daemon + isolation verification | `live-docker` + persisted self-test | PASS |
| Offline core | `--network none` container, 62/62 target scenarios + 3/3 static gate | `airgap-container.json` | PASS |
| 10 GiB streaming | sparse read, peak RSS 137.7 MB | `streaming-10gb.json` | PASS |
| Security negatives | unknown action, model authorization, L3 deny, installer pre-approval, Origin/CSRF, replay | policy/approval/UI tests | PASS |
| Performance | same-host v1.2/v2 sequential comparison; no >10% regression | `performance-compare.json` | PASS |
| macOS | not available on this host | — | N/A (not claimed) |
| Desktop GUI model E2E | real V2 bundle + GUI model call + L0 report | `desktop-e2e.json`, `desktop-analysis.json` | PASS |

The single skipped test is intentional: missing external tool must produce actionable guidance, not silently downgrade. macOS was not run and is never reported as PASS.


