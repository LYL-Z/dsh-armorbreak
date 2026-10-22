# P0 Security Review (ABU-406)

This is an internal negative-test review, not a third-party certification.
Every declared P0 risk maps to an executable test or an explicit residual risk.

| Risk | Negative test | Result |
|---|---|---|
| Model text becomes operator/approval | `tests/approval-cli.test.mjs`, `tests/security-hardening.test.mjs` | rejected; task operator remains trusted principal |
| Cross-workspace task read/cancel | `tests/cross-client-security.test.mjs` | denied |
| Cross-principal approval token | `tests/cross-client-security.test.mjs` | binding mismatch |
| Prompt injection in title/arguments | `tests/security-hardening.test.mjs` | no authority change |
| Tool-output pollution | `tests/security-hardening.test.mjs` | stored as evidence data only |
| CSRF / malicious Origin / Host | `tests/mcp-http.test.mjs` | 403/404, no CORS allow |
| Supply-chain config overwrite | `tests/json-installer.test.mjs`, `toml-installer.test.mjs`, `yaml-installer.test.mjs` | conflict/rollback tests |
| Secret leakage | `tests/evidence-envelope.test.mjs`, `tests/provider-router.test.mjs` | redaction/no key in route |
| L3 escalation | `tests/approval-cli.test.mjs`, policy tests | always denied |

## Residual risks

- No independent third-party audit.
- No remote multi-tenant identity/TLS deployment review.
- No real prompt-injection evaluation against a live model/host.
- No fuzzing of all tool schemas.
