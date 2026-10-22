# Provider Security and Policy

## Secret storage

- `WindowsDpapiVault` uses Windows DPAPI `CurrentUser` to encrypt a JSON vault file.
  Only ciphertext is persisted; `list()` returns names only.
- `MemorySecretVault` is for tests and ephemeral use.
- `redactSecret()` strips `sk-`, `ant-`, `gem-` keys and authorization/token/password
  fields before errors or diagnostics are emitted.

## Egress policy

`ProviderPolicy.checkEgress(url)`:

- loopback HTTP is allowed only when `allowLoopback` is true;
- all non-loopback endpoints must be HTTPS;
- the host must be in `allowedHosts` (default OpenAI/Anthropic/Gemini endpoints).

## Budget and fallback

- `checkBudget({tokens,costUsd})` fails with `BUDGET_EXCEEDED` before a call that
  would cross the configured token/USD budget.
- `fallback({from,to})` requires an explicit `from->to` entry in
  `approvedFallbacks`; otherwise it fails with `FALLBACK_NOT_APPROVED`.
- The model is never an approval principal.

## Test coverage

`tests/provider-vault-policy.test.mjs` covers ciphertext-only persistence, DPAPI
round-trip, redaction, egress denial, budget exhaustion and unapproved fallback.
