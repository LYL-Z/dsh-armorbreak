# Runtime compatibility notes (M4-06 / M4-07)

## Preset package naming is host-version dependent

- DSH Desktop app `resources/app.asar` (current installed host) contains
  `node_modules/@deepseek-ai/dsh-agent-preset` (**singular**).
- Global CLI `dsh 0.1.0-rc.6` contains `@deepseek-ai/dsh-agent-presets`
  (**plural**, config schema `{ default, roots }`).
- V2 targets the installed DSH Desktop host, so `cordis.patch.yml` keeps the
  singular package. Changing it to plural makes Desktop incompatible and is
  therefore rejected.

## Consequence for M4-06

A second Web instance cannot be booted through the global CLI with the v2 bundle:

- `dsh --profile v12test` fails because the profile lacks base/preset deps;
- `dsh --profile desktop` fails on missing experimental bundles;
- global CLI's plural preset package is not the Desktop host's singular package.

The running Desktop GUI is a v1.x session and must not be restarted while it
hosts this work. Consequently, a real V2 Desktop GUI/model E2E was **not**
executed; M4-06 remains REVIEW/BLOCKED.

## Follow-up

- A host-version-aware preset adapter (singular for Desktop, plural for CLI) is
  required before claiming cross-host compatibility.
- Do not silently rewrite the bundle patch based on one host; this is a
  compatibility gate, not a cosmetic rename.
