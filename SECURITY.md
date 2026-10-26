# Security Policy / 安全政策

## Supported versions

| Version | Supported |
|---|---|
| 2.2.x (Stable) | Security fixes or mitigations for confirmed vulnerabilities, subject to maintainer capacity; no fixed support end date |
| 1.0.x | ✅ security fixes (existing commitment unchanged) |
| < 1.0.0 | ❌ (not published) |

### Support lifecycle

- `2.2.x` is the current Stable maintenance line.
- No fixed support end date is promised; this is not a permanent-maintenance commitment.
- Confirmed security issues are handled according to severity, impact, technical feasibility and maintainer capacity.
- The existing `1.0.x` security-fix commitment remains in force.
- Lifecycle status for other historical versions is not decided by this revision; no EOL or unsupported status is asserted for them.
- Any future change to support scope or EOL requires a new explicit policy revision.

## Reporting a vulnerability

**Please do not open a public issue for security reports.**

- Preferred: GitHub Security Advisories — open a private advisory on
  `https://github.com/LYL-Z/dsh-armorbreak/security/advisories/new`.
- Alternative: email the maintainer at `3507103376@qq.com` with the subject
  `[SECURITY][dsh-armorbreak]`.
- Include: affected version/tag, DSH version, reproduction steps, impact
  analysis, and (if available) a minimal proof of concept that does **not**
  affect third-party systems.

### What to expect

| Stage | Target |
|---|---|
| Acknowledgement | ≤ 72 hours |
| Triage + severity (CVSS 4.0 rationale) | ≤ 7 days |
| Fix or mitigation plan | ≤ 30 days for high/critical |
| Coordinated disclosure | agreed with reporter; default 90 days |

Credit is given in the advisory and CHANGELOG unless the reporter prefers to
remain anonymous.

## In-scope assets and expected security properties

This project is a **DeepSeek Harness plugin bundle + agent preset** that runs
inside the Host process. In-scope weakness classes:

- policy-engine bypasses (L0/L1/L2/L3 gates, approvals, path/network scope);
- evidence/audit hash-chain integrity defects;
- non-lossless tool output, prototype pollution, unbounded parsing;
- prompt-injection paths where analyzed content can change tool behavior;
- secrets leaking into logs, evidence, reports, or the read-only UI route.

Out of scope: vulnerabilities in DeepSeek Harness itself (report upstream),
in external tools (Ghidra/JADX/etc.), or in target samples analyzed by the mode.

## Ethical-use boundary

ArmorBreak is for **authorized** security research only. Reports or requests
that involve unauthorized access, credential theft, stealth persistence,
malware delivery, or destructive attacks will not be accepted as features.
L3-class operations are denied by the policy engine and will stay that way.
