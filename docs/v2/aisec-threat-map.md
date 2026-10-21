# AISEC threat map (AB2-M3-01)

| Scenario category | Threat | Required boundary | Evidence |
|---|---|---|---|
| prompt-injection | Untrusted content asks for tools/authorization | Knowledge guard marks UNTRUSTED_DATA; PolicyGateway rejects model authorization | traceId + output sha256 + flags |
| tool-abuse | Model tries L2/installer via tool arguments | explicit routes; unknown action deny; installer pre-approval deny | gateway decision code |
| data-exfiltration | Output contains secrets or sends to external URL | secret patterns + no external endpoint in M3-01 | result output hash/preview |
| memory-poisoning | Poisoned memory persists across turns | memory updates are data, not policy; trace-linked audit | scenario/result traceId |
| multimodal | OCR/PDF/audio carries instructions | content stays untrusted; missing runtime = SKIPPED, never PASS | judge verdict + skip reason |
| jailbreak-research | Research corpus becomes reusable payload | only aggregate results; no raw harmful payload distribution | dataset fingerprint + aggregate |

M3-01 enforces: scenario/result traceId linkage, mock/local targets only, explicit operator authorization, model-supplied authorization rejected, and no target invocation before validation.
