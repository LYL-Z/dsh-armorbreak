# AISEC worker protocol (AB2-M3-02)

- Transport: newline-delimited JSON over stdin/stdout; stderr is captured (bounded 4 KiB) for diagnostics.
- Request: `{"id":<int>,"method":"ping|env|evaluate|sleep|crash|shutdown","params":{}}`
- Response: `{"id":<int>,"ok":true,"result":{}}` or `{"id":<int>,"ok":false,"error":{"code","message"}}`
- Protocol id: `armorbreak.aisec-worker/v1`.
- Runtime: CPython >= 3.10, stdlib only (`scripts/aisec/requirements.lock`).
- Environment: explicit allowlist (`PATH`, `PYTHONPATH`, `PYTHONUNBUFFERED`, locale/temp/home/Windows system keys); secrets are not inherited.
- Failure: timeout/cancel kills the worker and rejects pending requests; the next request starts a fresh worker. `crash` is a deliberate test method only.
