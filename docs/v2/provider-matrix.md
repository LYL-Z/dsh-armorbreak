# Provider Matrix (P3)

No API keys are stored in the repository or provider config. Credentials are
read only from the named environment variable in the host process/secret store.
The model is never an approval principal.

| Provider | Kind | Example model | Credential | Tools | Verification |
|---|---|---|---|---|---|
| OpenAI-compatible | `openai-compatible` | `gpt-4.1` | `OPENAI_API_KEY` | yes | Mock + local Ollama real; paid OpenAI endpoint `BLOCKED_EXTERNAL` |
| OpenAI Responses | `openai-responses` | `gpt-5` | `OPENAI_API_KEY` | yes | Mock/golden text+tool+stream+error; real endpoint `BLOCKED_EXTERNAL` |
| Anthropic | `anthropic` | `claude-sonnet-4-5` | `ANTHROPIC_API_KEY` | yes | Mock/golden + streaming/tool lifecycle; real endpoint `BLOCKED_EXTERNAL` |
| Gemini native | `gemini` | `gemini-2.5-pro` | `GEMINI_API_KEY` | yes | Mock/golden text+tool+stream+error; real endpoint `BLOCKED_EXTERNAL` |
| Ollama | `ollama` | `qwen3.5:4b` | none | yes | **Live local**: chat, SSE, tool call and 3-turn loop; `provider-live-ollama.json` |
| Local OpenAI-compatible | `local` | `local-model` | none | yes | Unit-tested router; no live call |

## Router guarantees

- unknown model → `MODEL_NOT_FOUND`
- tool-required but provider lacks tools → `MODEL_UNSUPPORTED`
- required credential env missing → `KEY_MISSING`
- config with `apiKey`/token/secret-like fields → `PROVIDER_INVALID`
- returned route has `modelIsAuthority:false` and no key material
- `list()` exposes `credentialPresent` boolean, not credentials

## Security

Secret vault, egress policy, budget and fallback approval are documented in
`docs/v2/provider-security.md` and tested by `tests/provider-vault-policy.test.mjs`.

Example config: `packages/provider-router/providers.example.json`.
