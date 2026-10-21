# Provider Matrix (P3 slice)

No API keys are stored in the repository or provider config. Credentials are
read only from the named environment variable in the host process/secret store.
The model is never an approval principal.

| Provider | Kind | Example model | Credential | Tools | Verification |
|---|---|---|---|---|---|
| OpenAI-compatible | `openai-compatible` | `gpt-4.1` | `OPENAI_API_KEY` | yes | Unit-tested router; no live call |
| Anthropic | `anthropic` | `claude-sonnet-4-5` | `ANTHROPIC_API_KEY` | yes | Unit-tested router; no live call |
| Ollama | `ollama` | `qwen2.5-coder:14b` | none | no | Unit-tested router; no live call |
| Local OpenAI-compatible | `local` | `local-model` | none | yes | Unit-tested router; no live call |

## Router guarantees

- unknown model → `MODEL_NOT_FOUND`
- tool-required but provider lacks tools → `MODEL_UNSUPPORTED`
- required credential env missing → `KEY_MISSING`
- config with `apiKey`/token/secret-like fields → `PROVIDER_INVALID`
- returned route has `modelIsAuthority:false` and no key material
- `list()` exposes `credentialPresent` boolean, not credentials

Example config: `packages/provider-router/providers.example.json`.
