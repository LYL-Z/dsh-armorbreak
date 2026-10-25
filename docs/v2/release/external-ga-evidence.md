# Signed external evidence for Full GA

`v2-readiness.mjs` treats task frontmatter as descriptive metadata. Changing a task's `realEndpoint`, `independentReview`, `hostInstall`, or `productionSignature` value cannot satisfy a Full GA requirement by itself.

The gate requires a commit-bound receipt bundle supplied through the protected release environment variable `ARMORBREAK_EXTERNAL_GA_EVIDENCE_BUNDLE`. The bundle must be an absolute path to a bounded, regular file outside the repository tree. Generate it **after** the candidate commit is fixed; keeping it outside Git avoids a self-referential commit hash. Each required claim must:

- identify the current 40-character source commit and repository;
- use the exact `claimId`, criterion, and subject defined in `lib/release/externalGaEvidence.js`;
- include the SHA-256 of its evidence; provider, review, and host claims reference a regular evidence file under `docs/v2/acceptance/external-evidence/`, while the production-signature proof is base64-embedded in the external bundle;
- have an Ed25519 claim signature from a signer with the required role;
- remain valid for the exact candidate commit. Any source commit change requires new receipts.

The currently required claims cover five real provider endpoints, ABU-409 independent review, ten host L0/install records, and ABU-408 production artifact signing. These receipts are separate from GitHub's build-provenance attestation. Provenance proves which workflow built an artifact; it does not prove a provider transaction, independent review, host installation, or production signature.

## Trusted signers

The verifier reads `ARMORBREAK_EXTERNAL_GA_TRUSTED_SIGNERS` as JSON from the protected release environment. It must be provisioned outside pull-request-controlled files and protected so an untrusted change cannot replace the trust set. Each entry has an `id`, one or more allowed `roles`, and an Ed25519 `publicKeyPem`. Supported roles are `provider-verifier`, `independent-reviewer`, `host-verifier`, and `production-signer`. Configure distinct trusted identities for independent review and production signing; never store private keys in the repository or CI logs.

If the trust-set variable, external bundle, evidence, signer, or signature is missing or invalid, the relevant GA claim remains blocked. No trusted signer configuration or external receipt is included in this repository, so this mechanism is fail-closed and does not make the current candidate GA-ready.

## Receipt shape

The bundle has this shape:

```json
{
  "schemaVersion": "armorbreak.external-ga-evidence/v1",
  "repository": "LYL-Z/dsh-armorbreak",
  "sourceCommit": "<exact 40-character commit>",
  "claims": [
    {
      "claimId": "realEndpoint:ABU-311",
      "criterion": "realEndpoint",
      "subject": "ABU-311",
      "status": "PASS",
      "evidencePath": "docs/v2/acceptance/external-evidence/ABU-311-real-endpoint.json",
      "evidenceSha256": "<sha256 of the evidence file>",
      "verifiedAt": "<ISO-8601 UTC timestamp>",
      "signerId": "<trusted signer id>",
      "signature": "<base64 Ed25519 signature>"
    }
  ]
}
```

The claim signature is over the canonical JSON returned by `externalGaEvidenceSigningPayload(repository, sourceCommit, claim)`. Object keys are sorted recursively; arrays retain order; the `signature` field is excluded. For `productionSignature:ABU-408`, put the base64-encoded UTF-8 JSON proof in `evidenceBase64` instead of `evidencePath`; the proof uses schema `armorbreak.production-signature-evidence/v1` and its Ed25519 signature must cover the exact artifact name, artifact SHA-256, repository, and source commit returned by `productionArtifactSignaturePayload`. The claim signer must also have the `production-signer` role. Since both the receipt bundle and this production proof are supplied externally after the source commit is fixed, neither creates a commit-hash cycle.

This schema only defines verification. It does not manufacture evidence or signatures; the relevant external verifier must perform and attest its real work before creating a receipt.
