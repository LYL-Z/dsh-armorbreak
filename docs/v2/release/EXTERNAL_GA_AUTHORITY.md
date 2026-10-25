# External GA evidence and release authority

`verifyExternalGaEvidence()` is an evidence validator. It checks signatures and exact-SHA claims against the signer configuration supplied to it; it does not itself authorize publication. Its result therefore reports `releaseAuthorization.status: REVIEW` even when the evidence signatures validate.

The signer configuration must be pinned by a SHA-256 value provisioned outside the candidate tree. A future protected GA environment must provide `ARMORBREAK_EXTERNAL_GA_TRUSTED_SIGNERS` and `ARMORBREAK_EXTERNAL_GA_TRUSTED_SIGNERS_SHA256`; a missing or mismatching pin leaves every external claim `UNVERIFIED`. Do not place the pin or signer private keys in source-controlled files or ordinary candidate evidence.

Formal authorization also requires a protected main-branch workflow, an approved deployment/release environment, the exact merged source SHA, the expected attestation workflow identity, and the exact artifact digest. GitHub OIDC/Sigstore provenance proves build origin and subject binding; it is not a production artifact signature, commercial-provider receipt, host-install receipt, or independent human review.

As of 2026-10-25, GitHub reports no configured repository environments. Consequently there is no protected GA deployment environment yet, and the current local readiness command can report evidence completeness only; its formal release authorization remains `REVIEW`.
