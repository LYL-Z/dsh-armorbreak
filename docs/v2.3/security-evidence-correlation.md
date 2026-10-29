# M4 — Offline security evidence correlation

Status: `IN_PROGRESS` until the complete exact-SHA local validation and the remaining P0 gates are recorded. This document describes the bounded local implementation; it is not a claim that the M4 release gate or V2.3.0 is complete.

## Input contract

`security.correlate` is an L0 capability that reads an explicitly supplied local JSON file using schema `armorbreak.security-evidence-bundle/v1`. It does not select or invoke scanners, access the network, execute a sample, or perform an exploit check. `UniversalSecurityReview` wraps that one capability; previous workflow-step output is not piped into it, so callers prepare the evidence bundle themselves.

Accepted source kinds are:

- ArmorBreak finding arrays (`armorbreak` / `armorbreak-findings`)
- SARIF 2.1.0 result records
- Semgrep JSON `results[]`
- Trivy JSON `Results[].Vulnerabilities[]`
- Explicit, already matched OSV records (`matches[]`), without fetching or evaluating version ranges
- CycloneDX and SPDX documents, which are validated, summarized, and hashed

Correlation requires an artifact SHA-256, normalized file and line, CWE or rule, and non-empty evidence-context hash. Records missing any key remain separate. Independent source-family records with the same key are labeled `corroborated`; otherwise source-provided evidence maturity is preserved conservatively. This is report-level cross-source agreement, not independent reproduction. Every aggregate has `vulnerabilityStatus: not_tested`; imported `confirmed` or `refuted` values are retained only as source claims and cannot promote the aggregate.

## Output and data handling

The capability emits deterministic JSON and SARIF 2.1.0 artifacts. SARIF retains source relationships in `relatedLocations` and properties. Finding excerpts and derived strings are redacted; absolute paths are replaced with stable opaque identifiers, and the source finding is retained as a bounded redacted record. The report contains a digest of the redacted source record, not a claim that it is a byte-exact source archive. Absolute path names are not included in that digest's preimage as emitted data.

CycloneDX/SPDX payloads are not copied into the report and are not converted. The report records declared format/version, available component count, an input document digest after redaction, and any declared source digest. Database snapshot age is calculated only when an assessment date and valid snapshot date are supplied; otherwise freshness remains unknown. OSV/CVE advisory matching and version applicability are outside this capability.

Bounds: 8 MiB input, 50 sources, 200 findings in total, 2 KiB per retained source finding before truncation, and 900 KiB per generated artifact. Oversized input fails closed; oversized source records are represented by a digest and truncated preview. An output exceeding the artifact cap fails rather than silently dropping findings.

## Validation evidence and limits

The authored M4 contrast corpus covers 20 groups and 60 single-line snippets over CWE-78, CWE-89, CWE-22, CWE-918, and CWE-95. Its scanner metrics are reported separately in `evidence/m4/vulnerability-corpus-metrics.json` after exact-SHA execution. These metrics characterize only this authored corpus; they do not estimate real-world prevalence, precision, or recall. No sample execution or network access is part of the corpus run.

M4 remains incomplete until evidence records exact source SHA, focused tests, typecheck, the full suite, registry/compatibility counts, and corpus hashes/metrics. CI, cross-platform behavior, independent validation, advisory synchronization, and automated scanner invocation are not established by this local capability.
