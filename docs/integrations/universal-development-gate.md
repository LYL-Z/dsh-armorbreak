# Universal development gate candidate

Stable context: `ArmorBreak development gate (required)`.

Every pull_request event (including maintenance, development, docs-only and unexpected branch names) and every main push executes the same Node22/24 Ubuntu/Windows full suite and typecheck, L0 and digest-pinned Docker L1. There are no branch-name or path exemptions. Existing version-specific release workflows remain additive and unchanged. The full suite includes applicable version contracts; this development gate is not release approval.

The aggregate uses always(), checks the exact dependency key set and requires each result to equal success. Missing, skipped, failure, cancellation and timeout fail closed. If GitHub cancels the entire workflow or infrastructure cannot schedule the aggregate, no successful gate exists: branch protection must require this stable context. Each validation asserts the event candidate SHA. The evaluator also checks its checkout SHA against the event candidate; a previous run cannot validate a new candidate.

Local injected-result unit tests are simulations. Live GitHub success/failure/cancellation/timeout evidence must be recorded separately. This candidate does not modify protection, reviews, main, tags or releases. Main push cannot be verified before an authorized merge; no test merge is authorized.

This PR is stacked on PR #33 so its validated Windows migration fixes are reused, not duplicated. Review the new PR diff against that base; after #33 merges, rebase/retarget through the protected normal workflow and rerun exact-source checks.
