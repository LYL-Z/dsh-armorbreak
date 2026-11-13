# V2.4 Purge integration — first executable migration slice

Status: **IMPLEMENTED IN ISOLATED DRAFT BRANCH, NOT MERGED / NOT SHIPPED**.

## What actually migrated

An original, read-only implementation of the **Desktop disk-layout and package-family diagnostic**, informed by two pinned Purge snapshots:

- Original mirror: [mmparko/dsh-purge](https://github.com/mmparko/dsh-purge) at 033e6bd1e0f101352b39075ecd0d758ffef26b76; conceptual host surface selection from lib/surface.js.
- Community fork: [kingcharleslzy-ai/dsh-purge](https://github.com/kingcharleslzy-ai/dsh-purge) at 411f98c676e5ff5f400df78316c9bd056416a46d; conceptual distinctions from lib/host-layout.js and lib/next-host.js.

No upstream source or prompt text was copied; all new implementation and fixtures are ArmorBreak-native. The fork shares original ancestry and is **not** counted as an independent second copy of each capability. This is a small P1 diagnostic increment, not a claim of migrating all 165 capability IDs.

## New usable command

Run without ArmorBreak task store or engine configuration:

    node packages/cli/index.js host layout --resources /absolute/path/to/Desktop/resources --json

On Windows, pass an absolute path to the installation's actual Resources directory. The command makes **no host writes**. It only inspects explicitly selected, known paths:

- app.asar (archive file presence, not ASAR contents)
- app (unpacked directory presence)
- app.asar.unpacked (archive companion presence)
- Official package identity at known unpacked dsh/node_modules/@deepseek-ai/dsh-desktop-host/package.json paths
- NEXT package identity at known unpacked app/package.json paths (requires name dsh-desktop-next and a nonempty main)

The JSON contract is armorbreak.dsh-runtime-layout/v1. Possible outcomes include DISK_PACKAGE_FOUND, NO_VERIFIED_PACKAGE, CONFLICTING_IDENTITIES, CONFLICTING_VERSIONS, INCOMPLETE. A known package is **on-disk evidence only**. The output always sets runtime=NOT_VERIFIED and patch=NOT_ASSESSED. It never infers that process code is loaded, an injection reached a model, the host was patched, or a particular version is compatible. No automatic running-process scan or auto-selected installation is used.

Security: all paths are bounded and explicit; metadata files are capped at 64 KiB, final symlinks are not followed and the directory ancestry is checked. Only recognized package family, validated version and bounded source category enter reports. Unknown JSON fields, registry credentials, scripts, model prompts and environment variables are neither executed nor printed. Concurrent adversarial parent-path replacement is outside the guarantee; a trusted local installation root is required for reliable evidence.

## Tests and non-claims

    node --test tests/dsh-runtime-layout.test.mjs

Eleven synthetic *real filesystem* tests: official/NEXT identification; mixed identities; conflicting versions; archive-only unknown; symlinked metadata and directory; hostile/secret metadata; oversize; invalid path; no-write invariants.

These tests establish local module behavior. They do not replace remote CI, official DSH Desktop live-instance tests, Windows/macOS/Linux platform tests, full Core regression, authorization review, or protected merge checks.

## PR integration and boundary

This slice is stacked on the **unmerged** existing PR #32 read-only Purge foundation and does not modify main, PR #32, PR #33, PR #35, PR #38, v2.3.1 tag or any release artifacts. The existing CI transition and trusted App Gate are still pending. Updating packages/cli/index.js changes a protected control path; **a separate owner-reviewed frozen-policy promotion is required** before an external trusted gate can accept this code. Do not fake a green trusted Check.

The ZIP used for A1a-R4 is an **independent Windows host security review artifact**; it is not a prerequisite for this isolated code branch. A1a remains blocked on VHDX sharing violation 32 and complete backup/restore evidence. No App was provisioned, no Check posted and no host ACL applied.

Next M2 slices should add scoped runtime/probe diagnostics with real-process evidence only when externally verifiable, then separately scoped configuration overlays/transactional maintenance behind Core policy. Never port unrestricted host mutation, model refusal-bypass prompts or unscoped credentials operations as defaults.