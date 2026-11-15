# R4-F-06 public selection boundary

Ordinary `readInstalled()` and `copySelected()` require a finalized transaction, an installed (not disabled) selection, valid complete files and current independent scoped trust. Both recheck transaction and trust after asynchronous file reads, before returning bytes. Caller options cannot enable historical export.

The planner alone holds a module-private historical snapshot capability. This permits bounded updates, disable operations and separately approved rollback of disabled or revoked selections. It exposes no raw historical export method and retains the existing sealed record, identity, closure and hash checks. This is an API boundary, not protection from an operating-system account that can directly read the lab filesystem.

The unchanged independent reproduction patch first confirmed both disabled and revoked exports returned four files on 05657c38d34de642cc3640edea8db11762a6f9ac. After the fix its two bypass assertions fail with PLUGIN_STORE_DISABLED_OR_UNTRUSTED. The original patch and both logs are retained outside the repository. The new denial regressions pass with the original plugin lifecycle suite: 35/35 on Windows. Type checking passes. Tests cover pending commit, reopen, key/authority revocation, disabled update, byte restoration and revocation after initial inspection. This implementation remains FIXED_PENDING_INDEPENDENT_REVIEW, not an independent review approval.

R3-F-05 remains AI_REVIEW_PASS_SCOPED according to the supplied R4 review. Existing frozen npm TGZ installation, exports, YAML, CLI/MCP/Workbench and isolated plugin probes are retained; distribution approval, actual DSH installation and v2.4 release remain separate and blocked.
