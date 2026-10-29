# Windows test temporary-volume diagnostic

## Observed runs

- Source `ba3c5ea4134f138bca22d1a6aa597f1e7f2b0cc4`, default `npm test`: 635 tests, 629 passed, 6 failed. The failures were in evidence-manifest, MCP hard-link, and safe-evidence race tests.
- The errors showed that the default temporary directory was on C: while the checkout was on D:. The Windows safe writer could not perform its handle-relative traversal under the host-protected `C:\Users` directory (`Win32=5`), and the MCP hard-link fixture failed with `EXDEV` across volumes. The race assertion failed because the expected temporary file was never opened after the write refusal.
- Re-running the same 635-test suite with TEMP/TMP on the checkout volume passed 635/635. The 14 tests in the affected files passed 14/14 under that setup.
- Commit `e57287f5abc9fb9ba86cb686736f67f3ab030357` adds a test-only helper that selects a temporary directory on the workspace volume/device when the system temp differs. On that commit, the 14 affected tests passed 14/14 and the unmodified `npm test` command passed 635/635 with no environment override.

## Scope and interpretation

This was a Windows test-fixture placement issue, not an ArmorBreak runtime or M3 analyzer change. The helper changes only where the three filesystem-security test groups create temporary fixtures. It preserves the hard-link, safe-write, and concurrent-rename assertions. The initial failure is retained here so the final pass does not hide it.

The final full-suite output is [`full-test-default-final.log`](full-test-default-final.log). The final test result and raw-log hash are indexed in [`m3-validation.json`](m3-validation.json).
