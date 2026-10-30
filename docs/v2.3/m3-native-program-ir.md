# M3 — Native Program IR

## Status

**Native P0: `LOCAL_REAL_TOOL_E2E_VERIFIED`; M3 overall: `PARTIAL`.** At exact source SHA `e57287f5abc9fb9ba86cb686736f67f3ab030357`, focused tests passed 28/28, the full suite passed 635/635, and typecheck exited 0. On this Windows host, six self-authored PE, ELF, and Mach-O fixtures passed the real `ArmorBreakRuntime.runner.runCapability` → PolicyGateway → `binary.program_ir` → Ghidra 12.1.4 path. The fixture hashes, captured functions/call edges, bounds, and per-sample `inputExecuted: false` are in [`native-ghidra-runner-e2e.json`](evidence/m3/native-ghidra-runner-e2e.json); exact commands and log hashes are in [`m3-validation.json`](evidence/m3/m3-validation.json).

This closes the local native P0-D static-analysis evidence gap, including Mach-O and two Ghidra ISAs. It does not close the release gate: output is bounded and heuristic, no macOS runtime was used, Ghidra was run on the host rather than in the currently available container isolation, and P1 bytecode coverage remains open.

## Implemented scope

- `binary.program_ir` is an L0 file capability registered through the existing analyzer registry. `NativeProgramIRReview` exposes it through the existing workflow system.
- The capability normalizes PE, ELF, and Mach-O identity, architecture, bitness, sections/segments, entry points, symbol summaries, import/export and debug/resource clues, and optional Ghidra function, basic-block, call-edge, and function-byte-hash records.
- Ghidra receives a bounded temporary copy only when Core supplied a complete input. Truncated/mismatched input skips Ghidra. Tool timeout/error states are structured, result arrays and total output are bounded, and temporary inputs are cleaned up.
- Input samples are not executed. `inputExecuted` was asserted false in the actual Runner results.

## Real Ghidra E2E results

The checked-in report records Node 24.16.0, Temurin JDK 21.0.12.1, Ghidra 12.1.4, Windows x64, exact input sizes and SHA-256 values, and the source commit used for the run. The PE rows hit the output bound: Ghidra reported the full function and call-edge counts while the serialized function/basic-block details were truncated. The `301` basic-block count in those bounded rows is a truncation sentinel, not a claim that the PE contains exactly 301 blocks.

| Fixture | Format / ISA | Ghidra functions (emitted) | Call edges (emitted) | Basic blocks (emitted) | Output |
|---|---|---:|---:|---:|---|
| `native_fixture_x64.exe` | PE / x86-64 | 129 (93) | 127 (127) | ≥301 (300) | `PARTIAL`, bounded |
| `native_fixture_x64_stripped.exe` | PE / x86-64 | 112 (78) | 127 (127) | ≥301 (300) | `PARTIAL`, bounded |
| `native_fixture_i386.elf` | ELF / x86 | 3 (3) | 2 (2) | 3 (3) | `PARTIAL` |
| `native_fixture_i386_stripped.elf` | ELF / x86 | 3 (3) | 2 (2) | 3 (3) | `PARTIAL` |
| `native_fixture_x86_64_macho.macho` | Mach-O / x86-64 | 3 (3) | 2 (2) | 3 (3) | `PARTIAL` |
| `native_fixture_x86_64_macho_stripped.macho` | Mach-O / x86-64 | 3 (3) | 2 (2) | 3 (3) | `PARTIAL` |

For Mach-O, Ghidra found `_helper`, `_caller`, and `entry`, with call sites `_caller → _helper` and `entry → _caller`; the report includes file offsets and function-byte hashes. The stripped derivative retained three functions and two call edges while the local symbol table was absent. The third Mach-O fixture is a 512-byte truncation and is tested by the native parser as `PARTIAL`; it is deliberately not passed to Ghidra.

## Mach-O fixture provenance

`native_fixture.c` is a self-authored three-function C fixture. It was cross-compiled on Windows to a 64-bit macOS Mach-O target with Zig 0.17.0; this does not constitute a macOS build-host or runtime test. The Zig Windows archive was checked against the official Zig download index: 100,268,137 bytes, SHA-256 `b5663f69581dcf391293fbf16c06cb80d81d806545ce618b4d0bab7f0eb8c428`. The capture is recorded in [`mach-o-toolchain.json`](evidence/m3/mach-o-toolchain.json).

The symbol-bearing fixture SHA-256 is `02edb976b622c349337f53429a424ae853f0b0a86d0fa73a80a709571ed302de`. The stripped derivative was made from a compiler-produced hidden/local-symbol variant by deterministically removing its `LC_SYMTAB` and `LC_DYSYMTAB` load commands with [`derive-m3-macho-fixtures.mjs`](../../scripts/v2/derive-m3-macho-fixtures.mjs); that input was 16,572 bytes with SHA-256 `b897d8072ca0c4730b76a21cde15fda6df97ce6a1f5809201f454ef52d257f4f`. The resulting stripped fixture SHA-256 is `78255a8f267a4ba7ea62ff2d5f75528c24fc062c2dd8954cc9f3ea8ab866e38b`. This states the precise transformation used; it is not represented as output from Apple's `strip` utility.

The compiler command used for the symbol-bearing sample was:

```powershell
zig cc -target x86_64-macos -g -O0 -fno-sanitize=undefined -fno-stack-protector -nostdlib `
  '-Wl,-e,_main' '-Wl,-undefined,dynamic_lookup' `
  native_fixture.c -o native_fixture_x86_64_macho.macho
```

The hidden/local-symbol variant adds `-fvisibility=hidden '-Wl,-x' '-Wl,-S'`, then runs:

```powershell
node scripts/v2/derive-m3-macho-fixtures.mjs --input <compiled-hidden-symbol-macho>
```

The Mach-O header/load-command transformation and truncation are reproducible from the supplied input. A fresh compiler invocation is not claimed to reproduce the committed binary hash byte-for-byte; the committed fixtures and their SHA-256 values are the tested inputs.

## Verification commands

```powershell
node --test tests/binary.test.mjs tests/native-program-ir-fixtures.test.mjs tests/external-adapters-v2.test.mjs
node scripts/v2/verify-m3-native-ghidra-e2e.mjs --output docs/v2.3/evidence/m3/native-ghidra-runner-e2e.json
npm test
npm run typecheck
```

The E2E script analyzes only the catalogued self-authored fixtures, records the exact source commit and tool versions, and removes its temporary workspace/state on exit. It does not download tools or execute a target sample.

## Not implemented or not verified

- PE base relocations are detected but not decoded; ELF and Mach-O relocation entries are not decoded in this slice. Indirect calls/data references, whole-program control/data flow, taint, deobfuscation, unpacking, and source reconstruction are not provided.
- Ghidra output is a navigation aid, not recovered source or proof of behavior. Calls and block boundaries depend on the selected loader, ISA, and auto-analysis. Bounded/truncated details must remain visible.
- The tool ran on the host and did not process third-party or hostile samples. Docker was unavailable during the Oct 29 fresh environment check; the earlier Oct 26 harmless isolation self-test is historical and does not prove current isolation readiness.
- `android.jadx` has not been revalidated here against a real APK/DEX. New JVM class/JAR, .NET CIL, WebAssembly, Python/Lua bytecode, and HarmonyOS HAP analyzers are not included. These P1 items remain deferred/unverified.
- No macOS host/runtime, Linux host/CI, Node 22 CI, PR checks, release artifact, SBOM, attestation, migration exercise, or independent security review was verified by this M3 work.
