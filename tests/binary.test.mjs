/**
 * ArmorBreak — binary domain tests.
 * Fixtures are built programmatically with Buffer (no binary files committed).
 * Run from armorbreak/: node --test tests/binary.test.mjs tests/forensics.test.mjs
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import manifest from '../lib/analyzers/binary/manifest.js';
import { entropyOf } from '../lib/analyzers/binary/util.js';
import { parsePe } from '../lib/analyzers/binary/pe.js';
import { parseElf } from '../lib/analyzers/binary/elf.js';
import { parseMachO } from '../lib/analyzers/binary/macho.js';
import { detectContainer } from '../lib/analyzers/binary/identify.js';

const CAPS = new Map(manifest.capabilities.map((c) => [c.id, c]));

function inputFor(buffer, options = {}, limits = {}, envOverrides = {}) {
  return {
    targetPath: null,
    buffer,
    text: buffer ? buffer.toString('utf8') : null,
    options,
    limits: {
      maxBytes: 8 * 1024 * 1024,
      maxItems: 200,
      maxStrings: 500,
      maxFindings: 100,
      timeoutMs: 15000,
      ...limits,
    },
    env: {
      signal: new AbortController().signal,
      workspaceRoot: 'D:\\dsh-ABM\\armorbreak',
      nowIso: '2026-10-20T00:00:00.000Z',
      log: () => {},
      ...envOverrides,
    },
  };
}

async function runCap(id, input) {
  const cap = CAPS.get(id);
  assert.ok(cap, `capability ${id} missing`);
  return cap.run(input);
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const PE_TIMESTAMP = 0x5f5e1000;

/** Minimal but structurally valid PE32+ with imports, exports, overlay and strings. */
function buildPe() {
  const base = Buffer.alloc(0x800, 0xcc);
  base.fill(0, 0, 0x200); // headers and directory area start zeroed
  base.write('MZ', 0, 'latin1');
  base.writeUInt32LE(0x80, 0x3c);
  base.writeUInt32LE(0x00004550, 0x80); // PE\0\0
  // COFF header at 0x84
  base.writeUInt16LE(0x8664, 0x84); // machine x86-64
  base.writeUInt16LE(2, 0x86); // numberOfSections
  base.writeUInt32LE(PE_TIMESTAMP, 0x88);
  base.writeUInt32LE(0, 0x8c); // pointerToSymbolTable
  base.writeUInt32LE(0, 0x90); // numberOfSymbols
  base.writeUInt16LE(0xf0, 0x94); // sizeOfOptionalHeader
  base.writeUInt16LE(0x0022, 0x96); // executable-image | large-address-aware
  // Optional header at 0x98
  base.writeUInt16LE(0x20b, 0x98); // PE32+
  base[0x9a] = 14; // MajorLinkerVersion
  base[0x9b] = 0;
  base.writeUInt32LE(0x200, 0x9c); // SizeOfCode
  base.writeUInt32LE(0x400, 0xa0); // SizeOfInitializedData
  base.writeUInt32LE(0, 0xa4); // SizeOfUninitializedData
  base.writeUInt32LE(0x1000, 0xa8); // AddressOfEntryPoint
  base.writeUInt32LE(0x1000, 0xac); // BaseOfCode
  base.writeBigUInt64LE(0x140000000n, 0xb0); // ImageBase
  base.writeUInt32LE(0x1000, 0xb8); // SectionAlignment
  base.writeUInt32LE(0x200, 0xbc); // FileAlignment
  base.writeUInt16LE(6, 0xc0); // MajorOperatingSystemVersion
  base.writeUInt16LE(0, 0xc2);
  base.writeUInt16LE(0, 0xc4);
  base.writeUInt16LE(0, 0xc6);
  base.writeUInt16LE(6, 0xc8); // MajorSubsystemVersion
  base.writeUInt16LE(0, 0xca);
  base.writeUInt32LE(0x4000, 0xd0); // SizeOfImage
  base.writeUInt32LE(0x200, 0xd4); // SizeOfHeaders
  base.writeUInt32LE(0, 0xd8); // CheckSum
  base.writeUInt16LE(3, 0xdc); // Subsystem = windows console
  base.writeUInt16LE(0x0140, 0xde); // DllCharacteristics = ASLR | DEP
  base.writeBigUInt64LE(0x100000n, 0xe0); // SizeOfStackReserve
  base.writeBigUInt64LE(0x1000n, 0xe8); // SizeOfStackCommit
  base.writeBigUInt64LE(0x100000n, 0xf0); // SizeOfHeapReserve
  base.writeBigUInt64LE(0x1000n, 0xf8); // SizeOfHeapCommit
  base.writeUInt32LE(0, 0x100); // LoaderFlags
  base.writeUInt32LE(16, 0x104); // NumberOfRvaAndSizes
  const dirs = 0x108;
  base.writeUInt32LE(0x2100, dirs); // export dir RVA
  base.writeUInt32LE(40, dirs + 4);
  base.writeUInt32LE(0x2000, dirs + 8); // import dir RVA
  base.writeUInt32LE(40, dirs + 12);
  // Section headers at 0x188
  const s1 = 0x188;
  base.write('.text', s1, 'latin1');
  base.writeUInt32LE(0x100, s1 + 8);
  base.writeUInt32LE(0x1000, s1 + 12);
  base.writeUInt32LE(0x200, s1 + 16);
  base.writeUInt32LE(0x200, s1 + 20);
  base.writeUInt32LE(0x60000020, s1 + 36); // code|execute|read
  const s2 = 0x1b0;
  base.write('.rdata', s2, 'latin1');
  base.writeUInt32LE(0x300, s2 + 8);
  base.writeUInt32LE(0x2000, s2 + 12);
  base.writeUInt32LE(0x400, s2 + 16);
  base.writeUInt32LE(0x400, s2 + 20);
  base.writeUInt32LE(0x40000040, s2 + 36); // initialized-data|read
  // .text payload: code filler + plain/wide strings
  base.fill(0x90, 0x200, 0x208);
  base.write('http://evil.example.com/payload\u0000', 0x210, 'latin1');
  base.write('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater\u0000', 0x240, 'latin1');
  base.write('SecretWideString', 0x2c0, 'utf16le');
  base.write('VirtualAllocEx', 0x2f0, 'utf16le');
  // .rdata: zero it first, then structures
  base.fill(0, 0x400, 0x800);
  const imp = 0x400; // RVA 0x2000
  base.writeUInt32LE(0x2040, imp); // OriginalFirstThunk
  base.writeUInt32LE(0, imp + 4);
  base.writeUInt32LE(0, imp + 8);
  base.writeUInt32LE(0x2080, imp + 12); // Name -> KERNEL32.dll
  base.writeUInt32LE(0x2060, imp + 16); // FirstThunk
  // thunks (8-byte entries on PE32+)
  base.writeBigUInt64LE(0x2090n, 0x440);
  base.writeBigUInt64LE(0x20a0n, 0x448);
  base.writeBigUInt64LE(0n, 0x450);
  base.writeBigUInt64LE(0x2090n, 0x460);
  base.writeBigUInt64LE(0x20a0n, 0x468);
  base.writeBigUInt64LE(0n, 0x470);
  base.write('KERNEL32.dll\u0000', 0x480, 'latin1');
  base.writeUInt16LE(0, 0x490);
  base.write('CreateFileW\u0000', 0x492, 'latin1');
  base.writeUInt16LE(1, 0x4a0);
  base.write('DeleteFileW\u0000', 0x4a2, 'latin1');
  // export directory at RVA 0x2100 -> offset 0x500
  const exp = 0x500;
  base.writeUInt32LE(0, exp);
  base.writeUInt32LE(0, exp + 4);
  base.writeUInt16LE(0, exp + 8);
  base.writeUInt16LE(0, exp + 10);
  base.writeUInt32LE(0x2180, exp + 12); // module name RVA
  base.writeUInt32LE(1, exp + 16); // Base ordinal
  base.writeUInt32LE(2, exp + 20); // NumberOfFunctions
  base.writeUInt32LE(2, exp + 24); // NumberOfNames
  base.writeUInt32LE(0x2140, exp + 28); // AddressOfFunctions
  base.writeUInt32LE(0x2150, exp + 32); // AddressOfNames
  base.writeUInt32LE(0x2160, exp + 36); // AddressOfNameOrdinals
  base.writeUInt32LE(0x1010, 0x540);
  base.writeUInt32LE(0x1020, 0x544);
  base.writeUInt32LE(0x2190, 0x550);
  base.writeUInt32LE(0x21a0, 0x554);
  base.writeUInt16LE(0, 0x560);
  base.writeUInt16LE(1, 0x562);
  base.write('test.dll\u0000', 0x580, 'latin1');
  base.write('ExportedFn\u0000', 0x590, 'latin1');
  base.write('AnotherExport\u0000', 0x5a0, 'latin1');
  // overlay: 64 bytes after last section raw end (0x800)
  return Buffer.concat([base, Buffer.alloc(0x40, 0xab)]);
}

/** Minimal 64-bit little-endian ELF with dynsym/symtab/dynamic/build-id. */
function buildElf() {
  const sections = [];
  const dynstr = Buffer.from('\u0000libc.so.6\u0000puts\u0000main\u0000', 'latin1');
  const strtab = Buffer.from('\u0000main\u0000helper\u0000', 'latin1');
  const dynsym = Buffer.alloc(3 * 24);
  // dynsym[1] = undefined puts (GLOBAL FUNC)
  dynsym.writeUInt32LE(11, 24);
  dynsym[24 + 4] = 0x12;
  dynsym.writeUInt16LE(0, 24 + 6);
  // dynsym[2] = defined main (GLOBAL FUNC)
  dynsym.writeUInt32LE(16, 48);
  dynsym[48 + 4] = 0x12;
  dynsym.writeUInt16LE(1, 48 + 6);
  dynsym.writeBigUInt64LE(0x401000n, 48 + 8);
  dynsym.writeBigUInt64LE(0x20n, 48 + 16);
  const symtab = Buffer.alloc(3 * 24);
  symtab.writeUInt32LE(1, 24);
  symtab[24 + 4] = 0x12;
  symtab.writeUInt16LE(1, 24 + 6);
  symtab.writeBigUInt64LE(0x401000n, 24 + 8);
  symtab.writeBigUInt64LE(0x20n, 24 + 16);
  symtab.writeUInt32LE(6, 48);
  symtab[48 + 4] = 0x12;
  symtab.writeUInt16LE(1, 48 + 6);
  symtab.writeBigUInt64LE(0x401020n, 48 + 8);
  symtab.writeBigUInt64LE(0x10n, 48 + 16);
  const dynamic = Buffer.alloc(4 * 16);
  dynamic.writeBigUInt64LE(1n, 0); // DT_NEEDED
  dynamic.writeBigUInt64LE(1n, 8); // offset of libc.so.6 in .dynstr
  dynamic.writeBigUInt64LE(5n, 16); // DT_STRTAB
  dynamic.writeBigUInt64LE(0x402000n, 24);
  dynamic.writeBigUInt64LE(14n, 32); // DT_SONAME
  dynamic.writeBigUInt64LE(16n, 40); // offset of "main"? reuse dynstr offset 16
  dynamic.writeBigUInt64LE(0n, 48);
  dynamic.writeBigUInt64LE(0n, 56);
  const note = Buffer.alloc(24);
  note.writeUInt32LE(4, 0);
  note.writeUInt32LE(8, 4);
  note.writeUInt32LE(3, 8);
  note.write('GNU\u0000', 12, 'latin1');
  Buffer.from([0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe]).copy(note, 16);
  const shstr = Buffer.from('\u0000.text\u0000.dynstr\u0000.dynsym\u0000.symtab\u0000.strtab\u0000.dynamic\u0000.note.gnu.build-id\u0000.shstrtab\u0000', 'latin1');
  const shstrOffsets = {};
  {
    let idx = 1;
    for (const name of ['.text', '.dynstr', '.dynsym', '.symtab', '.strtab', '.dynamic', '.note.gnu.build-id', '.shstrtab']) {
      shstrOffsets[name] = idx;
      idx += name.length + 1;
    }
  }
  const layout = {
    text: 0x200,
    dynstr: 0x240,
    dynsym: 0x280,
    symtab: 0x2d0,
    strtab: 0x320,
    dynamic: 0x340,
    note: 0x380,
    shstr: 0x3a0,
    shoff: 0x400,
  };
  const size = 0x640;
  const buf = Buffer.alloc(size, 0);
  // ELF header
  buf.write('\u007fELF', 0, 'latin1');
  buf[4] = 2; // 64-bit
  buf[5] = 1; // little endian
  buf[6] = 1; // version
  buf[7] = 0; // SYSV
  buf.writeUInt16LE(2, 16); // ET_EXEC
  buf.writeUInt16LE(62, 18); // x86-64
  buf.writeUInt32LE(1, 20);
  buf.writeBigUInt64LE(0x401000n, 24); // entry
  buf.writeBigUInt64LE(0x40n, 32); // phoff
  buf.writeBigUInt64LE(BigInt(layout.shoff), 40);
  buf.writeUInt32LE(0, 48);
  buf.writeUInt16LE(64, 52);
  buf.writeUInt16LE(56, 54);
  buf.writeUInt16LE(2, 56);
  buf.writeUInt16LE(64, 58);
  buf.writeUInt16LE(9, 60);
  buf.writeUInt16LE(8, 62);
  // Program headers
  const ph1 = 0x40;
  buf.writeUInt32LE(1, ph1); // PT_LOAD
  buf.writeUInt32LE(5, ph1 + 4); // R+X
  buf.writeBigUInt64LE(0x200n, ph1 + 8);
  buf.writeBigUInt64LE(0x401000n, ph1 + 16);
  buf.writeBigUInt64LE(0x401000n, ph1 + 24);
  buf.writeBigUInt64LE(0x40n, ph1 + 32);
  buf.writeBigUInt64LE(0x40n, ph1 + 40);
  buf.writeBigUInt64LE(0x1000n, ph1 + 48);
  const ph2 = 0x78;
  buf.writeUInt32LE(4, ph2); // PT_NOTE
  buf.writeUInt32LE(4, ph2 + 4);
  buf.writeBigUInt64LE(BigInt(layout.note), ph2 + 8);
  buf.writeBigUInt64LE(0x402300n, ph2 + 16);
  buf.writeBigUInt64LE(0x402300n, ph2 + 24);
  buf.writeBigUInt64LE(24n, ph2 + 32);
  buf.writeBigUInt64LE(24n, ph2 + 40);
  buf.writeBigUInt64LE(4n, ph2 + 48);
  // Section payloads
  buf.fill(0x90, layout.text, layout.text + 0x40);
  dynstr.copy(buf, layout.dynstr);
  dynsym.copy(buf, layout.dynsym);
  symtab.copy(buf, layout.symtab);
  strtab.copy(buf, layout.strtab);
  dynamic.copy(buf, layout.dynamic);
  note.copy(buf, layout.note);
  shstr.copy(buf, layout.shstr);
  // Section headers
  const sh = (index, name, type, flags, addr, offset, sz, link, info, entsize) => {
    const off = layout.shoff + index * 64;
    buf.writeUInt32LE(shstrOffsets[name], off);
    buf.writeUInt32LE(type, off + 4);
    buf.writeBigUInt64LE(flags, off + 8);
    buf.writeBigUInt64LE(addr, off + 16);
    buf.writeBigUInt64LE(BigInt(offset), off + 24);
    buf.writeBigUInt64LE(BigInt(sz), off + 32);
    buf.writeUInt32LE(link, off + 40);
    buf.writeUInt32LE(info, off + 44);
    buf.writeBigUInt64LE(1n, off + 48);
    buf.writeBigUInt64LE(BigInt(entsize), off + 56);
  };
  sh(0, '.text', 0, 0n, 0n, 0, 0, 0, 0, 0); // .null (name string reused only as placeholder)
  sh(1, '.text', 1, 0x6n, 0x401000n, layout.text, 0x40, 0, 0, 0);
  sh(2, '.dynstr', 3, 0x2n, 0x402000n, layout.dynstr, dynstr.length, 0, 0, 0);
  sh(3, '.dynsym', 11, 0x2n, 0x402100n, layout.dynsym, dynsym.length, 2, 1, 24);
  sh(4, '.symtab', 2, 0n, 0n, layout.symtab, symtab.length, 5, 1, 24);
  sh(5, '.strtab', 3, 0n, 0n, layout.strtab, strtab.length, 0, 0, 0);
  sh(6, '.dynamic', 6, 0x3n, 0x402200n, layout.dynamic, dynamic.length, 2, 0, 16);
  sh(7, '.note.gnu.build-id', 7, 0x2n, 0x402300n, layout.note, note.length, 0, 0, 4);
  sh(8, '.shstrtab', 3, 0n, 0n, layout.shstr, shstr.length, 0, 0, 0);
  return buf;
}

/** Minimal 64-bit little-endian thin Mach-O with segment, main, dylib, UUID, function starts, symtab. */
function buildMachO() {
  const buf = Buffer.alloc(0x220, 0);
  buf.writeUInt32LE(0xfeedfacf, 0); // magic (bytes CF FA ED FE -> LE)
  buf.writeUInt32LE(0x01000007, 4); // CPU_TYPE_X86_64
  buf.writeUInt32LE(3, 8); // cpusubtype
  buf.writeUInt32LE(2, 12); // filetype MH_EXECUTE
  const lcStart = 32;
  let off = lcStart;
  const commands = [];
  // LC_SEGMENT_64 __TEXT with one section
  {
    const size = 72 + 80;
    buf.writeUInt32LE(0x19, off);
    buf.writeUInt32LE(size, off + 4);
    buf.write('__TEXT', off + 8, 'latin1');
    buf.writeBigUInt64LE(0x100000000n, off + 24);
    buf.writeBigUInt64LE(0x1000n, off + 32);
    buf.writeBigUInt64LE(0n, off + 40);
    buf.writeBigUInt64LE(0x200n, off + 48);
    buf.writeUInt32LE(5, off + 56);
    buf.writeUInt32LE(5, off + 60);
    buf.writeUInt32LE(1, off + 64);
    buf.writeUInt32LE(0, off + 68);
    const sh = off + 72;
    buf.write('__text', sh, 'latin1');
    buf.write('__TEXT', sh + 16, 'latin1');
    buf.writeBigUInt64LE(0x100000150n, sh + 32);
    buf.writeBigUInt64LE(0x40n, sh + 40);
    buf.writeUInt32LE(0x150, sh + 48);
    buf.writeUInt32LE(4, sh + 52);
    buf.writeUInt32LE(0x80000400, sh + 64);
    commands.push({ cmd: 0x19, size });
    off += size;
  }
  // LC_MAIN
  {
    const size = 24;
    buf.writeUInt32LE(0x80000028, off);
    buf.writeUInt32LE(size, off + 4);
    buf.writeBigUInt64LE(0x150n, off + 8);
    commands.push({ cmd: 0x80000028, size });
    off += size;
  }
  // LC_LOAD_DYLIB
  {
    const name = '/usr/lib/libSystem.B.dylib';
    const nameLen = name.length + 1;
    const namePadded = Math.ceil(nameLen / 8) * 8;
    const size = 24 + namePadded;
    buf.writeUInt32LE(0xc, off);
    buf.writeUInt32LE(size, off + 4);
    buf.writeUInt32LE(24, off + 8); // name offset
    buf.writeUInt32LE(0, off + 12);
    buf.writeUInt32LE(0x10000, off + 16);
    buf.writeUInt32LE(0x10000, off + 20);
    buf.write(name + '\u0000', off + 24, 'latin1');
    commands.push({ cmd: 0xc, size });
    off += size;
  }
  // LC_UUID
  {
    const size = 24;
    buf.writeUInt32LE(0x1b, off);
    buf.writeUInt32LE(size, off + 4);
    Buffer.from('00112233445566778899aabbccddeeff', 'hex').copy(buf, off + 8);
    commands.push({ cmd: 0x1b, size });
    off += size;
  }
  // LC_FUNCTION_STARTS -> data at 0x1c0: ULEB deltas 0x10, 0x20, terminator 0
  {
    const size = 16;
    buf.writeUInt32LE(0x26, off);
    buf.writeUInt32LE(size, off + 4);
    buf.writeUInt32LE(0x1c0, off + 8);
    buf.writeUInt32LE(8, off + 12);
    buf.writeUInt8(0x10, 0x1c0);
    buf.writeUInt8(0x20, 0x1c1);
    buf.writeUInt8(0x00, 0x1c2);
    commands.push({ cmd: 0x26, size });
    off += size;
  }
  // LC_SYMTAB: 2 nlist64 entries at 0x1d0, strings at 0x1f0
  {
    const size = 24;
    buf.writeUInt32LE(0x2, off);
    buf.writeUInt32LE(size, off + 4);
    buf.writeUInt32LE(0x1d0, off + 8);
    buf.writeUInt32LE(2, off + 12);
    buf.writeUInt32LE(0x1f0, off + 16);
    buf.writeUInt32LE(14, off + 20);
    // nlist[0]: defined external section symbol "main"
    buf.writeUInt32LE(1, 0x1d0);
    buf[0x1d4] = 0x0f;
    buf[0x1d5] = 1;
    buf.writeUInt16LE(0, 0x1d6);
    buf.writeBigUInt64LE(0x10000150n, 0x1d8);
    // nlist[1]: undefined external "_printf" (import)
    buf.writeUInt32LE(6, 0x1e0);
    buf[0x1e4] = 0x01;
    buf[0x1e5] = 0;
    buf.writeUInt16LE(0, 0x1e6);
    buf.writeBigUInt64LE(0n, 0x1e8);
    buf.write('\u0000main\u0000_printf\u0000', 0x1f0, 'latin1');
    commands.push({ cmd: 0x2, size });
    off += size;
  }
  buf.writeUInt32LE(commands.length, 16);
  buf.writeUInt32LE(off - lcStart, 20);
  buf.writeUInt32LE(0, 24);
  buf.fill(0x90, 0x150, 0x190);
  return buf;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test('binary manifest: shape, ids, risk levels and params schema follow CONTRACT', () => {
  assert.equal(manifest.domain, 'binary');
  assert.ok(Array.isArray(manifest.capabilities));
  const ids = manifest.capabilities.map((c) => c.id);
  assert.deepEqual(ids.sort(), [
    'binary.behavior', 'binary.entropy', 'binary.ghidra', 'binary.headers', 'binary.identify', 'binary.strings', 'binary.structure',
  ]);
  for (const cap of manifest.capabilities) {
    assert.match(cap.id, /^binary\.[a-z0-9-]+$/);
    assert.ok(typeof cap.title === 'string' && cap.title.length > 0);
    assert.ok(typeof cap.description === 'string' && cap.description.length > 20);
    assert.equal(cap.riskLevel, 'L0');
    assert.equal(typeof cap.run, 'function');
    assert.ok(cap.params && cap.params.type === 'object');
    assert.equal(cap.params.additionalProperties, false);
    assert.ok(cap.params.properties && typeof cap.params.properties === 'object');
  }
});

test('binary.identify: PE32+ fields, imports, exports, overlay, hashes', async () => {
  const pe = buildPe();
  const result = await runCap('binary.identify', inputFor(pe));
  assert.equal(result.data.format, 'pe');
  assert.equal(result.data.container, 'pe');
  assert.equal(result.data.arch, 'x86-64');
  assert.equal(result.data.bits, 64);
  assert.equal(result.data.endianness, 'little');
  assert.equal(result.data.type, 'executable');
  assert.equal(result.data.subsystem, 'windows-console');
  assert.equal(result.data.entryPointHex, '0x1000');
  assert.equal(result.data.entryPointVa, '0x140001000');
  assert.equal(result.data.imageBase, '0x140000000');
  assert.equal(result.data.sectionCount, 2);
  assert.deepEqual(result.data.sections.map((s) => s.name), ['.text', '.rdata']);
  assert.equal(result.data.imports.dllCount, 1);
  assert.equal(result.data.imports.functionCount, 2);
  assert.equal(result.data.imports.libraries[0].name, 'KERNEL32.dll');
  assert.deepEqual(result.data.imports.libraries[0].sample, ['CreateFileW', 'DeleteFileW']);
  assert.equal(result.data.exports.namedExportCount, 2);
  assert.equal(result.data.exports.moduleName, 'test.dll');
  assert.deepEqual(result.data.exports.sample.map((e) => e.name), ['ExportedFn', 'AnotherExport']);
  assert.equal(result.data.overlay.present, true);
  assert.equal(result.data.overlay.offset, 0x800);
  assert.equal(result.data.overlay.size, 0x40);
  assert.equal(result.data.packer.detected, false);
  assert.match(result.data.hashes.md5, /^[0-9a-f]{32}$/);
  assert.match(result.data.hashes.sha256, /^[0-9a-f]{64}$/);
  assert.equal(result.data.hashes.sha256.length, 64);
  assert.ok(typeof result.summary === 'string' && result.summary.includes('PE'));
  assert.ok(Array.isArray(result.findings));
  assert.ok(result.findings.some((f) => f.title.includes('overlay') && f.verification === 'observed'));
});

test('binary.identify: ELF fields, build-id, dynamic imports', async () => {
  const elf = buildElf();
  const result = await runCap('binary.identify', inputFor(elf, {}, { maxStrings: 100 }));
  assert.equal(result.data.format, 'elf');
  assert.equal(result.data.arch, 'x86-64');
  assert.equal(result.data.bits, 64);
  assert.equal(result.data.endianness, 'little');
  assert.equal(result.data.type, 'executable');
  assert.equal(result.data.machine, 'x86-64');
  assert.equal(result.data.entryPoint, '0x401000');
  assert.equal(result.data.buildId, 'deadbeefcafebabe');
  assert.deepEqual(result.data.dynamic.needed, ['libc.so.6']);
  assert.ok(result.data.imports.sample.includes('puts'), `expected puts import, got ${JSON.stringify(result.data.imports.sample)}`);
  assert.ok(result.data.exports.sample.includes('main'));
  assert.equal(result.data.sectionCount, 9);
  assert.equal(result.data.programHeaderCount, 2);
  assert.ok(result.summary.includes('ELF'));
});

test('binary.identify: thin Mach-O, fat/java detection and unknown input', async () => {
  const macho = buildMachO();
  const result = await runCap('binary.identify', inputFor(macho));
  assert.equal(result.data.format, 'macho');
  assert.equal(result.data.container, 'macho-thin');
  assert.equal(result.data.arch, 'x86-64');
  assert.equal(result.data.bits, 64);
  assert.equal(result.data.type, 'execute');
  assert.equal(result.data.entryPoint, '0x150');
  assert.equal(result.data.uuid, '00112233-4455-6677-8899-AABBCCDDEEFF');
  assert.ok(result.data.imports.dylibs.includes('/usr/lib/libSystem.B.dylib'));
  assert.ok(result.data.imports.sample.includes('_printf'));
  assert.ok(result.data.exports.sample.includes('main'));

  // Java class collision: CAFEBABE must not be parsed as fat Mach-O.
  const javaClass = Buffer.alloc(64, 0);
  javaClass.writeUInt32BE(0xcafebabe, 0);
  javaClass.writeUInt16BE(0, 4);
  javaClass.writeUInt16BE(52, 6);
  const javaResult = await runCap('binary.identify', inputFor(javaClass));
  assert.equal(javaResult.data.format, 'other');
  assert.equal(javaResult.data.container, 'java-class');

  const random = Buffer.from(Array.from({ length: 300 }, (_, i) => (i * 37 + 11) & 0xff));
  const unknownResult = await runCap('binary.identify', inputFor(random));
  assert.equal(unknownResult.data.format, 'unknown');
  assert.equal(unknownResult.data.container, 'unrecognized');
});

test('binary.identify: malformed/truncated PE and ELF return structured results without crashing', async () => {
  const truncatedPe = Buffer.alloc(0x40);
  truncatedPe.write('MZ', 0, 'latin1');
  truncatedPe.writeUInt32LE(0x80, 0x3c); // e_lfanew beyond file end
  const peResult = await runCap('binary.identify', inputFor(truncatedPe));
  assert.equal(peResult.data.format, 'unknown');
  assert.equal(peResult.data.container, 'mz-dos');

  const corruptPe = buildPe();
  corruptPe.writeUInt16LE(0xffff, 0x86); // absurd section count
  const corruptResult = await runCap('binary.identify', inputFor(corruptPe));
  assert.equal(corruptResult.data.format, 'pe');
  assert.ok(Array.isArray(corruptResult.data.warnings));

  const truncatedElf = buildElf().subarray(0, 20);
  const elfResult = await runCap('binary.identify', inputFor(truncatedElf));
  assert.equal(elfResult.data.format, 'elf');
  assert.ok(elfResult.data.parseError, 'truncated ELF should carry parseError');

  const bogusElf = buildElf();
  bogusElf.writeBigUInt64LE(0xffffffffn, 40); // e_shoff beyond file
  const bogusResult = await runCap('binary.identify', inputFor(bogusElf));
  assert.equal(bogusResult.data.format, 'elf');
  assert.ok(Array.isArray(bogusResult.data.warnings));
});

test('binary.identify: empty inputs throw actionable Errors', async () => {
  await assert.rejects(
    () => runCap('binary.identify', inputFor(Buffer.alloc(0))),
    (err) => {
      assert.ok(err instanceof Error);
      assert.match(err.message, /0 字节|缺少可分析字节/);
      assert.match(err.message, /targetPath/);
      return true;
    },
  );
  await assert.rejects(
    () => runCap('binary.identify', { targetPath: null, buffer: null, text: null, options: {}, limits: {}, env: {} }),
    /缺少可分析字节/,
  );
});

test('binary.identify: deterministic output (same input -> identical JSON)', async () => {
  const pe = buildPe();
  const a = await runCap('binary.identify', inputFor(pe));
  const b = await runCap('binary.identify', inputFor(pe));
  assert.equal(JSON.stringify(a), JSON.stringify(b));
});

test('binary.strings: ASCII/UTF-16 extraction and categorization', async () => {
  const pe = buildPe();
  const result = await runCap('binary.strings', inputFor(pe, { minLength: 4 }));
  const counts = result.data.categoryCounts;
  assert.equal(counts.url, 1);
  assert.equal(counts.registryKey, 1);
  assert.ok(counts.ipv4 >= 0);
  assert.ok(counts.winapi >= 1, JSON.stringify(counts));
  assert.ok(result.data.counts.ascii > 0);
  assert.ok(result.data.counts.utf16le >= 1);
  const values = result.data.strings.map((s) => s.value);
  assert.ok(values.some((v) => v.includes('http://evil.example.com/payload')));
  assert.ok(values.some((v) => v.includes('SecretWideString')), 'UTF-16LE wide string should be extracted');
  const urlSamples = result.data.categorySamples.url;
  assert.equal(urlSamples[0].value, 'http://evil.example.com/payload');
  // command-related finding is not triggered by this fixture (no powershell string)
  assert.ok(Array.isArray(result.findings));
  // minLength filters shorter strings
  const filtered = await runCap('binary.strings', inputFor(pe, { minLength: 24 }));
  assert.ok(filtered.data.categoryCounts.url === 1, 'long URL still present');
  assert.equal(filtered.data.categoryCounts.winapi, 0, 'short winapi ASCII string is below minLength');
  // control characters never survive in excerpts
  const evil = Buffer.from('http://a.example.com/ok\u0007\u0000tail', 'latin1');
  const evilResult = await runCap('binary.strings', inputFor(evil));
  assert.ok(evilResult.data.categorySamples.url.every((s) => !/[\u0000-\u0008]/.test(s.value)));
});

test('binary.strings: shell command and persistence strings produce hypothesis findings', async () => {
  const buf = Buffer.from(
    'powershell -enc AAAA Invoke-Expression DownloadString '
    + 'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\x '
    + 'user@example.org http://198.51.100.7/gate.php',
    'latin1',
  );
  const result = await runCap('binary.strings', inputFor(buf));
  assert.ok(result.data.categoryCounts.command >= 2, JSON.stringify(result.data.categoryCounts));
  assert.equal(result.data.categoryCounts.email, 1);
  assert.equal(result.data.categoryCounts.url, 1);
  const titles = result.findings.map((f) => f.title).join('\n');
  assert.match(titles, /命令执行/);
  assert.match(titles, /注册表路径/);
  for (const f of result.findings) {
    assert.ok(['critical', 'high', 'medium', 'low', 'info'].includes(f.severity));
    assert.ok(['observed', 'corroborated', 'hypothesis', 'unverified'].includes(f.verification));
    assert.ok(f.method.length > 0);
    assert.ok(f.remediation.length > 0);
    assert.equal(f.cvss, null);
  }
});

test('binary.entropy: zero buffer, high-entropy buffer and bounded block map', async () => {
  const zeros = await runCap('binary.entropy', inputFor(Buffer.alloc(8192)));
  assert.equal(zeros.data.overall.entropy, 0);
  assert.equal(zeros.data.overall.classification, 'mostly-empty');
  assert.equal(zeros.data.overall.stats.zeroByteRatio, 1);
  assert.equal(zeros.data.likelyPackedOrEncrypted, false);

  const pseudoRandom = Buffer.alloc(8192);
  for (let i = 0; i < pseudoRandom.length; i += 1) pseudoRandom[i] = (i * 2654435761) >>> 24;
  const high = await runCap('binary.entropy', inputFor(pseudoRandom, { blockSize: 512, maxBlocks: 16 }));
  assert.ok(high.data.overall.entropy > 7.5, `expected high entropy, got ${high.data.overall.entropy}`);
  assert.equal(high.data.overall.classification, 'very-high');
  assert.equal(high.data.likelyPackedOrEncrypted, true);
  assert.ok(high.data.blockCount <= 16);
  assert.equal(high.data.blockSize, 512);
  assert.equal(entropyOf(Buffer.alloc(100)), 0);

  const pe = buildPe();
  const peEntropy = await runCap('binary.entropy', inputFor(pe, { blockSize: 256, maxBlocks: 8 }));
  assert.ok(peEntropy.data.sectionEntropies.length >= 2);
  const textSection = peEntropy.data.sectionEntropies.find((s) => s.name === '.text');
  assert.ok(textSection && typeof textSection.entropy === 'number');
  assert.ok(textSection.entropy >= 0 && textSection.entropy <= 8);
  assert.ok(Array.isArray(peEntropy.data.blocks));
});

test('binary.headers: PE optional header, directories, hardening flags', async () => {
  const pe = buildPe();
  const result = await runCap('binary.headers', inputFor(pe));
  assert.equal(result.data.format, 'pe');
  assert.equal(result.data.coffHeader.machineName, 'x86-64');
  assert.equal(result.data.coffHeader.numberOfSections, 2);
  assert.equal(result.data.optionalHeader.bits, 64);
  assert.equal(result.data.optionalHeader.pe32Plus, true);
  assert.equal(result.data.optionalHeader.magic, '0x20b');
  assert.equal(result.data.optionalHeader.imageBase, '0x140000000');
  assert.equal(result.data.optionalHeader.entryPointRva, 0x1000);
  assert.equal(result.data.optionalHeader.subsystemName, 'windows-console');
  assert.equal(result.data.dataDirectories.length, 16);
  assert.equal(result.data.dataDirectories[0].name, 'export');
  assert.equal(result.data.dataDirectories[0].present, true);
  assert.equal(result.data.dataDirectories[1].name, 'import');
  assert.equal(result.data.hardening.aslr, true);
  assert.equal(result.data.hardening.dep, true);
  assert.equal(result.data.hardening.cfg, false);
  const fl = result.data.sectionFlags.find((s) => s.name === '.text');
  assert.ok(fl.characteristicFlags.includes('execute'));
});

test('binary.headers: ELF program headers and Mach-O load commands', async () => {
  const elf = await runCap('binary.headers', inputFor(buildElf()));
  assert.equal(elf.data.format, 'elf');
  assert.equal(elf.data.header.machineName, 'x86-64');
  assert.equal(elf.data.header.typeName, 'executable');
  assert.equal(elf.data.programHeaders.length, 2);
  assert.equal(elf.data.programHeaders[0].typeName, 'load');
  assert.equal(elf.data.programHeaders[1].typeName, 'note');
  assert.equal(elf.data.buildId, 'deadbeefcafebabe');
  assert.equal(elf.data.identity.classBits, 64);
  assert.equal(elf.data.hardening.nx, false);

  const macho = await runCap('binary.headers', inputFor(buildMachO()));
  assert.equal(macho.data.format, 'macho');
  assert.equal(macho.data.header.arch, 'x86-64');
  const cmdNames = macho.data.loadCommands.map((c) => c.command);
  for (const expected of ['LC_SEGMENT_64', 'LC_MAIN', 'LC_LOAD_DYLIB', 'LC_UUID', 'LC_FUNCTION_STARTS', 'LC_SYMTAB']) {
    assert.ok(cmdNames.includes(expected), `missing ${expected} in ${cmdNames.join(',')}`);
  }
  assert.equal(macho.data.segments[0].name, '__TEXT');
  assert.equal(macho.data.uuid, '00112233-4455-6677-8899-AABBCCDDEEFF');

  const unknown = await runCap('binary.headers', inputFor(Buffer.from('not an executable at all', 'latin1')));
  assert.ok([...Object.keys(unknown.data)].includes('note'));
  assert.match(unknown.summary, /不是 PE\/ELF\/Mach-O/);
});

test('binary.structure: ELF symbols, PE exports and Mach-O function starts', async () => {
  const elf = await runCap('binary.structure', inputFor(buildElf(), { maxSymbols: 50 }));
  assert.equal(elf.data.format, 'elf');
  const elfNames = elf.data.functions.map((f) => f.name);
  assert.ok(elfNames.includes('main'), JSON.stringify(elfNames));
  assert.ok(elfNames.includes('helper'));
  assert.equal(elf.data.counts.symtabFunctions, 2);
  assert.ok(elf.data.imports.includes('puts'));
  const dynNames = elf.data.dynamicFunctions.map((f) => f.name);
  assert.ok(dynNames.includes('main'));
  assert.equal(elf.data.buildId, 'deadbeefcafebabe');
  assert.equal(elf.data.functionEstimate.count, 2);

  const peStruct = await runCap('binary.structure', inputFor(buildPe()));
  assert.equal(peStruct.data.format, 'pe');
  assert.equal(peStruct.data.counts.exportFunctions, 2);
  assert.deepEqual(peStruct.data.exports.map((e) => e.name), ['ExportedFn', 'AnotherExport']);
  assert.equal(peStruct.data.exceptionDirectory.present, false);
  assert.equal(peStruct.data.functionEstimate.verification, 'hypothesis');
  assert.equal(peStruct.data.functionEstimate.count, 2);

  const macho = await runCap('binary.structure', inputFor(buildMachO()));
  assert.equal(macho.data.format, 'macho');
  assert.equal(macho.data.slices.length, 1);
  const slice = macho.data.slices[0];
  assert.equal(slice.arch, 'x86-64');
  assert.equal(slice.functionStarts.entryCount, 2);
  assert.deepEqual(slice.functionStarts.firstAddresses, ['0x100000010', '0x100000030']);
  assert.ok(slice.counts.undefinedImports >= 1);
  assert.ok(slice.counts.definedExports >= 1);

  const random = await runCap('binary.structure', inputFor(Buffer.from('plain text, not a container', 'latin1')));
  assert.equal(random.data.format, 'unknown');
  assert.match(random.data.note, /不是 PE\/ELF\/Mach-O/);
});

test('binary.structure: PE exception directory is summarized when present', async () => {
  const pe = buildPe();
  // add an exception data directory (index 3): rva 0x2000, size 36 -> 3 RUNTIME_FUNCTION records
  pe.writeUInt32LE(0x2000, 0x108 + 3 * 8);
  pe.writeUInt32LE(36, 0x108 + 3 * 8 + 4);
  const result = await runCap('binary.structure', inputFor(pe));
  assert.equal(result.data.exceptionDirectory.present, true);
  assert.equal(result.data.exceptionDirectory.recordSize, 12);
  assert.equal(result.data.exceptionDirectory.approxCount, 3);
  assert.ok(result.findings.some((f) => f.title.includes('RUNTIME_FUNCTION')));
});

test('binary: long loops cooperate with AbortSignal', async () => {
  const controller = new AbortController();
  controller.abort();
  const input = inputFor(buildPe(), {}, {}, { signal: controller.signal });
  for (const cap of manifest.capabilities) {
    await assert.rejects(() => cap.run(input), /中止/, `${cap.id} must honor abort signal`);
  }
});

test('binary: helper parsers agree with container detection and never throw on garbage', () => {
  const pe = buildPe();
  const peParsed = parsePe(pe);
  assert.equal(peParsed.ok, true);
  assert.equal(peParsed.coff.machineName, 'x86-64');
  assert.equal(peParsed.overlay.size, 0x40);
  assert.equal(parsePe(Buffer.alloc(10)).ok, false);

  const elfParsed = parseElf(buildElf());
  assert.equal(elfParsed.ok, true);
  assert.equal(elfParsed.buildId, 'deadbeefcafebabe');
  assert.equal(parseElf(Buffer.alloc(10)).ok, false);

  const machoParsed = parseMachO(buildMachO());
  assert.equal(machoParsed.ok, true);
  assert.equal(machoParsed.slices[0].entryPoint, '0x150');
  assert.equal(parseMachO(Buffer.alloc(10)).ok, false);
  assert.equal(parseMachO(Buffer.from([0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x34])).ok, false);

  const garbage = Buffer.from(Array.from({ length: 4096 }, (_, i) => (i * 131 + 7) & 0xff));
  assert.doesNotThrow(() => parsePe(garbage));
  assert.doesNotThrow(() => parseElf(garbage));
  assert.doesNotThrow(() => parseMachO(garbage));
  assert.equal(detectContainer(garbage).format, 'unknown');
});

test('binary.behavior: aggregates suspicious API categories and stays hypothesis-level', async () => {
  const pe = buildPe();
  const result = await runCap('binary.behavior', inputFor(pe));
  assert.equal(result.data.format, 'pe');
  assert.equal(result.data.verification, 'hypothesis');
  assert.ok(result.data.categoryCount >= 1, 'fixture exposes at least one suspicious API category');
  assert.ok(result.data.categories['file-collection']?.some((name) => /CreateFileW/i.test(name)));
  assert.ok(result.data.score > 0);
  assert.ok(result.findings.length >= 1);
  assert.equal(result.findings[0].verification, 'hypothesis');
  assert.ok(Array.isArray(result.data.limitations) && result.data.limitations.length >= 2);
  const again = await runCap('binary.behavior', inputFor(pe));
  assert.deepEqual(again.data.categories, result.data.categories);
  assert.equal(again.data.score, result.data.score);
  await assert.rejects(() => runCap('binary.behavior', inputFor(Buffer.alloc(0))));
});
