/**
 * Binary domain — ELF parser (pure, defensive, bounded). Zero dependencies.
 * Parses 32/64-bit, little/big-endian ELF images. Never executes sample code.
 */
import { hex, readAsciiZ, sanitizeText } from './util.js';

const MACHINES = new Map([
  [0, 'none'], [2, 'sparc'], [3, 'x86'], [4, 'm68k'], [5, 'm88k'], [7, 'i860'],
  [8, 'mips'], [15, 'parisc'], [18, 'sparc32plus'], [20, 'ppc'], [21, 'ppc64'],
  [22, 's390'], [40, 'arm'], [41, 'alpha'], [42, 'sh'], [43, 'sparcv9'], [50, 'ia64'],
  [62, 'x86-64'], [183, 'aarch64'], [243, 'riscv'], [247, 'bpf'], [258, 'loongarch'],
]);

const TYPES = new Map([
  [0, 'none'], [1, 'relocatable'], [2, 'executable'], [3, 'shared-object'],
  [4, 'core'], [0xfe00, 'os-specific-lo'], [0xfeff, 'os-specific-hi'],
  [0xff00, 'processor-specific-lo'], [0xffff, 'processor-specific-hi'],
]);

const OSABI = new Map([
  [0, 'sysv'], [1, 'hpux'], [2, 'netbsd'], [3, 'linux'], [6, 'solaris'], [7, 'aix'],
  [8, 'irix'], [9, 'freebsd'], [10, 'tru64'], [11, 'modesto'], [12, 'openbsd'],
  [13, 'openvms'], [14, 'nsk'], [15, 'aros'], [16, 'fenixos'], [17, 'cloudabi'],
  [18, 'openc2e'], [64, 'arm-eabi'], [97, 'arm'], [255, 'standalone'],
]);

const SECTION_TYPES = new Map([
  [0, 'null'], [1, 'progbits'], [2, 'symtab'], [3, 'strtab'], [4, 'rela'],
  [5, 'hash'], [6, 'dynamic'], [7, 'note'], [8, 'nobits'], [9, 'rel'],
  [10, 'shlib'], [11, 'dynsym'], [14, 'init-array'], [15, 'fini-array'],
  [16, 'preinit-array'], [17, 'group'], [18, 'symtab-shndx'], [19, 'relr'],
  [0x6ffffff6, 'gnu-hash'], [0x6ffffffd, 'gnu-verdef'], [0x6ffffffe, 'gnu-verneed'],
  [0x6fffffff, 'gnu-versym'], [0x70000000, 'proc-specific'],
]);

const PROGRAM_TYPES = new Map([
  [0, 'null'], [1, 'load'], [2, 'dynamic'], [3, 'interp'], [4, 'note'],
  [5, 'shlib'], [6, 'phdr'], [7, 'tls'], [0x6474e550, 'gnu-eh-frame'],
  [0x6474e551, 'gnu-stack'], [0x6474e552, 'gnu-relro'], [0x6474e553, 'gnu-property'],
]);

const SYMBOL_TYPES = new Map([
  [0, 'notype'], [1, 'object'], [2, 'func'], [3, 'section'], [4, 'file'],
  [5, 'common'], [6, 'tls'], [10, 'gnu-ifunc'], [13, 'gnu-indirect-func'],
]);

const DT = new Map([
  [0, 'null'], [1, 'needed'], [2, 'pltrelsz'], [3, 'pltgot'], [4, 'hash'],
  [5, 'strtab'], [6, 'symtab'], [7, 'rela'], [8, 'relasz'], [9, 'relaent'],
  [10, 'strsz'], [11, 'syment'], [12, 'init'], [13, 'fini'], [14, 'soname'],
  [15, 'rpath'], [16, 'symbolic'], [17, 'rel'], [18, 'relsz'], [19, 'relent'],
  [20, 'pltrel'], [21, 'debug'], [22, 'textrel'], [23, 'jmprel'], [24, 'bind-now'],
  [25, 'init-array'], [26, 'fini-array'], [27, 'init-arraysz'], [28, 'fini-arraysz'],
  [29, 'runpath'], [30, 'flags'], [32, 'preinit-array'], [33, 'preinit-arraysz'],
  [0x6ffffef5, 'gnu-hash'], [0x6ffffff0, 'versym'], [0x6ffffff9, 'relacount'],
  [0x6ffffffb, 'flags-1'], [0x6ffffffe, 'verneed'], [0x6fffffff, 'versym2'],
]);

const NOTE_TYPES = new Map([
  [1, 'gnu-abi-tag'], [2, 'gnu-hwcaps'], [3, 'gnu-build-id'], [4, 'gnu-gold-version'],
  [5, 'gnu-property'], [0x100, 'android-ident'], [0x101, 'android-kernel-version'],
]);

function u16At(buffer, off, le) {
  if (off < 0 || off + 2 > buffer.length) return null;
  return le ? buffer.readUInt16LE(off) : buffer.readUInt16BE(off);
}
function u32At(buffer, off, le) {
  if (off < 0 || off + 4 > buffer.length) return null;
  return le ? buffer.readUInt32LE(off) : buffer.readUInt32BE(off);
}
function u64At(buffer, off, le) {
  if (off < 0 || off + 8 > buffer.length) return null;
  return le ? buffer.readBigUInt64LE(off) : buffer.readBigUInt64BE(off);
}
function toSafe(big) {
  if (big === null || big === undefined) return null;
  if (big > BigInt(Number.MAX_SAFE_INTEGER)) return null;
  return Number(big);
}
function readAddr(buffer, off, bits, le) {
  const raw = bits === 64 ? u64At(buffer, off, le) : u32At(buffer, off, le);
  if (raw === null) return null;
  return typeof raw === 'bigint' ? { value: raw, safe: toSafe(raw) } : { value: BigInt(raw), safe: raw };
}

/** Cheap ELF identification (used for format detection). */
export function detectElf(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 16) return { isElf: false, reason: '不足 16 字节，无法包含 ELF 标识。' };
  if (buffer[0] !== 0x7f || buffer[1] !== 0x45 || buffer[2] !== 0x4c || buffer[3] !== 0x46) {
    return { isElf: false, reason: 'offset 0 不是 7F 45 4C 46（\\x7fELF）。' };
  }
  const classBits = buffer[4] === 1 ? 32 : buffer[4] === 2 ? 64 : null;
  const endianness = buffer[5] === 1 ? 'little' : buffer[5] === 2 ? 'big' : null;
  return { isElf: true, classBits, endianness, osabi: buffer[7], version: buffer[6] };
}

function parseNotes(buffer, start, size, warnings, noteList, seenOffsets, le) {
  let off = start;
  const end = Math.min(buffer.length, start + size);
  let guard = 0;
  while (off + 12 <= end && guard < 64) {
    guard += 1;
    const namesz = u32At(buffer, off, le);
    const descsz = u32At(buffer, off + 4, le);
    const type = u32At(buffer, off + 8, le);
    if (namesz === null || descsz === null || type === null) break;
    if (namesz > 4096 || descsz > 65536) {
      warnings.push(`ELF note 头长度异常（namesz=${namesz}, descsz=${descsz}），停止解析该 note 段。`);
      break;
    }
    const nameOff = off + 12;
    const nameEnd = nameOff + namesz;
    const descOff = nameOff + Math.ceil(namesz / 4) * 4;
    const descEnd = descOff + descsz;
    if (descEnd > end + 4) break;
    const rawName = buffer.subarray(nameOff, Math.min(nameEnd, buffer.length));
    const name = rawName.toString('latin1').replace(/\u0000+$/, '');
    const desc = buffer.subarray(descOff, Math.min(descEnd, buffer.length));
    const key = `${start}:${off}`;
    if (!seenOffsets.has(key)) {
      seenOffsets.add(key);
      const note = {
        name: sanitizeText(name, 64),
        type,
        typeName: NOTE_TYPES.get(type) || `type-${type}`,
        descSize: descsz,
      };
      if (name === 'GNU' && type === 3 && desc.length >= 4) {
        note.buildId = desc.subarray(0, 512).toString('hex');
        note.kind = 'build-id';
      } else if (name === 'Go' || name === 'Go\\x00') {
        note.kind = 'go-note';
        note.descHex = desc.subarray(0, 32).toString('hex');
      } else if (desc.length <= 64 && desc.length > 0) {
        note.descHex = desc.toString('hex');
      }
      noteList.push(note);
    }
    off = descOff + Math.ceil(descsz / 4) * 4;
  }
}

/**
 * Parse ELF. Returns { ok:false, reason } for non-ELF or unusable headers;
 * otherwise a structured model with warnings for truncation/oddities.
 */
export function parseElf(buffer, opts = {}) {
  const warnings = [];
  const buf = Buffer.isBuffer(buffer) ? buffer : Buffer.alloc(0);
  if (buf.length < 52) return { ok: false, reason: '文件小于 52 字节，不可能是 ELF 文件。', warnings };
  if (buf[0] !== 0x7f || buf[1] !== 0x45 || buf[2] !== 0x4c || buf[3] !== 0x46) {
    return { ok: false, reason: '缺少 ELF 魔数（\\x7fELF）。', warnings };
  }
  const classByte = buf[4];
  const dataByte = buf[5];
  if (classByte !== 1 && classByte !== 2) return { ok: false, reason: `EI_CLASS=${classByte} 非法（应为 1=32 位或 2=64 位）。`, warnings };
  if (dataByte !== 1 && dataByte !== 2) return { ok: false, reason: `EI_DATA=${dataByte} 非法（应为 1=小端或 2=大端）。`, warnings };
  const bits = classByte === 2 ? 64 : 32;
  const littleEndian = dataByte === 1;
  const e = littleEndian;
  if (buf.length < (bits === 64 ? 64 : 52)) {
    return { ok: false, reason: `ELF ${bits} 位头需要 ${bits === 64 ? 64 : 52} 字节，实际仅 ${buf.length} 字节（文件被截断）。`, warnings };
  }
  const identity = {
    classBits: bits,
    endianness: littleEndian ? 'little' : 'big',
    version: buf[6],
    osabi: buf[7],
    osabiName: OSABI.get(buf[7]) || `osabi-${buf[7]}`,
    abiVersion: buf[8],
  };
  const eType = u16At(buf, 16, e);
  const eMachine = u16At(buf, 18, e);
  const eVersion = u32At(buf, 20, e);
  const entry = readAddr(buf, 24, bits, e);
  const phoff = readAddr(buf, 24 + (bits === 64 ? 8 : 4), bits, e);
  const shoff = readAddr(buf, 24 + (bits === 64 ? 16 : 8), bits, e);
  const flagOff = 24 + (bits === 64 ? 24 : 12);
  const eFlags = u32At(buf, flagOff, e);
  const ehsize = u16At(buf, flagOff + 4, e);
  const phentsize = u16At(buf, flagOff + 6, e);
  const phnum = u16At(buf, flagOff + 8, e);
  const shentsize = u16At(buf, flagOff + 10, e);
  const shnum = u16At(buf, flagOff + 12, e);
  const shstrndx = u16At(buf, flagOff + 14, e);
  const header = {
    type: eType,
    typeName: TYPES.get(eType) || `type-0x${Number(eType).toString(16)}`,
    machine: eMachine,
    machineName: MACHINES.get(eMachine) || `machine-${eMachine}`,
    version: eVersion,
    entryPoint: entry === null ? null : hex(entry.value),
    entryPointNumeric: entry === null ? null : entry.safe,
    phoff: phoff === null ? null : phoff.safe,
    shoff: shoff === null ? null : shoff.safe,
    flags: eFlags,
    elfHeaderSize: ehsize,
    programHeaderEntrySize: phentsize,
    programHeaderCount: phnum,
    sectionHeaderEntrySize: shentsize,
    sectionHeaderCount: shnum,
    sectionNameStringTableIndex: shstrndx,
  };
  if (ehsize !== null && ehsize !== (bits === 64 ? 64 : 52)) {
    warnings.push(`ELF e_ehsize=${ehsize} 与标准 ${bits === 64 ? 64 : 52} 不一致，按标准布局继续解析。`);
  }

  // ---- Program headers ----
  const programHeaders = [];
  const maxPh = Math.min(phnum || 0, 256, Number.isFinite(opts.maxProgramHeaders) ? opts.maxProgramHeaders : 256);
  const phSize = bits === 64 ? 56 : 32;
  if (phnum && phoff && phoff.safe !== null) {
    const actualEntSize = phentsize || phSize;
    if (actualEntSize < phSize) warnings.push(`ELF 程序头条目大小 ${actualEntSize} 小于标准 ${phSize}，按标准解析。`);
    for (let i = 0; i < maxPh; i += 1) {
      const off = phoff.safe + i * actualEntSize;
      if (off + phSize > buf.length) { warnings.push(`程序头表在索引 ${i} 处被截断。`); break; }
      const pType = u32At(buf, off, e);
      let rec;
      if (bits === 64) {
        const pFlags = u32At(buf, off + 4, e);
        const pOffset = readAddr(buf, off + 8, 64, e);
        const pVaddr = readAddr(buf, off + 16, 64, e);
        const pPaddr = readAddr(buf, off + 24, 64, e);
        const pFilesz = readAddr(buf, off + 32, 64, e);
        const pMemsz = readAddr(buf, off + 40, 64, e);
        const pAlign = readAddr(buf, off + 48, 64, e);
        rec = { type: pType, flags: pFlags, offset: pOffset && pOffset.safe, vaddr: pVaddr, paddr: pPaddr, filesz: pFilesz, memsz: pMemsz, align: pAlign };
      } else {
        const pOffset = readAddr(buf, off + 4, 32, e);
        const pVaddr = readAddr(buf, off + 8, 32, e);
        const pPaddr = readAddr(buf, off + 12, 32, e);
        const pFilesz = readAddr(buf, off + 16, 32, e);
        const pMemsz = readAddr(buf, off + 20, 32, e);
        const pFlags = u32At(buf, off + 24, e);
        const pAlign = readAddr(buf, off + 28, 32, e);
        rec = { type: pType, flags: pFlags, offset: pOffset && pOffset.safe, vaddr: pVaddr, paddr: pPaddr, filesz: pFilesz, memsz: pMemsz, align: pAlign };
      }
      const name = PROGRAM_TYPES.get(pType) || `pt-0x${Number(pType).toString(16)}`;
      programHeaders.push({
        index: i,
        type: pType,
        typeName: name,
        flags: rec.flags,
        flagNames: bits === 64 ? flagsProgramNames(rec.flags) : flagsProgramNames(rec.flags),
        offset: rec.offset,
        vaddr: rec.vaddr ? hex(rec.vaddr.value) : null,
        paddr: rec.paddr ? hex(rec.paddr.value) : null,
        filesz: rec.filesz ? hex(rec.filesz.value) : null,
        fileszNumeric: rec.filesz ? rec.filesz.safe : null,
        memsz: rec.memsz ? hex(rec.memsz.value) : null,
        align: rec.align ? hex(rec.align.value) : null,
      });
    }
  } else if (phnum) {
    warnings.push('ELF 声明了程序头但 e_phoff 无法映射到文件，跳过程序头表。');
  }

  // ---- Section headers ----
  const sections = [];
  const shSize = bits === 64 ? 64 : 40;
  if (shnum && shoff && shoff.safe !== null) {
    const actualEntSize = shentsize || shSize;
    const maxSh = Math.min(shnum, 512);
    for (let i = 0; i < maxSh; i += 1) {
      const off = shoff.safe + i * actualEntSize;
      if (off + shSize > buf.length) { warnings.push(`节头表在索引 ${i} 处被截断。`); break; }
      const nameIdx = u32At(buf, off, e);
      const shType = u32At(buf, off + 4, e);
      let rec;
      let link;
      let info;
      let entsize;
      if (bits === 64) {
        const flags = readAddr(buf, off + 8, 64, e);
        const addr = readAddr(buf, off + 16, 64, e);
        const offset = readAddr(buf, off + 24, 64, e);
        const size = readAddr(buf, off + 32, 64, e);
        link = u32At(buf, off + 40, e);
        info = u32At(buf, off + 44, e);
        const align = readAddr(buf, off + 48, 64, e);
        entsize = readAddr(buf, off + 56, 64, e);
        rec = { flags, addr, offset, size, align };
      } else {
        const flags = readAddr(buf, off + 8, 32, e);
        const addr = readAddr(buf, off + 12, 32, e);
        const offset = readAddr(buf, off + 16, 32, e);
        const size = readAddr(buf, off + 20, 32, e);
        link = u32At(buf, off + 24, e);
        info = u32At(buf, off + 28, e);
        const align = readAddr(buf, off + 32, 32, e);
        entsize = readAddr(buf, off + 36, 32, e);
        rec = { flags, addr, offset, size, align };
      }
      const section = {
        index: i,
        name: null,
        nameOffset: nameIdx,
        type: shType,
        typeName: SECTION_TYPES.get(shType) || `sh-0x${Number(shType).toString(16)}`,
        flags: rec.flags ? hex(rec.flags.value) : null,
        flagNames: sectionFlagNames(rec.flags ? rec.flags.value : null),
        addr: rec.addr ? hex(rec.addr.value) : null,
        offset: rec.offset ? rec.offset.safe : null,
        size: rec.size ? hex(rec.size.value) : '0x0',
        sizeNumeric: rec.size ? rec.size.safe : null,
        link,
        info,
        align: rec.align ? hex(rec.align.value) : null,
        entsize: entsize ? hex(entsize.value) : null,
      };
      sections.push(section);
    }
    // resolve names via shstrtab
    const shstrIndex = Number.isFinite(shstrndx) ? shstrndx : -1;
    if (shstrIndex >= 0 && shstrIndex < sections.length) {
      const strSection = sections[shstrIndex];
      if (strSection.type === 3 && strSection.offset !== null && strSection.sizeNumeric !== null) {
        const strStart = strSection.offset;
        const strEnd = Math.min(buf.length, strStart + strSection.sizeNumeric);
        for (const s of sections) {
          if (s.nameOffset === null || s.nameOffset === 0) { s.name = ''; continue; }
          const abs = strStart + s.nameOffset;
          s.name = abs < strEnd ? (readAsciiZ(buf, abs, 256) || '') : '';
        }
      } else {
        warnings.push('e_shstrndx 指向的节不是字符串表，节名不可用。');
      }
    } else if (shstrndx !== 0) {
      warnings.push(`e_shstrndx=${shstrndx} 超出已解析节表范围，节名不可用。`);
    }
  } else if (shnum) {
    warnings.push('ELF 声明了节头但 e_shoff 无法映射到文件，跳过节表。');
  }

  // ---- Symbol tables (dynsym → imports/exports; symtab → functions) ----
  const symbols = { symtab: { present: false, count: 0, functions: [] }, dynsym: { present: false, count: 0, imports: [], exports: [] }, truncated: false };
  const maxSymbolNames = Math.max(1, Number.isFinite(opts.maxSymbols) ? opts.maxSymbols : 1024);
  const parseSymTable = (section, kind) => {
    if (section.offset === null || section.sizeNumeric === null) return null;
    const strSection = section.link !== null && section.link < sections.length ? sections[section.link] : null;
    if (!strSection || strSection.offset === null || strSection.sizeNumeric === null) {
      warnings.push(`${kind === 'dynsym' ? '.dynsym' : '.symtab'} 的 sh_link 未指向有效字符串表，符号名不可用。`);
      return null;
    }
    const entrySize = bits === 64 ? 24 : 16;
    const count = Math.floor(section.sizeNumeric / entrySize);
    const strStart = strSection.offset;
    const strEnd = Math.min(buf.length, strStart + strSection.sizeNumeric);
    const limit = Math.min(count, 8192);
    const functions = [];
    const imports = [];
    const exports = [];
    let readCount = 0;
    for (let i = 0; i < limit; i += 1) {
      const off = section.offset + i * entrySize;
      if (off + entrySize > buf.length) { warnings.push(`${kind === 'dynsym' ? '.dynsym' : '.symtab'} 在索引 ${i} 处被截断。`); break; }
      readCount += 1;
      const stName = u32At(buf, off, e);
      const stInfo = buf[off + (bits === 64 ? 4 : 12)];
      const stOther = buf[off + (bits === 64 ? 5 : 13)];
      const stShndx = u16At(buf, off + (bits === 64 ? 6 : 14), e);
      const stValue = readAddr(buf, off + (bits === 64 ? 8 : 4), bits, e);
      const stSize = readAddr(buf, off + (bits === 64 ? 16 : 8), bits, e);
      const bind = stInfo >> 4;
      const symType = stInfo & 0x0f;
      const typeName = SYMBOL_TYPES.get(symType) || `st-${symType}`;
      const isFunc = symType === 2 || symType === 10 || symType === 13;
      const isObject = symType === 1;
      if (!isFunc && !isObject) continue;
      const fields = {
        name: null,
        bind,
        bindName: bind === 1 ? 'global' : bind === 2 ? 'weak' : bind === 10 ? 'gnu-unique' : bind === 0 ? 'local' : `bind-${bind}`,
        type: symType,
        typeName,
        visibility: stOther & 0x3,
        sectionIndex: stShndx,
        defined: stShndx !== 0,
        value: stValue ? hex(stValue.value) : null,
        valueNumeric: stValue ? stValue.safe : null,
        size: stSize ? hex(stSize.value) : '0x0',
        sizeNumeric: stSize ? stSize.safe : null,
      };
      if (stName && stName > 0) {
        const abs = strStart + stName;
        fields.name = abs < strEnd ? readAsciiZ(buf, abs, 256) : null;
      }
      if (!fields.name) continue;
      if (isFunc && fields.defined) {
        if (functions.length < maxSymbolNames) functions.push(fields);
      } else if (isFunc && !fields.defined) {
        if (imports.length < maxSymbolNames && (bind !== 0)) imports.push(fields);
      }
      if (isFunc && fields.defined && kind === 'dynsym' && (bind === 1 || bind === 2 || bind === 10)
        && (fields.visibility === 0 || fields.visibility === 3)) {
        if (exports.length < maxSymbolNames) exports.push(fields);
      }
    }
    return { readCount, count, functions, imports, exports };
  };

  for (const section of sections) {
    if (section.type === 11 && !symbols.dynsym.present) {
      const parsed = parseSymTable(section, 'dynsym');
      if (parsed) {
        symbols.dynsym = {
          present: true,
          count: parsed.count,
          readCount: parsed.readCount,
          imports: parsed.imports,
          exports: parsed.exports,
          functionCount: parsed.functions.length,
          sectionIndex: section.index,
        };
        symbols.dynsym.functions = parsed.functions.length > maxSymbolNames ? parsed.functions.slice(0, maxSymbolNames) : parsed.functions;
      }
    } else if (section.type === 2 && !symbols.symtab.present) {
      const parsed = parseSymTable(section, 'symtab');
      if (parsed) {
        symbols.symtab = {
          present: true,
          count: parsed.count,
          readCount: parsed.readCount,
          functions: parsed.functions.slice(0, maxSymbolNames),
          sectionIndex: section.index,
        };
      }
    }
  }

  // ---- Dynamic section (DT_NEEDED / SONAME / RPATH / RUNPATH) ----
  const dynamic = { present: false, needed: [], soname: null, rpath: null, runpath: null };
  const dynSection = sections.find((s) => s.type === 6);
  if (dynSection && dynSection.offset !== null && dynSection.sizeNumeric !== null) {
    dynamic.present = true;
    const entrySize = bits === 64 ? 16 : 8;
    const count = Math.floor(dynSection.sizeNumeric / entrySize);
    const limit = Math.min(count, 4096);
    const strSection = dynSection.link !== null && dynSection.link < sections.length ? sections[dynSection.link] : null;
    const strStart = strSection && strSection.offset !== null ? strSection.offset : null;
    const strEnd = strSection && strSection.offset !== null && strSection.sizeNumeric !== null
      ? Math.min(buf.length, strSection.offset + strSection.sizeNumeric)
      : null;
    const readStr = (val) => {
      if (strStart === null || strEnd === null || val === null) return null;
      const abs = strStart + val;
      return abs < strEnd ? readAsciiZ(buf, abs, 512) : null;
    };
    for (let i = 0; i < limit; i += 1) {
      const off = dynSection.offset + i * entrySize;
      if (off + entrySize > buf.length) { warnings.push('动态段在文件末尾被截断。'); break; }
      let tag;
      let val;
      if (bits === 64) {
        tag = toSafe(e ? buf.readBigUInt64LE(off) : buf.readBigUInt64BE(off));
        val = toSafe(e ? buf.readBigUInt64LE(off + 8) : buf.readBigUInt64BE(off + 8));
      } else {
        tag = e ? buf.readUInt32LE(off) : buf.readUInt32BE(off);
        val = e ? buf.readUInt32LE(off + 4) : buf.readUInt32BE(off + 4);
      }
      if (tag === 0) break;
      if (tag === 1) {
        const lib = readStr(val);
        if (lib) dynamic.needed.push(lib);
      } else if (tag === 14) dynamic.soname = readStr(val);
      else if (tag === 15) dynamic.rpath = readStr(val);
      else if (tag === 29) dynamic.runpath = readStr(val);
      else if (tag === 10) dynamic.strsz = val;
      else if (tag === 5) dynamic.strtabAddr = val === null ? null : `0x${val.toString(16)}`;
    }
    dynamic.needed = [...new Set(dynamic.needed)].slice(0, 64);
  }

  // ---- Notes / build-id ----
  const notes = [];
  const seenNoteOffsets = new Set();
  for (const section of sections) {
    if (section.type !== 7 || section.offset === null || section.sizeNumeric === null) continue;
    parseNotes(buf, section.offset, section.sizeNumeric, warnings, notes, seenNoteOffsets, e);
  }
  for (const ph of programHeaders) {
    if (ph.type !== 4 || ph.offset === null || ph.fileszNumeric === null) continue;
    parseNotes(buf, ph.offset, ph.fileszNumeric, warnings, notes, seenNoteOffsets, e);
  }
  const buildIdNote = notes.find((n) => n.kind === 'build-id');
  const buildId = buildIdNote ? buildIdNote.buildId : null;

  // ---- Interpreter ----
  let interp = null;
  const interpPh = programHeaders.find((p) => p.type === 3);
  if (interpPh && interpPh.offset !== null && interpPh.fileszNumeric !== null) {
    interp = readAsciiZ(buf, interpPh.offset, Math.min(256, interpPh.fileszNumeric));
  }

  const imports = symbols.dynsym.present
    ? symbols.dynsym.imports.map((s) => s.name).filter(Boolean)
    : [];
  const exports = symbols.dynsym.present
    ? symbols.dynsym.exports.map((s) => s.name).filter(Boolean)
    : [];
  const functions = symbols.symtab.present ? symbols.symtab.functions : [];
  const sectionByName = new Map(sections.map((s) => [s.name, s]));
  let interpreterResolved = interp;
  if (!interpreterResolved && sectionByName.has('.interp')) {
    const s = sectionByName.get('.interp');
    if (s.offset !== null && s.sizeNumeric !== null) interpreterResolved = readAsciiZ(buf, s.offset, Math.min(256, s.sizeNumeric));
  }

  return {
    ok: true,
    identity,
    header,
    programHeaders,
    sections,
    symbols,
    dynamic,
    notes,
    buildId,
    interp: interpreterResolved,
    imports,
    exports,
    warnings,
    timestamps: [],
  };
}

function sectionFlagNames(flagsBig) {
  if (flagsBig === null || flagsBig === undefined) return [];
  const flags = typeof flagsBig === 'bigint' ? Number(flagsBig & 0xffffffffn) : Number(flagsBig);
  const list = [];
  if (flags & 0x1) list.push('write');
  if (flags & 0x2) list.push('alloc');
  if (flags & 0x4) list.push('exec');
  if (flags & 0x10) list.push('merge');
  if (flags & 0x20) list.push('strings');
  if (flags & 0x40) list.push('info-link');
  if (flags & 0x80) list.push('link-order');
  if (flags & 0x100) list.push('os-nonconforming');
  if (flags & 0x200) list.push('group');
  if (flags & 0x400) list.push('tls');
  return list;
}

function flagsProgramNames(flags) {
  if (!Number.isFinite(flags)) return [];
  const list = [];
  if (flags & 0x1) list.push('x');
  if (flags & 0x2) list.push('w');
  if (flags & 0x4) list.push('r');
  return list;
}

export { MACHINES as ELF_MACHINES, TYPES as ELF_TYPES, DT as ELF_DYNAMIC_TAGS };
