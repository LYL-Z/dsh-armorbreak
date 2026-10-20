/**
 * Binary domain — Mach-O parser (thin + fat), pure/defensive/bounded. Zero dependencies.
 * Handles 32/64-bit, both endiannesses, and fat (universal) binaries.
 */
import { hex, readAsciiZ, sanitizeText } from './util.js';

const CPU_TYPES = new Map([
  [7, 'x86'],
  [0x01000007, 'x86-64'],
  [12, 'arm'],
  [0x0100000c, 'arm64'],
  [0x0200000c, 'arm64-32'],
  [18, 'ppc'],
  [0x01000012, 'ppc64'],
  [13, 'm68k'],
  [14, 'm88k'],
  [15, 'sparc'],
  [10, 'mc680x0'],
]);

const FILE_TYPES = new Map([
  [1, 'object'], [2, 'execute'], [3, 'fvmlib'], [4, 'core'], [5, 'preload'],
  [6, 'dylib'], [7, 'dylinker'], [8, 'bundle'], [9, 'dylib-stub'], [10, 'dsym'],
  [11, 'kext-bundle'],
]);

const LOAD_COMMANDS = new Map([
  [0x1, 'LC_SEGMENT'], [0x2, 'LC_SYMTAB'], [0x3, 'LC_SYMSEG'], [0x4, 'LC_THREAD'],
  [0x5, 'LC_UNIXTHREAD'], [0x6, 'LC_LOADFVMLIB'], [0x7, 'LC_IDFVMLIB'],
  [0x8, 'LC_IDENT'], [0x9, 'LC_FVMFILE'], [0xa, 'LC_PREPAGE'], [0xb, 'LC_DYSYMTAB'],
  [0xc, 'LC_LOAD_DYLIB'], [0xd, 'LC_ID_DYLIB'], [0xe, 'LC_LOAD_DYLINKER'],
  [0xf, 'LC_ID_DYLINKER'], [0x10, 'LC_PREBOUND_DYLIB'], [0x11, 'LC_ROUTINES'],
  [0x12, 'LC_SUB_FRAMEWORK'], [0x13, 'LC_SUB_UMBRELLA'], [0x14, 'LC_SUB_CLIENT'],
  [0x15, 'LC_SUB_LIBRARY'], [0x16, 'LC_TWOLEVEL_HINTS'], [0x17, 'LC_PREBIND_CKSUM'],
  [0x19, 'LC_SEGMENT_64'], [0x1a, 'LC_ROUTINES_64'], [0x1b, 'LC_UUID'],
  [0x1d, 'LC_CODE_SIGNATURE'], [0x1e, 'LC_SEGMENT_SPLIT_INFO'],
  [0x20, 'LC_LAZY_LOAD_DYLIB'], [0x21, 'LC_ENCRYPTION_INFO'], [0x22, 'LC_DYLD_INFO'],
  [0x24, 'LC_VERSION_MIN_MACOSX'], [0x25, 'LC_VERSION_MIN_IPHONEOS'],
  [0x26, 'LC_FUNCTION_STARTS'], [0x27, 'LC_DYLD_ENVIRONMENT'],
  [0x29, 'LC_DATA_IN_CODE'], [0x2a, 'LC_SOURCE_VERSION'],
  [0x2b, 'LC_DYLIB_CODE_SIGN_DRS'], [0x2c, 'LC_ENCRYPTION_INFO_64'],
  [0x2d, 'LC_LINKER_OPTION'], [0x2e, 'LC_LINKER_OPTIMIZATION_HINT'],
  [0x2f, 'LC_VERSION_MIN_TVOS'], [0x30, 'LC_VERSION_MIN_WATCHOS'],
  [0x31, 'LC_NOTE'], [0x32, 'LC_BUILD_VERSION'],
  [0x80000018, 'LC_LOAD_WEAK_DYLIB'],
  [0x8000001c, 'LC_RPATH'],
  [0x8000001f, 'LC_REEXPORT_DYLIB'],
  [0x80000022, 'LC_DYLD_INFO_ONLY'],
  [0x80000023, 'LC_LOAD_UPWARD_DYLIB'],
  [0x80000028, 'LC_MAIN'],
]);

const DYLIB_COMMANDS = new Set([0xc, 0xd, 0x80000018, 0x8000001f, 0x20, 0x80000023]);

function magicInfo(buffer, offset = 0) {
  if (!Buffer.isBuffer(buffer) || offset + 4 > buffer.length) return null;
  const mag = buffer.readUInt32BE(offset);
  switch (mag) {
    // Bytes FE ED FA CE / FE ED FA CF are big-endian Mach-O headers.
    case 0xfeedface: return { kind: 'thin', bits: 32, endianness: 'big', le: false, magic: '0xfeedface' };
    // Bytes CE FA ED FE / CF FA ED FE are little-endian Mach-O headers.
    case 0xcefaedfe: return { kind: 'thin', bits: 32, endianness: 'little', le: true, magic: '0xcefaedfe' };
    case 0xfeedfacf: return { kind: 'thin', bits: 64, endianness: 'big', le: false, magic: '0xfeedfacf' };
    case 0xcffaedfe: return { kind: 'thin', bits: 64, endianness: 'little', le: true, magic: '0xcffaedfe' };
    case 0xcafebabe: return { kind: 'fat', bits: 32, endianness: 'big', le: false, magic: '0xcafebabe' };
    case 0xbebafeca: return { kind: 'fat', bits: 32, endianness: 'little', le: true, magic: '0xbebafeca' };
    case 0xcafebabf: return { kind: 'fat', bits: 64, endianness: 'big', le: false, magic: '0xcafebabf' };
    case 0xbfbafeca: return { kind: 'fat', bits: 64, endianness: 'little', le: true, magic: '0xbfbafeca' };
    default: return null;
  }
}

function u16At(buf, off, le) {
  if (off < 0 || off + 2 > buf.length) return null;
  return le ? buf.readUInt16LE(off) : buf.readUInt16BE(off);
}
function u32At(buf, off, le) {
  if (off < 0 || off + 4 > buf.length) return null;
  return le ? buf.readUInt32LE(off) : buf.readUInt32BE(off);
}
function u64AtHex(buf, off, le) {
  if (off < 0 || off + 8 > buf.length) return null;
  const v = le ? buf.readBigUInt64LE(off) : buf.readBigUInt64BE(off);
  return { value: v, safe: v <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(v) : null };
}
function u32AtSafe(buf, off, le) {
  const v = u32At(buf, off, le);
  return v === null ? null : v;
}

function versionString(raw) {
  if (raw === null || raw === undefined) return null;
  const major = (raw >>> 16) & 0xffff;
  const minor = (raw >>> 8) & 0xff;
  const patch = raw & 0xff;
  return `${major}.${minor}.${patch}`;
}

function cpuName(cputype) {
  return CPU_TYPES.get(cputype >>> 0) || `cpu-0x${(cputype >>> 0).toString(16)}`;
}

function readLcString(buf, cmdOff, cmdSize, strOffset, le) {
  if (!Number.isFinite(strOffset) || strOffset < 8 || strOffset >= cmdSize) return null;
  return readAsciiZ(buf, cmdOff + strOffset, Math.min(512, cmdSize - strOffset));
}

/**
 * Parse one thin Mach-O image starting at `offset` and limited to `size`.
 * Returns a structured model; never throws.
 */
export function parseMachOImage(buffer, offset, size, opts = {}) {
  const warnings = [];
  const buf = buffer;
  const limit = Math.min(buf.length, offset + size);
  const info = magicInfo(buf, offset);
  if (!info || info.kind !== 'thin') return { ok: false, reason: '偏移处不是 thin Mach-O 魔数。', warnings };
  const { bits, le } = info;
  const headerSize = bits === 64 ? 32 : 28;
  if (offset + headerSize > limit) return { ok: false, reason: `Mach-O ${bits} 位头被截断（需要 ${headerSize} 字节）。`, warnings };
  const cputype = u32At(buf, offset + 4, le);
  const cpusubtype = u32At(buf, offset + 8, le);
  const filetype = u32At(buf, offset + 12, le);
  const ncmds = u32At(buf, offset + 16, le);
  const sizeofcmds = u32At(buf, offset + 20, le);
  const flags = u32At(buf, offset + 24, le);
  const header = {
    bits,
    endianness: info.endianness,
    magic: info.magic,
    cpuType: cputype === null ? null : `0x${(cputype >>> 0).toString(16)}`,
    arch: cpuName(cputype || 0),
    cpuSubtype: cpusubtype,
    fileType: filetype,
    fileTypeName: FILE_TYPES.get(filetype) || `type-${filetype}`,
    loadCommandCount: ncmds,
    sizeofLoadCommands: sizeofcmds,
    flags,
    flagNames: machoFlagNames(flags),
  };
  if (ncmds !== null && ncmds > 512) warnings.push(`ncmds=${ncmds} 过大（上限解析 512），可能为畸形输入。`);
  if (sizeofcmds !== null && sizeofcmds > 1024 * 1024) warnings.push(`sizeofcmds=${sizeofcmds} 异常巨大。`);

  const segments = [];
  const sections = [];
  const loadCommands = [];
  const dylibs = [];
  const rpaths = [];
  let uuid = null;
  let mainEntryOffset = null;
  let mainEntryVa = null;
  let codesign = null;
  let encryption = null;
  let buildVersion = null;
  let sourceVersion = null;
  let symtabInfo = null;
  let functionStarts = null;
  let dyldInfo = null;

  let cmdOff = offset + headerSize;
  const maxCmd = Math.min(ncmds || 0, 512);
  const declaredEnd = cmdOff + (sizeofcmds || 0);
  for (let i = 0; i < maxCmd; i += 1) {
    if (cmdOff + 8 > limit) { warnings.push(`加载命令在索引 ${i} 处被截断。`); break; }
    const cmd = u32At(buf, cmdOff, le);
    const cmdSize = u32At(buf, cmdOff + 4, le);
    const cmdName = LOAD_COMMANDS.get(cmd) || `LC_UNKNOWN_0x${(cmd >>> 0).toString(16)}`;
    if (!cmdSize || cmdSize < 8) {
      warnings.push(`加载命令 #${i} (${cmdName}) cmdsize=${cmdSize} 非法，停止解析。`);
      break;
    }
    if (cmdOff + cmdSize > limit) {
      warnings.push(`加载命令 #${i} (${cmdName}) 超出可用字节（cmdsize=${cmdSize}），按截断处理。`);
      if (cmdOff + cmdSize > limit + 0) { loadCommands.push({ index: i, command: cmdName, cmd, size: cmdSize, truncated: true }); break; }
    }
    const record = { index: i, command: cmdName, cmd: cmd === undefined ? null : `0x${(cmd >>> 0).toString(16)}`, size: cmdSize };
    if (cmd === 0x19 && bits === 64) {
      const segname = readAsciiZ(buf, cmdOff + 8, 16) || '';
      if (cmdOff + 72 <= limit) {
        const vmaddr = u64AtHex(buf, cmdOff + 24, le);
        const vmsize = u64AtHex(buf, cmdOff + 32, le);
        const fileoff = u64AtHex(buf, cmdOff + 40, le);
        const filesize = u64AtHex(buf, cmdOff + 48, le);
        const maxprot = u32At(buf, cmdOff + 56, le);
        const initprot = u32At(buf, cmdOff + 60, le);
        const nsects = u32At(buf, cmdOff + 64, le);
        const seg = {
          name: sanitizeText(segname, 32),
          vmaddr: vmaddr ? hex(vmaddr.value) : null,
          vmsize: vmsize ? hex(vmsize.value) : null,
          fileoff: fileoff ? fileoff.safe : null,
          filesize: filesize ? filesize.safe : null,
          maxprot, initprot,
          sectionCount: nsects,
          flagNames: segmentFlagNames(u32At(buf, cmdOff + 68, le)),
        };
        const sectionCount = Math.min(nsects || 0, 64);
        for (let k = 0; k < sectionCount; k += 1) {
          const sOff = cmdOff + 72 + k * 80;
          if (sOff + 80 > limit) { warnings.push(`段 ${segname} 的节表被截断。`); break; }
          const sectname = readAsciiZ(buf, sOff, 16) || '';
          const sectionSegname = readAsciiZ(buf, sOff + 16, 16) || '';
          const addr = u64AtHex(buf, sOff + 32, le);
          const sSize = u64AtHex(buf, sOff + 40, le);
          sections.push({
            index: sections.length,
            name: sanitizeText(sectname, 32),
            segment: sanitizeText(sectionSegname || segname, 32),
            addr: addr ? hex(addr.value) : null,
            size: sSize ? hex(sSize.value) : '0x0',
            sizeNumeric: sSize ? sSize.safe : null,
            offset: u32At(buf, sOff + 48, le),
            align: u32At(buf, sOff + 52, le),
            flags: u32At(buf, sOff + 64, le),
            flagNames: sectionFlagNames(u32At(buf, sOff + 64, le)),
          });
        }
        segments.push(seg);
        record.segment = seg.name;
        record.sectionCount = sectionCount;
      }
    } else if (cmd === 0x1 && bits === 32) {
      const segname = readAsciiZ(buf, cmdOff + 8, 16) || '';
      if (cmdOff + 56 <= limit) {
        const seg = {
          name: sanitizeText(segname, 32),
          vmaddr: hex(BigInt(u32At(buf, cmdOff + 24, le) || 0)),
          vmsize: hex(BigInt(u32At(buf, cmdOff + 28, le) || 0)),
          fileoff: u32At(buf, cmdOff + 32, le),
          filesize: u32At(buf, cmdOff + 36, le),
          maxprot: u32At(buf, cmdOff + 40, le),
          initprot: u32At(buf, cmdOff + 44, le),
          sectionCount: u32At(buf, cmdOff + 48, le),
          flagNames: segmentFlagNames(u32At(buf, cmdOff + 52, le)),
        };
        const sectionCount = Math.min(seg.sectionCount || 0, 64);
        for (let k = 0; k < sectionCount; k += 1) {
          const sOff = cmdOff + 56 + k * 68;
          if (sOff + 68 > limit) { warnings.push(`段 ${segname} 的节表被截断。`); break; }
          sections.push({
            index: sections.length,
            name: sanitizeText(readAsciiZ(buf, sOff, 16) || '', 32),
            segment: sanitizeText(readAsciiZ(buf, sOff + 16, 16) || segname, 32),
            addr: hex(BigInt(u32At(buf, sOff + 32, le) || 0)),
            size: hex(BigInt(u32At(buf, sOff + 36, le) || 0)),
            sizeNumeric: u32At(buf, sOff + 36, le),
            offset: u32At(buf, sOff + 40, le),
            align: u32At(buf, sOff + 44, le),
            flags: u32At(buf, sOff + 56, le),
            flagNames: sectionFlagNames(u32At(buf, sOff + 56, le)),
          });
        }
        segments.push(seg);
        record.segment = seg.name;
        record.sectionCount = sectionCount;
      }
    } else if (DYLIB_COMMANDS.has(cmd)) {
      const nameOffset = u32At(buf, cmdOff + 8, le);
      const dylibName = readLcString(buf, cmdOff, cmdSize, nameOffset, le);
      const isId = cmd === 0xd;
      const versionRaw = u32At(buf, cmdOff + 16, le);
      record.dylib = { name: dylibName, id: isId, currentVersion: versionString(versionRaw) };
      if (dylibName) dylibs.push({ name: dylibName, kind: isId ? 'id' : 'load', currentVersion: versionString(versionRaw) });
    } else if (cmd === 0x1b) {
      if (cmdOff + 24 <= limit) {
        const bytes = buf.subarray(cmdOff + 8, cmdOff + 24);
        uuid = formatUuid(bytes);
        record.uuid = uuid;
      }
    } else if (cmd === 0x1c || cmd === 0x8000001c) {
      const pathOffset = u32At(buf, cmdOff + 8, le);
      const rpath = readLcString(buf, cmdOff, cmdSize, pathOffset, le);
      if (rpath) { rpaths.push(rpath); record.rpath = rpath; }
    } else if (cmd === 0x80000028) {
      const entry = u64AtHex(buf, cmdOff + 8, le);
      if (entry) {
        mainEntryOffset = entry.safe;
        const textSeg = segments.find((s) => s.name === '__TEXT');
        if (textSeg && textSeg.fileoff !== null) {
          mainEntryVa = hex(BigInt('0x' + textSeg.vmaddr.slice(2)) + BigInt(entry.value) - BigInt(textSeg.fileoff));
        }
        record.entryOffset = entry.safe === null ? hex(entry.value) : entry.safe;
      }
    } else if (cmd === 0x1d) {
      codesign = { dataOffset: u32At(buf, cmdOff + 8, le), dataSize: u32At(buf, cmdOff + 12, le) };
      record.codesign = codesign;
    } else if (cmd === 0x21 || cmd === 0x2c) {
      encryption = {
        cryptOffset: u32At(buf, cmdOff + 8, le),
        cryptSize: u32At(buf, cmdOff + 12, le),
        cryptId: u32At(buf, cmdOff + 16, le),
        encrypted: (u32At(buf, cmdOff + 16, le) || 0) !== 0,
      };
      record.encryption = encryption;
    } else if (cmd === 0x32) {
      const platform = u32At(buf, cmdOff + 8, le);
      buildVersion = {
        platform,
        platformName: platform === 1 ? 'macos' : platform === 2 ? 'ios' : platform === 3 ? 'tvos' : platform === 4 ? 'watchos' : `platform-${platform}`,
        minos: versionString(u32At(buf, cmdOff + 12, le)),
        sdk: versionString(u32At(buf, cmdOff + 16, le)),
      };
      record.buildVersion = buildVersion;
    } else if (cmd === 0x24 || cmd === 0x25 || cmd === 0x2f || cmd === 0x30) {
      record.versionMin = { version: versionString(u32At(buf, cmdOff + 8, le)), sdk: versionString(u32At(buf, cmdOff + 12, le)) };
    } else if (cmd === 0x2a) {
      const sv = u64AtHex(buf, cmdOff + 8, le);
      if (sv) sourceVersion = sv.safe === null ? hex(sv.value) : String(sv.safe);
    } else if (cmd === 0x2) {
      symtabInfo = {
        symOffset: u32At(buf, cmdOff + 8, le),
        symbolCount: u32At(buf, cmdOff + 12, le),
        stringOffset: u32At(buf, cmdOff + 16, le),
        stringSize: u32At(buf, cmdOff + 20, le),
      };
      record.symtab = { symbolCount: symtabInfo.symbolCount, stringSize: symtabInfo.stringSize };
    } else if (cmd === 0x26) {
      functionStarts = { dataOffset: u32At(buf, cmdOff + 8, le), dataSize: u32At(buf, cmdOff + 12, le) };
      record.functionStarts = functionStarts;
    } else if (cmd === 0x22 || cmd === 0x80000022) {
      dyldInfo = {
        rebaseOffset: u32At(buf, cmdOff + 8, le),
        bindOffset: u32At(buf, cmdOff + 16, le),
        exportOffset: u32At(buf, cmdOff + 40, le),
        exportSize: u32At(buf, cmdOff + 44, le),
      };
      record.dyldInfo = dyldInfo;
    } else if (cmd === 0x5) {
      record.note = 'LC_UNIXTHREAD 线程状态未解码（不同架构寄存器布局差异大），入口点可能缺失。';
    }
    loadCommands.push(record);
    const next = cmdOff + cmdSize;
    if (next <= cmdOff) { warnings.push(`加载命令 #${i} cmdsize=${cmdSize} 导致偏移回退，停止。`); break; }
    cmdOff = next;
  }
  if (declaredEnd > limit + 4) warnings.push('sizeofcmds 超出可用字节，加载命令解析可能不完整。');

  // ---- Symbol table ----
  const symbolResult = { present: false, count: 0, undefinedImports: 0, definedExports: 0, importedSamples: [], exportSamples: [], truncated: false };
  if (symtabInfo && symtabInfo.symOffset && symtabInfo.symbolCount) {
    const nlistSize = bits === 64 ? 16 : 12;
    const symEnd = symtabInfo.symOffset + symtabInfo.symbolCount * nlistSize;
    const strStart = symtabInfo.stringOffset || 0;
    const strEnd = strStart + (symtabInfo.stringSize || 0);
    if (symtabInfo.symOffset + nlistSize <= limit) {
      symbolResult.present = true;
      const maxRead = Math.min(symtabInfo.symbolCount, 65536, Number.isFinite(opts.maxSymbols) ? opts.maxSymbols * 8 : 65536);
      const maxSamples = Math.max(1, Number.isFinite(opts.maxSymbols) ? opts.maxSymbols : 256);
      for (let i = 0; i < maxRead; i += 1) {
        const sOff = symtabInfo.symOffset + i * nlistSize;
        if (sOff + nlistSize > limit) { symbolResult.truncated = true; break; }
        const nStrx = u32At(buf, sOff, le);
        const nType = buf[sOff + 4];
        const nSect = buf[sOff + 5];
        const isExternal = (nType & 0x01) !== 0;
        const typeBits = nType & 0x0e;
        let name = null;
        if (nStrx && strStart + nStrx < strEnd && strStart + nStrx < buf.length) {
          name = readAsciiZ(buf, strStart + nStrx, Math.min(256, strEnd - (strStart + nStrx)));
        }
        symbolResult.count += 1;
        if (typeBits === 0 && isExternal) {
          symbolResult.undefinedImports += 1;
          if (name && symbolResult.importedSamples.length < maxSamples) symbolResult.importedSamples.push(name);
        } else if (typeBits === 0x0e && isExternal && nSect > 0) {
          symbolResult.definedExports += 1;
          if (name && symbolResult.exportSamples.length < maxSamples) symbolResult.exportSamples.push(name);
        }
      }
      if (symEnd > limit) symbolResult.truncated = true;
    } else {
      warnings.push('LC_SYMTAB 的符号表偏移超出可用字节。');
    }
  }

  const entryPoint = mainEntryOffset !== null ? hex(BigInt(mainEntryOffset)) : null;
  const firstSeg = segments.find((s) => s.name === '__TEXT') || segments[0] || null;
  return {
    ok: true,
    offset,
    size,
    header,
    segments,
    sections,
    loadCommands,
    dylibs,
    rpaths,
    uuid,
    entryPoint,
    entryPointVa: mainEntryVa,
    codesign,
    encryption,
    buildVersion,
    sourceVersion,
    functionStarts,
    dyldInfo,
    symbolTable: symbolResult,
    imports: {
      dylibCount: dylibs.filter((d) => d.kind === 'load').length,
      dylibs: dylibs.filter((d) => d.kind === 'load').map((d) => d.name).slice(0, 64),
      undefinedSymbolCount: symbolResult.undefinedImports,
      sample: symbolResult.importedSamples.slice(0, Math.max(1, Number.isFinite(opts.maxSymbols) ? opts.maxSymbols : 256)),
    },
    exports: {
      definedSymbolCount: symbolResult.definedExports,
      sample: symbolResult.exportSamples.slice(0, Math.max(1, Number.isFinite(opts.maxSymbols) ? opts.maxSymbols : 256)),
    },
    firstSegment: firstSeg,
    warnings,
  };
}

/** Parse thin or fat Mach-O. Returns { ok:false } when not Mach-O (incl. Java class collision). */
export function parseMachO(buffer, opts = {}) {
  const warnings = [];
  const buf = Buffer.isBuffer(buffer) ? buffer : Buffer.alloc(0);
  const info = magicInfo(buf, 0);
  if (!info) return { ok: false, reason: 'offset 0 不是 Mach-O / fat Mach-O 魔数。', warnings };
  if (info.kind === 'thin') {
    const image = parseMachOImage(buf, 0, buf.length, opts);
    if (!image.ok) return image;
    return { ok: true, fat: false, archCount: 1, slices: [image], warnings: image.warnings };
  }
  // fat / universal — also rejects the Java class-file CAFEBABE collision
  if (buf.length < 8) return { ok: false, reason: 'fat Mach-O 头不足 8 字节。', warnings };
  const le = info.le;
  const nfat = u32At(buf, 4, le);
  if (!nfat || nfat < 1 || nfat > 32) {
    return {
      ok: false,
      reason: `CAFEBABE 魔数但 nfat_arch=${nfat} 不在 1..32，判定为 Java class 文件而非 fat Mach-O。`,
      warnings,
      javaClassCandidate: true,
    };
  }
  const entrySize = info.bits === 64 ? 32 : 20;
  const headerEnd = 8 + nfat * entrySize;
  if (headerEnd > buf.length) return { ok: false, reason: 'fat Mach-O 架构表被截断。', warnings };
  const slices = [];
  for (let i = 0; i < nfat; i += 1) {
    const off = 8 + i * entrySize;
    const cputype = u32At(buf, off, le);
    const cpusubtype = u32At(buf, off + 4, le);
    let archOffset;
    let archSize;
    if (info.bits === 64) {
      const o = u64AtHex(buf, off + 8, le);
      const s = u64AtHex(buf, off + 16, le);
      archOffset = o ? o.safe : null;
      archSize = s ? s.safe : null;
    } else {
      archOffset = u32At(buf, off + 8, le);
      archSize = u32At(buf, off + 12, le);
    }
    const slice = {
      index: i,
      arch: cpuName(cputype || 0),
      cpuType: cputype === null ? null : `0x${(cputype >>> 0).toString(16)}`,
      cpuSubtype: cpusubtype,
      offset: archOffset,
      size: archSize,
    };
    if (archOffset === null || archSize === null || archOffset < headerEnd || archOffset + archSize > buf.length) {
      slice.ok = false;
      slice.reason = `fat 架构 #${i} 的偏移/大小 (${archOffset}+${archSize}) 超出文件范围。`;
      slices.push(slice);
      warnings.push(slice.reason);
      continue;
    }
    const image = parseMachOImage(buf, archOffset, archSize, opts);
    if (image.ok) {
      slice.ok = true;
      slice.image = image;
    } else {
      slice.ok = false;
      slice.reason = image.reason;
      slices.push(slice);
      warnings.push(`fat 架构 #${i}: ${image.reason}`);
      continue;
    }
    slices.push(slice);
  }
  return {
    ok: true,
    fat: true,
    archCount: nfat,
    slices,
    warnings: [...warnings, ...slices.flatMap((s) => (s.ok ? s.image.warnings : []))],
  };
}

function formatUuid(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 16) return null;
  const hexStr = bytes.subarray(0, 16).toString('hex').toUpperCase();
  return `${hexStr.slice(0, 8)}-${hexStr.slice(8, 12)}-${hexStr.slice(12, 16)}-${hexStr.slice(16, 20)}-${hexStr.slice(20, 32)}`;
}

function machoFlagNames(flags) {
  if (!Number.isFinite(flags)) return [];
  const out = [];
  if (flags & 0x1) out.push('noundefs');
  if (flags & 0x2) out.push('incrlink');
  if (flags & 0x4) out.push('dyldlink');
  if (flags & 0x8) out.push('bindatload');
  if (flags & 0x10) out.push('prebound');
  if (flags & 0x20) out.push('split-segs');
  if (flags & 0x40) out.push('lazy-init');
  if (flags & 0x80) out.push('two-level');
  if (flags & 0x100) out.push('force-flat');
  if (flags & 0x200) out.push('nomultidefs');
  if (flags & 0x400) out.push('nofixprebinding');
  if (flags & 0x800) out.push('prebindable');
  if (flags & 0x1000) out.push('nondrib');
  if (flags & 0x2000) out.push('subsections-via-symbols');
  if (flags & 0x4000) out.push('canonical');
  if (flags & 0x8000) out.push('weak-def');
  if (flags & 0x10000) out.push('quickstart');
  if (flags & 0x20000) out.push('root-safe');
  if (flags & 0x1000000) out.push('no-reexport-dylib');
  if (flags & 0x2000000) out.push('sim-support');
  if (flags & 0x8000000) out.push('dead-strippable-dylib');
  if (flags & 0x10000000) out.push('has-tlv-descriptors');
  if (flags & 0x20000000) out.push('is-app-extension');
  return out;
}

function segmentFlagNames(flags) {
  if (!Number.isFinite(flags)) return [];
  const out = [];
  if (flags & 0x1) out.push('highvm');
  if (flags & 0x2) out.push('fvmlib');
  if (flags & 0x4) out.push('norz');
  if (flags & 0x8) out.push('protected-version-1');
  if (flags & 0x10) out.push('read-only');
  if (flags & 0x20) out.push('debug');
  return out;
}

function sectionFlagNames(flags) {
  if (!Number.isFinite(flags)) return [];
  const type = flags & 0xff;
  const out = [];
  out.push(`type-${type}`);
  if (flags & 0x80000000) out.push('pure-instructions');
  if (flags & 0x40000000) out.push('no-toc');
  if (flags & 0x20000000) out.push('strip-static-syms');
  if (flags & 0x10000000) out.push('no-dead-strip');
  if (flags & 0x08000000) out.push('live-support');
  return out;
}

export { magicInfo as machoMagicInfo, magicInfo };
