/**
 * Binary domain — PE/COFF parser (pure, defensive, bounded).
 *
 * No sample code is executed and no filesystem/network access happens here.
 * Every read is bounds-checked; malformed structures are reported as warnings
 * and partial results rather than exceptions.
 */
import {
  entropyOf,
  formatUnixTime,
  hex,
  readAsciiZ,
  readU16,
  readU32,
  readBigU64,
  sanitizeText,
} from './util.js';

const MACHINES = new Map([
  [0x0, 'unknown'],
  [0x14c, 'x86'],
  [0x162, 'mips-r3000'],
  [0x166, 'mips-r4000'],
  [0x168, 'mips-r10000'],
  [0x169, 'mips-wce'],
  [0x184, 'alpha'],
  [0x1a2, 'sh3'],
  [0x1a6, 'sh4'],
  [0x1a8, 'sh5'],
  [0x1c0, 'arm'],
  [0x1c2, 'thumb'],
  [0x1c4, 'armnt'],
  [0x1d3, 'am33'],
  [0x1f0, 'powerpc'],
  [0x1f1, 'powerpc-fp'],
  [0x200, 'ia64'],
  [0x266, 'mips16'],
  [0x284, 'alpha64'],
  [0x366, 'mipsfpu'],
  [0x466, 'mipsfpu16'],
  [0x520, 'tricore'],
  [0x8664, 'x86-64'],
  [0x9041, 'm32r'],
  [0xaa64, 'arm64'],
  [0xc0ee, 'cee'],
]);

const SUBSYSTEMS = new Map([
  [0, 'unknown'],
  [1, 'native'],
  [2, 'windows-gui'],
  [3, 'windows-console'],
  [5, 'os2-console'],
  [7, 'posix-console'],
  [9, 'windows-ce'],
  [10, 'efi-application'],
  [11, 'efi-boot-service-driver'],
  [12, 'efi-runtime-driver'],
  [13, 'efi-rom'],
  [14, 'xbox'],
  [16, 'windows-boot-application'],
]);

const COFF_CHARACTERISTICS = [
  [0x0001, 'relocs-stripped'],
  [0x0002, 'executable-image'],
  [0x0004, 'line-numbers-stripped'],
  [0x0008, 'local-symbols-stripped'],
  [0x0010, 'aggressive-ws-trim'],
  [0x0020, 'large-address-aware'],
  [0x0080, 'bytes-reversed-lo'],
  [0x0100, '32bit-machine'],
  [0x0200, 'debug-stripped'],
  [0x0400, 'removable-run-from-swap'],
  [0x0800, 'net-run-from-swap'],
  [0x1000, 'system'],
  [0x2000, 'dll'],
  [0x4000, 'up-system-only'],
  [0x8000, 'bytes-reversed-hi'],
];

const DLL_CHARACTERISTICS = [
  [0x0020, 'high-entropy-va'],
  [0x0040, 'dynamic-base (ASLR)'],
  [0x0080, 'force-integrity'],
  [0x0100, 'nx-compat (DEP)'],
  [0x0200, 'no-isolation'],
  [0x0400, 'no-seh'],
  [0x0800, 'no-bind'],
  [0x1000, 'app-container'],
  [0x2000, 'wdm-driver'],
  [0x4000, 'guard-cf (CFG)'],
  [0x8000, 'terminal-server-aware'],
];

const SECTION_CHARACTERISTICS = [
  [0x00000020, 'contains-code'],
  [0x00000040, 'initialized-data'],
  [0x00000080, 'uninitialized-data'],
  [0x02000000, 'discardable'],
  [0x04000000, 'not-cached'],
  [0x08000000, 'not-paged'],
  [0x10000000, 'shared'],
  [0x20000000, 'execute'],
  [0x40000000, 'read'],
  [0x80000000, 'write'],
];

const DIRECTORY_NAMES = [
  'export', 'import', 'resource', 'exception', 'security', 'basereloc', 'debug',
  'architecture', 'globalptr', 'tls', 'load-config', 'bound-import', 'iat',
  'delay-import', 'com-descriptor', 'reserved',
];

const RESOURCE_TYPES = new Map([
  [1, 'cursor'], [2, 'bitmap'], [3, 'icon'], [4, 'menu'], [5, 'dialog'],
  [6, 'string'], [7, 'fontdir'], [8, 'font'], [9, 'accelerators'], [10, 'rcdata'],
  [11, 'messagetable'], [12, 'group-cursor'], [14, 'group-icon'], [16, 'version'],
  [17, 'dlginclude'], [19, 'plugplay'], [20, 'vxd'], [21, 'anicursor'],
  [22, 'anicon'], [23, 'html'], [24, 'manifest'],
]);

const DEBUG_TYPES = new Map([
  [0, 'unknown'], [1, 'coff'], [2, 'codeview'], [3, 'fpo'], [4, 'misc'],
  [5, 'exception'], [6, 'fixup'], [7, 'omap-to-src'], [8, 'omap-from-src'],
  [9, 'borland'], [10, 'reserved10'], [11, 'clsid'], [12, 'vc-feature'],
  [13, 'pogo'], [14, 'iltcg'], [15, 'mpx'], [16, 'repro'],
]);

const KNOWN_PACKER_SECTION_PATTERNS = [
  [/^UPX[0-9!]/i, 'UPX'],
  [/^\.?(?:aspack|adata)$/i, 'ASPack'],
  [/^fsg$/i, 'FSG'],
  [/^\.?MPRESS[0-9]?$/i, 'MPRESS'],
  [/^\.?petite/i, 'Petite'],
  [/^\.?themida/i, 'Themida'],
  [/^\.?winlice/i, 'WinLicense'],
  [/^\.vmp[0-9]?$/i, 'VMProtect'],
  [/^\.?enigma/i, 'Enigma'],
  [/^\.?nsp[0-9]?$/i, 'NsPack'],
  [/^\.?rlpack/i, 'RLPack'],
  [/^\.?kkrunchy/i, 'kkrunchy'],
  [/^\.?pec[0-9]?$/i, 'PECompact'],
  [/^\.?mew$/i, 'MEW'],
  [/^\.?bydwing/i, 'ByDwing'],
];

const VERSION_STRING_KEYS = [
  'CompanyName', 'FileDescription', 'FileVersion', 'InternalName', 'LegalCopyright',
  'LegalTrademarks', 'OriginalFilename', 'ProductName', 'ProductVersion', 'Comments',
  'PrivateBuild', 'SpecialBuild',
];

function flagsFrom(value, table) {
  const list = [];
  if (!Number.isFinite(value)) return list;
  for (const [bit, name] of table) if ((value & bit) !== 0) list.push(name);
  return list;
}

function readU8Safe(buffer, off) {
  if (off < 0 || off >= buffer.length) return null;
  return buffer[off];
}

/**
 * Map an RVA to a file offset using the section table. Headers are identity-mapped.
 * Returns null when unmapped / not present in the read-in bytes.
 */
export function rvaToOffset(buffer, sections, headersSize, rva) {
  if (!Number.isFinite(rva) || rva < 0) return null;
  const hs = Number.isFinite(headersSize) && headersSize > 0 ? headersSize : 0;
  if (rva < hs) return rva < buffer.length ? rva : null;
  for (const s of sections) {
    const span = Math.max(s.virtualSize || 0, s.rawSize || 0);
    if (rva >= s.virtualAddress && rva < s.virtualAddress + span) {
      const delta = rva - s.virtualAddress;
      if (!s.rawSize || delta >= s.rawSize || !s.rawPointer) return null;
      const off = s.rawPointer + delta;
      return off < buffer.length ? off : null;
    }
  }
  return null;
}

function parseCoff(buffer, coffOffset, warnings) {
  const coff = {
    machine: readU16(buffer, coffOffset),
    numberOfSections: readU16(buffer, coffOffset + 2),
    timeDateStamp: readU32(buffer, coffOffset + 4),
    pointerToSymbolTable: readU32(buffer, coffOffset + 8),
    numberOfSymbols: readU32(buffer, coffOffset + 12),
    sizeOfOptionalHeader: readU16(buffer, coffOffset + 16),
    characteristics: readU16(buffer, coffOffset + 18),
  };
  coff.machineName = MACHINES.get(coff.machine) || `machine-${coff.machine}`;
  coff.characteristicFlags = flagsFrom(coff.characteristics, COFF_CHARACTERISTICS);
  coff.compiledAt = formatUnixTime(coff.timeDateStamp);
  if (coff.numberOfSections !== null && coff.numberOfSections > 0x2000) {
    warnings.push(`COFF NumberOfSections=${coff.numberOfSections} 超出合理范围，视为畸形输入。`);
  }
  if (coff.timeDateStamp === 0) warnings.push('COFF 时间戳为 0（常见于可复现构建或时间戳被清除的样本）。');
  return coff;
}

function parseSectionHeaders(buffer, sectionsOffset, count, maxSections) {
  const n = Math.min(count || 0, maxSections, 0x2000);
  const sections = [];
  for (let i = 0; i < n; i += 1) {
    const off = sectionsOffset + i * 40;
    if (off + 40 > buffer.length) break;
    const rawName = buffer.subarray(off, off + 8);
    const nulIndex = rawName.indexOf(0);
    let name = rawName.subarray(0, nulIndex === -1 ? 8 : nulIndex).toString('latin1');
    name = sanitizeText(name, 64);
    const virtualSize = readU32(buffer, off + 8);
    const virtualAddress = readU32(buffer, off + 12);
    const rawSize = readU32(buffer, off + 16);
    const rawPointer = readU32(buffer, off + 20);
    const characteristics = readU32(buffer, off + 36);
    sections.push({
      index: i,
      name,
      virtualAddress,
      virtualSize,
      rawPointer,
      rawSize,
      characteristics,
      characteristicFlags: flagsFrom(characteristics, SECTION_CHARACTERISTICS),
      executable: (characteristics & 0x20000000) !== 0,
      writable: (characteristics & 0x80000000) !== 0,
      readable: (characteristics & 0x40000000) !== 0,
      containsCode: (characteristics & 0x00000020) !== 0,
    });
  }
  return sections;
}

function parseOptionalHeader(buffer, optionalOffset, warnings) {
  const magic = readU16(buffer, optionalOffset);
  if (magic === null) {
    warnings.push('PE 可选头被截断（无法读取 Magic）。');
    return null;
  }
  const pe32Plus = magic === 0x20b;
  if (magic !== 0x10b && !pe32Plus && magic !== 0x107) {
    warnings.push(`PE 可选头 Magic=0x${magic.toString(16)} 非标准（0x10b PE32 / 0x20b PE32+ / 0x107 ROM），按 PE32 布局解析。`);
  }
  const imageBase = pe32Plus ? readBigU64(buffer, optionalOffset + 24) : readU32(buffer, optionalOffset + 28);
  const dataDirStart = optionalOffset + (pe32Plus ? 112 : 96);
  const dllCharacteristics = readU16(buffer, optionalOffset + 70);
  const optional = {
    magic: `0x${magic.toString(16)}`,
    magicId: magic,
    pe32Plus,
    bits: pe32Plus ? 64 : 32,
    linkerVersion: `${readU8Safe(buffer, optionalOffset + 2)}.${readU8Safe(buffer, optionalOffset + 3)}`,
    sizeOfCode: readU32(buffer, optionalOffset + 4),
    sizeOfInitializedData: readU32(buffer, optionalOffset + 8),
    sizeOfUninitializedData: readU32(buffer, optionalOffset + 12),
    entryPointRva: readU32(buffer, optionalOffset + 16),
    baseOfCode: readU32(buffer, optionalOffset + 20),
    baseOfData: pe32Plus ? null : readU32(buffer, optionalOffset + 24),
    imageBase: imageBase === null ? null : (typeof imageBase === 'bigint' ? imageBase : BigInt(imageBase)),
    sectionAlignment: readU32(buffer, optionalOffset + 32),
    fileAlignment: readU32(buffer, optionalOffset + 36),
    osVersion: `${readU16(buffer, optionalOffset + 40) ?? 0}.${readU16(buffer, optionalOffset + 42) ?? 0}`,
    imageVersion: `${readU16(buffer, optionalOffset + 44) ?? 0}.${readU16(buffer, optionalOffset + 46) ?? 0}`,
    subsystemVersion: `${readU16(buffer, optionalOffset + 48) ?? 0}.${readU16(buffer, optionalOffset + 50) ?? 0}`,
    sizeOfImage: readU32(buffer, optionalOffset + 56),
    sizeOfHeaders: readU32(buffer, optionalOffset + 60),
    checksum: readU32(buffer, optionalOffset + 64),
    subsystem: readU16(buffer, optionalOffset + 68),
    dllCharacteristics,
    numberOfRvaAndSizes: readU32(buffer, optionalOffset + (pe32Plus ? 108 : 92)),
    dataDirectoryOffset: dataDirStart,
  };
  optional.subsystemName = SUBSYSTEMS.get(optional.subsystem) || `subsystem-${optional.subsystem}`;
  optional.dllCharacteristicFlags = flagsFrom(dllCharacteristics, DLL_CHARACTERISTICS);
  const imageBaseBig = imageBase === null ? null : (typeof imageBase === 'bigint' ? imageBase : BigInt(imageBase));
  optional.imageBaseHex = imageBaseBig === null ? null : hex(imageBaseBig);
  optional.entryPointHex = optional.entryPointRva === null ? null : hex(optional.entryPointRva);
  optional.entryPointVa = imageBaseBig === null || optional.entryPointRva === null
    ? null
    : hex(imageBaseBig + BigInt(optional.entryPointRva));
  return optional;
}

function parseDataDirectories(buffer, optional, warnings) {
  const dirs = [];
  if (!optional) return dirs;
  const declared = Number.isFinite(optional.numberOfRvaAndSizes) ? optional.numberOfRvaAndSizes : 0;
  const count = Math.min(16, declared, Math.max(0, Math.floor((buffer.length - optional.dataDirectoryOffset) / 8)));
  if (declared > 16) warnings.push(`PE 声明 ${declared} 个数据目录（标准为 16），仅解析前 16 个。`);
  if (declared > 0 && count < Math.min(declared, 16)) warnings.push('数据目录区被截断，仅解析文件内存在的目录项。');
  for (let i = 0; i < count; i += 1) {
    const off = optional.dataDirectoryOffset + i * 8;
    const rva = readU32(buffer, off);
    const size = readU32(buffer, off + 4);
    dirs.push({
      index: i,
      name: DIRECTORY_NAMES[i] || `directory-${i}`,
      rva,
      size,
      present: (rva || 0) !== 0 && (size || 0) !== 0,
    });
  }
  return dirs;
}

/** Import table: DLL names + imported function names/ordinals. Bounded. */
export function parsePeImports(buffer, sections, headersSize, importDir, warnings, pe32Plus) {
  const result = { present: false, dllCount: 0, functionCount: 0, libraries: [], truncated: false, thunkWidth: pe32Plus ? 64 : 32 };
  if (!importDir || !importDir.rva || !importDir.size) return result;
  const dirOff = rvaToOffset(buffer, sections, headersSize, importDir.rva);
  if (dirOff === null) {
    warnings.push(`导入目录 RVA=0x${importDir.rva.toString(16)} 不在任何已读入节内，无法解析导入表。`);
    return result;
  }
  result.present = true;
  const entryWidth = pe32Plus ? 8 : 4;
  const descriptorCount = Math.min(256, Math.max(1, Math.floor(importDir.size / 20) + 1));
  let totalFunctions = 0;
  for (let i = 0; i < descriptorCount; i += 1) {
    const off = dirOff + i * 20;
    if (off + 20 > buffer.length) { result.truncated = true; break; }
    const originalFirstThunk = readU32(buffer, off);
    const nameRva = readU32(buffer, off + 12);
    const firstThunk = readU32(buffer, off + 16);
    if (!nameRva) break;
    const nameOff = rvaToOffset(buffer, sections, headersSize, nameRva);
    const dllName = nameOff === null ? null : readAsciiZ(buffer, nameOff, 260);
    if (!dllName) {
      warnings.push(`导入描述符 #${i} 的 DLL 名 RVA=0x${nameRva.toString(16)} 无法读取，跳过。`);
      continue;
    }
    const thunkRva = originalFirstThunk || firstThunk;
    const functions = [];
    let truncated = false;
    if (thunkRva) {
      const thunkOff = rvaToOffset(buffer, sections, headersSize, thunkRva);
      if (thunkOff === null) {
        warnings.push(`DLL ${dllName} 的导入 thunk RVA=0x${thunkRva.toString(16)} 无法定位。`);
        truncated = true;
      } else {
        for (let j = 0; j < 4096; j += 1) {
          const eoff = thunkOff + j * entryWidth;
          if (eoff + entryWidth > buffer.length) { truncated = true; break; }
          const raw = entryWidth === 8 ? readBigU64(buffer, eoff) : BigInt(readU32(buffer, eoff));
          if (raw === null) { truncated = true; break; }
          if (raw === 0n) break;
          const isOrdinal = entryWidth === 8
            ? (raw & 0x8000000000000000n) !== 0n
            : (raw & 0x80000000n) !== 0n;
          if (isOrdinal) {
            functions.push({ ordinal: Number(raw & 0xffffn), byOrdinal: true });
          } else {
            const rva = Number(raw);
            const hintNameOff = rvaToOffset(buffer, sections, headersSize, rva + 2);
            const fn = hintNameOff === null ? null : readAsciiZ(buffer, hintNameOff, 512);
            functions.push(fn
              ? { name: fn, ordinal: null, byOrdinal: false }
              : { name: `<unmapped@0x${rva.toString(16)}>`, ordinal: null, byOrdinal: false });
          }
        }
        if (functions.length >= 4096) truncated = true;
      }
    } else {
      warnings.push(`DLL ${dllName} 的导入描述符没有 thunk RVA（OriginalFirstThunk/FirstThunk 均为 0）。`);
      truncated = true;
    }
    totalFunctions += functions.length;
    result.libraries.push({ name: dllName, functions, functionCount: functions.length, truncated });
    if (totalFunctions >= 4096) { result.truncated = true; break; }
  }
  result.dllCount = result.libraries.length;
  result.functionCount = totalFunctions;
  return result;
}

/** Export table: named exports with ordinals/RVAs. Bounded. */
export function parsePeExports(buffer, sections, headersSize, exportDir, warnings, maxNames = 4096) {
  const result = { present: false, moduleName: null, functionCount: 0, namedExportCount: 0, exports: [], truncated: false };
  if (!exportDir || !exportDir.rva || !exportDir.size) return result;
  const dirOff = rvaToOffset(buffer, sections, headersSize, exportDir.rva);
  if (dirOff === null) {
    warnings.push(`导出目录 RVA=0x${exportDir.rva.toString(16)} 不在任何已读入节内。`);
    return result;
  }
  if (dirOff + 40 > buffer.length) {
    warnings.push('导出目录头被截断（不足 40 字节）。');
    return { ...result, present: true };
  }
  result.present = true;
  const directoryNameRva = readU32(buffer, dirOff + 12);
  const base = readU32(buffer, dirOff + 16) || 0;
  const numberOfFunctions = readU32(buffer, dirOff + 20) || 0;
  const numberOfNames = readU32(buffer, dirOff + 24) || 0;
  const addressOfFunctions = readU32(buffer, dirOff + 28) || 0;
  const addressOfNames = readU32(buffer, dirOff + 32) || 0;
  const addressOfNameOrdinals = readU32(buffer, dirOff + 36) || 0;
  result.baseOrdinal = base;
  result.functionCount = numberOfFunctions;
  result.namedExportCount = numberOfNames;
  const nameOff = directoryNameRva ? rvaToOffset(buffer, sections, headersSize, directoryNameRva) : null;
  result.moduleName = nameOff === null ? null : readAsciiZ(buffer, nameOff, 260);
  if (numberOfNames > 0) {
    const namesOff = rvaToOffset(buffer, sections, headersSize, addressOfNames);
    const ordinalsOff = rvaToOffset(buffer, sections, headersSize, addressOfNameOrdinals);
    if (namesOff === null || ordinalsOff === null) {
      warnings.push('导出名称表无法定位（RVA 未映射），仅保留导出统计。');
      return result;
    }
    const funcsOff = numberOfFunctions ? rvaToOffset(buffer, sections, headersSize, addressOfFunctions) : null;
    const limit = Math.min(numberOfNames, Math.max(1, maxNames), 4096);
    for (let i = 0; i < limit; i += 1) {
      const nameRva = readU32(buffer, namesOff + i * 4);
      const ordinalIndex = readU16(buffer, ordinalsOff + i * 2);
      if (nameRva === null || ordinalIndex === null) break;
      const nOff = rvaToOffset(buffer, sections, headersSize, nameRva);
      const exportName = nOff === null ? null : readAsciiZ(buffer, nOff, 512);
      let functionRva = null;
      if (funcsOff !== null && ordinalIndex < numberOfFunctions) {
        functionRva = readU32(buffer, funcsOff + ordinalIndex * 4);
      }
      result.exports.push({
        name: exportName || `<unnamed-${i}>`,
        ordinal: base + ordinalIndex,
        rva: functionRva,
        address: functionRva === null ? null : hex(functionRva),
      });
    }
    if (numberOfNames > limit) result.truncated = true;
  }
  return result;
}

/** Debug directory incl. CodeView PDB path/GUID when present. */
export function parsePeDebugDirectory(buffer, sections, headersSize, debugDir, warnings) {
  const result = { present: false, entries: [] };
  if (!debugDir || !debugDir.rva || !debugDir.size) return result;
  const dirOff = rvaToOffset(buffer, sections, headersSize, debugDir.rva);
  if (dirOff === null) {
    warnings.push(`调试目录 RVA=0x${debugDir.rva.toString(16)} 无法定位。`);
    return result;
  }
  result.present = true;
  const count = Math.min(32, Math.floor(debugDir.size / 28));
  for (let i = 0; i < count; i += 1) {
    const off = dirOff + i * 28;
    if (off + 28 > buffer.length) { result.truncated = true; break; }
    const timestamp = readU32(buffer, off + 4);
    const type = readU32(buffer, off + 12);
    const sizeOfData = readU32(buffer, off + 16);
    const addressOfRawData = readU32(buffer, off + 20);
    const pointerToRawData = readU32(buffer, off + 24);
    const entry = {
      index: i,
      type,
      typeName: DEBUG_TYPES.get(type) || `type-${type}`,
      timestamp: formatUnixTime(timestamp),
      timestampRaw: timestamp,
      sizeOfData,
    };
    let dataOff = pointerToRawData && pointerToRawData < buffer.length ? pointerToRawData : null;
    if (dataOff === null && addressOfRawData) dataOff = rvaToOffset(buffer, sections, headersSize, addressOfRawData);
    if (dataOff !== null && dataOff + 4 <= buffer.length) {
      const sig = buffer.subarray(dataOff, dataOff + 4).toString('latin1');
      if (sig === 'RSDS' && dataOff + 24 <= buffer.length) {
        entry.codeview = {
          signature: 'RSDS',
          guid: formatGuid(buffer.subarray(dataOff + 4, dataOff + 20)),
          age: readU32(buffer, dataOff + 20),
          pdbPath: readAsciiZ(buffer, dataOff + 24, 512),
        };
      } else if (sig === 'NB10' && dataOff + 16 <= buffer.length) {
        const nbTimestamp = readU32(buffer, dataOff + 8);
        entry.codeview = {
          signature: 'NB10',
          offset: readU32(buffer, dataOff + 4),
          timestamp: formatUnixTime(nbTimestamp),
          timestampRaw: nbTimestamp,
          age: readU32(buffer, dataOff + 12),
          pdbPath: readAsciiZ(buffer, dataOff + 16, 512),
        };
      }
    }
    result.entries.push(entry);
  }
  return result;
}

function formatGuid(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 16) return null;
  const d1 = bytes.readUInt32LE(0).toString(16).padStart(8, '0');
  const d2 = bytes.readUInt16LE(4).toString(16).padStart(4, '0');
  const d3 = bytes.readUInt16LE(6).toString(16).padStart(4, '0');
  const d4 = bytes.subarray(8, 10).toString('hex');
  const d5 = bytes.subarray(10, 16).toString('hex');
  return `${d1}-${d2}-${d3}-${d4}-${d5}`;
}

/** Bounded resource-directory walk; extracts RT_VERSION metadata and a type summary. */
export function parsePeResources(buffer, sections, headersSize, resourceDir, warnings) {
  const result = { present: false, count: 0, types: [], entries: [], versionInfo: null, manifestPresent: false };
  if (!resourceDir || !resourceDir.rva || !resourceDir.size) return result;
  const base = rvaToOffset(buffer, sections, headersSize, resourceDir.rva);
  if (base === null) {
    warnings.push(`资源目录 RVA=0x${resourceDir.rva.toString(16)} 无法定位。`);
    return result;
  }
  result.present = true;
  const typeCounts = new Map();
  let visited = 0;
  const maxEntries = 256;
  const maxDepth = 3;

  const walk = (relativeOffset, depth, context, budget) => {
    if (depth > maxDepth || visited > maxEntries || budget.left <= 0) return;
    const dirOff = base + relativeOffset;
    if (dirOff + 16 > buffer.length) return;
    const namedCount = readU16(buffer, dirOff + 12) || 0;
    const idCount = readU16(buffer, dirOff + 14) || 0;
    const entryCount = Math.min(namedCount + idCount, 64, budget.left);
    const entriesOff = dirOff + 16;
    for (let i = 0; i < entryCount; i += 1) {
      const off = entriesOff + i * 8;
      if (off + 8 > buffer.length) return;
      const nameRaw = readU32(buffer, off);
      const dataRaw = readU32(buffer, off + 4);
      if (nameRaw === null || dataRaw === null) return;
      visited += 1;
      budget.left -= 1;
      const nameIsString = (nameRaw & 0x80000000) !== 0;
      const id = nameRaw & 0x7fffffff;
      const isDirectory = (dataRaw & 0x80000000) !== 0;
      const childOffset = dataRaw & 0x7fffffff;
      const childContext = { ...context };
      if (depth === 0) {
        childContext.typeId = nameIsString ? null : id;
        childContext.typeName = nameIsString ? `named-${id}` : (RESOURCE_TYPES.get(id) || `type-${id}`);
      } else if (depth === 1) {
        childContext.resourceId = nameIsString ? `named-${id}` : id;
      } else if (depth === 2) {
        childContext.language = id;
      }
      if (isDirectory && depth < maxDepth) {
        walk(childOffset, depth + 1, childContext, budget);
      } else if (!isDirectory && depth === 2) {
        const dataEntryOff = base + childOffset;
        if (dataEntryOff + 16 > buffer.length) continue;
        const dataRva = readU32(buffer, dataEntryOff);
        const size = readU32(buffer, dataEntryOff + 4);
        const codePage = readU32(buffer, dataEntryOff + 8);
        const dataOff = rvaToOffset(buffer, sections, headersSize, dataRva);
        result.entries.push({
          typeId: childContext.typeId,
          typeName: childContext.typeName,
          id: childContext.resourceId,
          language: childContext.language,
          size,
          codePage,
          dataRva,
          dataOffset: dataOff,
        });
        result.count += 1;
        typeCounts.set(childContext.typeName, (typeCounts.get(childContext.typeName) || 0) + 1);
        if (childContext.typeId === 16 && childContext.resourceId === 1 && dataOff !== null && size > 0) {
          const available = Math.min(size, 8192, buffer.length - dataOff);
          if (available > 0) result.versionInfo = extractVersionInfo(buffer.subarray(dataOff, dataOff + available));
        }
        if (childContext.typeId === 24) result.manifestPresent = true;
      }
      if (visited > maxEntries || budget.left <= 0) return;
    }
  };

  try {
    walk(0, 0, {}, { left: maxEntries });
  } catch (err) {
    warnings.push(`资源目录解析中遇到异常结构，已截断：${err && err.message ? err.message : String(err)}`);
  }
  result.types = [...typeCounts.entries()].map(([type, count]) => ({ type, count })).sort((a, b) => a.type.localeCompare(b.type));
  return result;
}

/** Extract VS_VERSION_INFO fixed-file info + StringFileInfo values (bounded, heuristic on strings). */
export function extractVersionInfo(data) {
  const result = {
    rawVersionInfoPresent: false,
    fixedFileInfo: null,
    strings: {},
    extractionNote: 'StringFileInfo 键值通过 UTF-16LE 键名定位启发式提取，可能存在偏差。',
  };
  if (!Buffer.isBuffer(data) || data.length === 0) return result;
  const magic = Buffer.from([0xbd, 0x04, 0xef, 0xfe]);
  const magicOff = data.indexOf(magic);
  if (magicOff !== -1 && magicOff + 24 <= data.length) {
    result.rawVersionInfoPresent = true;
    const ms = data.readUInt32LE(magicOff + 8);
    const ls = data.readUInt32LE(magicOff + 12);
    const pms = magicOff + 20 <= data.length ? data.readUInt32LE(magicOff + 16) : null;
    const pls = magicOff + 24 <= data.length ? data.readUInt32LE(magicOff + 20) : null;
    result.fixedFileInfo = {
      fileVersion: `${(ms >>> 16) & 0xffff}.${ms & 0xffff}.${(ls >>> 16) & 0xffff}.${ls & 0xffff}`,
      productVersion: pms !== null && pls !== null
        ? `${(pms >>> 16) & 0xffff}.${pms & 0xffff}.${(pls >>> 16) & 0xffff}.${pls & 0xffff}`
        : null,
      fileFlags: magicOff + 36 <= data.length ? data.readUInt32LE(magicOff + 32) : null,
      fileOs: magicOff + 40 <= data.length ? data.readUInt32LE(magicOff + 36) : null,
      fileType: magicOff + 44 <= data.length ? data.readUInt32LE(magicOff + 40) : null,
    };
  } else {
    result.rawVersionInfoPresent = data.includes(Buffer.from('VS_VERSION_INFO', 'utf16le'));
  }
  for (const key of VERSION_STRING_KEYS) {
    const value = scanUtf16Value(data, key);
    if (value !== null && value.length > 0) result.strings[key] = value;
  }
  return result;
}

function scanUtf16Value(data, key) {
  const needle = Buffer.from(key, 'utf16le');
  const idx = data.indexOf(needle);
  if (idx === -1) return null;
  let pos = idx + needle.length;
  while (pos + 1 < data.length && data[pos] === 0 && data[pos + 1] === 0) pos += 2;
  const chars = [];
  while (pos + 1 < data.length && chars.length < 512) {
    const code = data[pos] | (data[pos + 1] << 8);
    pos += 2;
    if (code === 0) break;
    if (code < 0x20 && code !== 0x09) return null;
    chars.push(String.fromCharCode(code));
  }
  if (chars.length === 0) return null;
  const value = sanitizeText(chars.join(''), 512);
  return value.length > 0 ? value : null;
}

/** Overlay: bytes after the last raw section (the certificate table may live there). */
export function parsePeOverlay(buffer, sections, optional, directories) {
  const fileSize = buffer.length;
  let end = Number.isFinite(optional && optional.sizeOfHeaders) ? optional.sizeOfHeaders : 0;
  for (const s of sections) {
    if (!s.rawSize || !s.rawPointer) continue;
    end = Math.max(end, s.rawPointer + s.rawSize);
  }
  end = Math.min(end, fileSize);
  const overlaySize = fileSize - end;
  const security = (directories || []).find((d) => d.index === 4);
  return {
    present: overlaySize > 0,
    offset: end,
    size: overlaySize,
    fileSize,
    certificateTable: security && security.rva
      ? { offset: security.rva, size: security.size, present: security.rva + security.size <= fileSize }
      : null,
  };
}

/** Heuristic packer detection; all outputs are hypotheses, never confirmations. */
export function analyzePacker(buffer, pe) {
  const heuristics = [];
  const sectionNames = pe.sections.map((s) => s.name);
  let suspectedFamily = null;
  const patterns = new Map();
  for (const s of pe.sections) {
    for (const [re, family] of KNOWN_PACKER_SECTION_PATTERNS) {
      if (re.test(s.name)) patterns.set(family, (patterns.get(family) || []).concat(s.name));
    }
  }
  for (const [family, names] of patterns) {
    heuristics.push({ id: 'packer-section-names', weight: 4, detail: `节名匹配已知加壳器 ${family}: ${names.join(', ')}` });
    if (!suspectedFamily) suspectedFamily = family;
  }
  const importCount = pe.imports ? pe.imports.functionCount : 0;
  if (pe.imports && pe.imports.present && importCount === 0) {
    heuristics.push({ id: 'empty-imports', weight: 2, detail: '存在导入目录但导入函数数为 0（常见于加壳/手工导入）。' });
  }
  if (pe.optional && pe.optional.entryPointRva === 0) {
    heuristics.push({ id: 'zero-entry', weight: 1, detail: 'AddressOfEntryPoint 为 0。' });
  }
  const last = pe.sections[pe.sections.length - 1];
  if (last && pe.optional && last.virtualAddress !== undefined
    && pe.optional.entryPointRva >= last.virtualAddress
    && pe.optional.entryPointRva < last.virtualAddress + Math.max(last.virtualSize || 0, last.rawSize || 0)) {
    heuristics.push({ id: 'entry-in-last-section', weight: 1, detail: `入口点 RVA 落在最后一节 ${last.name || '(无名)'} 内。` });
  }
  const wx = pe.sections.filter((s) => s.executable && s.writable);
  if (wx.length > 0) {
    heuristics.push({ id: 'writable-executable-section', weight: 2, detail: `存在可写且可执行节：${wx.map((s) => s.name || '(无名)').join(', ')}。` });
  }
  const highEntropy = [];
  for (const s of pe.sections) {
    if (!s.rawSize || !s.rawPointer || s.rawPointer + s.rawSize > buffer.length) continue;
    if (s.rawSize < 256) continue;
    const h = entropyOf(buffer.subarray(s.rawPointer, s.rawPointer + s.rawSize), 1024 * 1024);
    s.entropy = Math.round(h * 1e4) / 1e4;
    if (h > 7.2) highEntropy.push(`${s.name || '(无名)'}(${s.entropy})`);
  }
  if (highEntropy.length > 0) {
    heuristics.push({ id: 'high-entropy-section', weight: 2, detail: `高熵节（>7.2 bits/byte，疑似压缩/加密）：${highEntropy.join(', ')}。` });
  }
  if (sectionNames.some((n) => n.length === 0 || /[^\x20-\x7e]/.test(n))) {
    heuristics.push({ id: 'abnormal-section-names', weight: 1, detail: '存在空节名或不可打印节名。' });
  }
  const score = heuristics.reduce((acc, h) => acc + h.weight, 0);
  return {
    detected: score >= 3 || suspectedFamily !== null,
    suspectedFamily,
    score,
    heuristics,
    note: '加壳判断为启发式（hypothesis）：节名/导入表/入口点/熵等静态特征可能被正常程序或保护器伪造，需要进一步人工确认。',
  };
}

/** COFF symbol table (functions/symbols heuristic for binary.structure). */
export function parsePeCoffSymbols(buffer, coff, maxNames = 1024) {
  const result = { present: false, totalSymbols: coff.numberOfSymbols || 0, functions: [], truncated: false };
  const ptr = coff.pointerToSymbolTable;
  const count = coff.numberOfSymbols;
  if (!ptr || !count || ptr >= buffer.length) return result;
  result.present = true;
  const strTableOff = ptr + count * 18;
  const limit = Math.min(count, 4096);
  let i = 0;
  while (i < limit) {
    const off = ptr + i * 18;
    if (off + 18 > buffer.length) break;
    const auxCount = buffer[off + 17] || 0;
    const sectionNumber = buffer.readInt16LE(off + 12);
    const type = buffer.readUInt16LE(off + 14);
    const storageClass = buffer[off + 16];
    let name = null;
    if (buffer.readUInt32LE(off) === 0 && buffer.readUInt32LE(off + 4) > 0) {
      const nameOff = strTableOff + buffer.readUInt32LE(off + 4);
      name = nameOff < buffer.length ? readAsciiZ(buffer, nameOff, 256) : null;
    } else {
      name = Buffer.from(buffer.subarray(off, off + 8)).toString('latin1').replace(/\u0000+$/, '').trim() || null;
    }
    const isFunction = (type & 0x20) !== 0;
    if (name && sectionNumber > 0 && isFunction) {
      result.functions.push({ name: sanitizeText(name, 256), value: buffer.readUInt32LE(off + 8), sectionNumber, storageClass });
      if (result.functions.length >= maxNames) { result.truncated = true; break; }
    }
    i += 1 + auxCount;
  }
  return result;
}

/** Exception directory summary (x64/arm64 RUNTIME_FUNCTION records). */
export function parsePeExceptionDirectory(directories, machine, bits) {
  const dir = (directories || []).find((d) => d.index === 3);
  if (!dir || !dir.present) return { present: false, recordSize: null, approxCount: null };
  let recordSize = null;
  if (machine === 0x8664 || machine === 0xaa64) recordSize = 12;
  else if (machine === 0x1c0 || machine === 0x1c4 || machine === 0x1c2) recordSize = 8;
  return {
    present: true,
    rva: dir.rva,
    size: dir.size,
    recordSize,
    approxCount: recordSize ? Math.floor(dir.size / recordSize) : null,
    note: recordSize
      ? '按 RUNTIME_FUNCTION 记录大小估算函数数量（observed 结构，计数为近似值）。'
      : '该架构无统一 RUNTIME_FUNCTION 记录大小，未估算。',
  };
}

/**
 * Full PE parse. Never throws on malformed input: returns { ok:false, reason, warnings }
 * or a partial model with warnings.
 */
export function parsePe(buffer, opts = {}) {
  const warnings = [];
  const buf = Buffer.isBuffer(buffer) ? buffer : Buffer.alloc(0);
  if (buf.length < 0x40) return { ok: false, reason: '文件小于 64 字节，不可能是 PE 文件。', warnings };
  if (buf[0] !== 0x4d || buf[1] !== 0x5a) return { ok: false, reason: '缺少 MZ 头（offset 0 不是 0x4D5A）。', warnings };
  const peOffset = readU32(buf, 0x3c);
  if (peOffset === null || peOffset < 0x40 || peOffset > 0x100000 || peOffset + 24 > buf.length) {
    return { ok: false, reason: `e_lfanew=${peOffset} 非法或指向文件外，不是有效 PE。`, warnings };
  }
  if (readU32(buf, peOffset) !== 0x00004550) {
    return { ok: false, reason: 'MZ 存在但 PE\\0\\0 签名缺失或错位。', warnings };
  }
  const coffOffset = peOffset + 4;
  const coff = parseCoff(buf, coffOffset, warnings);
  const optionalOffset = coffOffset + 20;
  const optional = parseOptionalHeader(buf, optionalOffset, warnings);
  const directories = parseDataDirectories(buf, optional, warnings);
  if (!optional) {
    return {
      ok: true, peOffset, coff, optional: null, directories: [], sections: [], imports: null,
      exports: null, debug: null, resources: null, overlay: null, warnings, partial: true,
    };
  }
  const maxSections = Number.isFinite(opts.maxSections) ? Math.max(1, opts.maxSections) : 96;
  const sectionsOffset = optionalOffset + (coff.sizeOfOptionalHeader || 0);
  const sections = parseSectionHeaders(buf, sectionsOffset, coff.numberOfSections || 0, maxSections);
  if (sections.length < (coff.numberOfSections || 0)) {
    warnings.push(`声明 ${coff.numberOfSections} 个节，实际可解析 ${sections.length} 个（文件可能被截断）。`);
  }
  const headersSize = optional.sizeOfHeaders || 0;
  const byIndex = (i) => directories.find((d) => d.index === i) || null;
  const imports = parsePeImports(buf, sections, headersSize, byIndex(1), warnings, optional.pe32Plus);
  const exports = parsePeExports(buf, sections, headersSize, byIndex(0), warnings);
  const debug = parsePeDebugDirectory(buf, sections, headersSize, byIndex(6), warnings);
  const resources = parsePeResources(buf, sections, headersSize, byIndex(2), warnings);
  const overlay = parsePeOverlay(buf, sections, optional, directories);
  const coffSymbols = parsePeCoffSymbols(buf, coff);
  const exceptionDirectory = parsePeExceptionDirectory(directories, coff.machine, optional.bits);
  const result = {
    ok: true,
    peOffset,
    coff,
    optional,
    sections,
    sectionsOffset,
    directories,
    imports,
    exports,
    debug,
    resources,
    overlay,
    coffSymbols,
    exceptionDirectory,
    warnings,
    partial: false,
  };
  result.packer = analyzePacker(buf, result);
  return result;
}
