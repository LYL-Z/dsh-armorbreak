/**
 * Forensics — metadata extraction by format (PE/ELF/Mach-O/ZIP/PNG/JPEG/OLE2/PDF/gzip).
 * Structural facts are reported as observed; interpretations as hypothesis.
 */
import { parsePe } from '../binary/pe.js';
import { parseElf } from '../binary/elf.js';
import { parseMachO } from '../binary/macho.js';
import { makeEvidence, makeFinding, sanitizeText } from '../binary/util.js';
import { parseGzip, parseJpeg, parseOle2, parsePdf, parsePng } from './formats.js';
import { parseZip } from './zip.js';
import { quickDigest } from './hashes.js';

function capStrings(value, maxLen = 1000) {
  return sanitizeText(typeof value === 'string' ? value : '', maxLen);
}

function peMetadata(buffer, limits, env) {
  const parsed = parsePe(buffer, { maxSections: Math.min(limits.maxItems, 96) });
  const findings = [];
  const evidence = [];
  if (!parsed.ok) return { data: { format: 'pe', parseError: parsed.reason }, findings, evidence, warnings: parsed.warnings };
  const versionInfo = parsed.resources && parsed.resources.versionInfo ? parsed.resources.versionInfo : null;
  const debugEntries = parsed.debug ? parsed.debug.entries : [];
  const pdb = debugEntries.find((e) => e.codeview && e.codeview.pdbPath) || null;
  const compiledAt = parsed.coff.compiledAt;
  const data = {
    format: 'pe',
    machine: parsed.coff.machineName,
    bits: parsed.optional ? parsed.optional.bits : null,
    subsystem: parsed.optional ? parsed.optional.subsystemName : null,
    type: parsed.coff.characteristicFlags.includes('dll') ? 'dll' : 'executable',
    linkerVersion: parsed.optional ? parsed.optional.linkerVersion : null,
    imageBase: parsed.optional ? parsed.optional.imageBaseHex : null,
    entryPoint: parsed.optional ? parsed.optional.entryPointHex : null,
    sizeOfImage: parsed.optional ? parsed.optional.sizeOfImage : null,
    checksum: parsed.optional ? parsed.optional.checksum : null,
    compiledAt,
    compiledAtRaw: parsed.coff.timeDateStamp,
    timestampZero: parsed.coff.timeDateStamp === 0,
    dllCharacteristics: parsed.optional ? parsed.optional.dllCharacteristicFlags : [],
    sections: parsed.sections.length,
    overlay: parsed.overlay,
    resources: parsed.resources ? {
      present: parsed.resources.present,
      count: parsed.resources.count,
      types: parsed.resources.types.slice(0, 16),
      manifestPresent: parsed.resources.manifestPresent,
    } : null,
    versionInfo: versionInfo ? {
      present: versionInfo.rawVersionInfoPresent || Object.keys(versionInfo.strings).length > 0,
      fixedFileInfo: versionInfo.fixedFileInfo,
      strings: versionInfo.strings,
      extractionNote: versionInfo.extractionNote,
    } : null,
    debug: debugEntries.slice(0, 8).map((e) => ({
      type: e.typeName,
      timestamp: e.timestamp,
      pdbPath: e.codeview ? e.codeview.pdbPath : null,
      guid: e.codeview && e.codeview.guid ? e.codeview.guid : null,
      age: e.codeview && e.codeview.age !== undefined ? e.codeview.age : null,
    })),
    warnings: parsed.warnings.slice(0, 10),
  };
  if (versionInfo && Object.keys(versionInfo.strings).length > 0) {
    evidence.push(makeEvidence('PE 版本信息 (StringFileInfo)', 'pe-version-info',
      Object.entries(versionInfo.strings).map(([k, v]) => `${k}: ${capStrings(v, 300)}`).join('\n')));
  }
  if (pdb && pdb.codeview.pdbPath) {
    const pdbPath = capStrings(pdb.codeview.pdbPath, 500);
    findings.push(makeFinding({
      title: 'PE 调试信息泄露构建路径（PDB）',
      severity: 'info',
      description: `调试目录包含 CodeView PDB 路径：${pdbPath}。可能泄露开发者用户名/构建目录结构，属于发布卫生问题，需结合发布场景判断影响。`,
      verification: 'observed',
      method: '解析 PE 调试目录 CODEVIEW (RSDS/NB10) 记录',
      cwe: 'CWE-200',
      cvss: null,
      remediation: '发布构建时剥离调试信息（如 /DEBUG:NONE 或 PDB 单独归档），避免路径泄露。',
      target: `pdb=${pdbPath}`,
      evidence: [makeEvidence('CodeView 记录', 'pe-codeview', JSON.stringify({
        pdbPath,
        guid: pdb.codeview.guid || null,
        age: pdb.codeview.age,
        timestamp: pdb.debug && pdb.debug.entries ? pdb.debug.entries[0].timestamp : null,
      }))],
    }));
  }
  if (parsed.coff.timeDateStamp === 0) {
    findings.push(makeFinding({
      title: 'PE 编译时间戳为 0（可能被清除/可复现构建）',
      severity: 'info',
      description: 'COFF TimeDateStamp 为 0，常见于可复现构建、时间戳被工具清零或伪造的样本。时间戳不作为可靠证据。',
      verification: 'observed',
      method: '读取 COFF 头 TimeDateStamp',
      remediation: '不要仅凭时间戳判定来源；结合签名、PDB GUID、代码特征与来源情报交叉验证。',
      target: null,
      evidence: [makeEvidence('COFF 时间戳', 'pe-timestamp', 'TimeDateStamp=0')],
    }));
  } else if (compiledAt && env && typeof env.nowIso === 'string') {
    const now = Date.parse(env.nowIso);
    const compiled = Date.parse(compiledAt);
    if (Number.isFinite(now) && Number.isFinite(compiled) && compiled > now + 24 * 3600 * 1000) {
      findings.push(makeFinding({
        title: 'PE 编译时间戳晚于分析时间（可疑）',
        severity: 'low',
        description: `编译时间戳 ${compiledAt} 晚于当前时间 ${env.nowIso}，可能是时钟错误或时间戳伪造；需人工复核。`,
        verification: 'hypothesis',
        method: '比较 COFF TimeDateStamp 与核心提供的 nowIso',
        remediation: '在来源与构建流程可核实时再确认；不要仅凭该字段定性。',
        target: null,
        evidence: [makeEvidence('时间比较', 'pe-timestamp-future', `compiledAt=${compiledAt} now=${env.nowIso}`)],
      }));
    }
  }
  return { data, findings, evidence, warnings: parsed.warnings };
}

function elfMetadata(buffer, limits) {
  const parsed = parseElf(buffer, { maxSymbols: 0 });
  if (!parsed.ok) return { data: { format: 'elf', parseError: parsed.reason }, findings: [], evidence: [], warnings: parsed.warnings };
  const data = {
    format: 'elf',
    type: parsed.header.typeName,
    machine: parsed.header.machineName,
    bits: parsed.identity.classBits,
    endianness: parsed.identity.endianness,
    osabi: parsed.identity.osabiName,
    entryPoint: parsed.header.entryPoint,
    buildId: parsed.buildId,
    interpreter: parsed.interp,
    soname: parsed.dynamic.soname,
    needed: parsed.dynamic.needed,
    rpath: parsed.dynamic.rpath,
    runpath: parsed.dynamic.runpath,
    sections: parsed.sections.length,
    programHeaders: parsed.programHeaders.length,
    notes: parsed.notes.slice(0, 16),
    timestamps: [],
    note: 'ELF 结构本身不包含编译/修改时间戳；时间信息通常来自文件系统、打包流程或外部构建记录。',
    warnings: parsed.warnings.slice(0, 10),
  };
  const evidence = [];
  if (parsed.buildId) {
    evidence.push(makeEvidence('ELF build-id', 'elf-build-id', `build-id=${parsed.buildId}`));
  }
  if (parsed.notes.length > 0) {
    evidence.push(makeEvidence('ELF note 段', 'elf-notes', parsed.notes.map((n) => `${n.name}/${n.typeName} size=${n.descSize}${n.buildId ? ` buildId=${n.buildId}` : ''}`).join('\n')));
  }
  return { data, findings: [], evidence, warnings: parsed.warnings };
}

function machoMetadata(buffer, limits) {
  const parsed = parseMachO(buffer, { maxSymbols: 0 });
  if (!parsed.ok) return { data: { format: 'macho', parseError: parsed.reason }, findings: [], evidence: [], warnings: [] };
  const images = parsed.fat ? parsed.slices.filter((s) => s.ok).map((s) => s.image) : [parsed.slices[0]];
  const data = {
    format: 'macho',
    fat: parsed.fat,
    archCount: parsed.fat ? parsed.archCount : 1,
    slices: images.slice(0, 8).map((image) => ({
      arch: image.header.arch,
      bits: image.header.bits,
      fileType: image.header.fileTypeName,
      uuid: image.uuid,
      entryPoint: image.entryPoint,
      buildVersion: image.buildVersion,
      sourceVersion: image.sourceVersion,
      minVersion: image.loadCommands.find((c) => c.versionMin) ? image.loadCommands.find((c) => c.versionMin).versionMin : null,
      dylibCount: image.imports.dylibCount,
      dylibs: image.imports.dylibs.slice(0, 32),
      rpaths: image.rpaths,
      codesign: image.codesign,
      encryption: image.encryption,
      segments: image.segments.length,
      sections: image.sections.length,
      warnings: image.warnings.slice(0, 6),
    })),
    note: 'Mach-O 结构不含通用编译时间戳；LC_BUILD_VERSION 提供平台/minos/sdk，UUID 可用于符号匹配。',
    warnings: parsed.warnings.slice(0, 10),
  };
  const evidence = [];
  for (const slice of data.slices) {
    if (slice.uuid) evidence.push(makeEvidence(`Mach-O UUID (${slice.arch})`, 'macho-uuid', `uuid=${slice.uuid}${slice.buildVersion ? ` platform=${slice.buildVersion.platformName} minos=${slice.buildVersion.minos} sdk=${slice.buildVersion.sdk}` : ''}`));
  }
  return { data, findings: [], evidence, warnings: parsed.warnings };
}

function zipMetadata(buffer, limits, typeInfo) {
  const parsed = parseZip(buffer, { maxEntries: Math.min(limits.maxItems, 200) });
  const data = {
    format: 'zip',
    subtype: typeInfo.type,
    entryCount: parsed.declaredEntryCount,
    parsedEntries: parsed.parsedEntryCount,
    zip64: parsed.zip64,
    scannedLocally: parsed.scannedLocally,
    comment: parsed.comment,
    encryptedEntryCount: parsed.entries.filter((e) => e.encrypted).length,
    totalUncompressed: parsed.entries.reduce((acc, e) => acc + (Number.isFinite(e.uncompressedSize) ? e.uncompressedSize : 0), 0),
    entries: parsed.entries.slice(0, Math.min(limits.maxItems, 100)).map((e) => ({
      name: e.name,
      method: e.methodName,
      compressedSize: e.compressedSize,
      uncompressedSize: e.uncompressedSize,
      encrypted: e.encrypted,
      directory: e.isDirectory,
      timestamp: e.timestamp || null,
      extraTimes: e.extraTimes || null,
    })),
    warnings: parsed.warnings.slice(0, 10),
  };
  const findings = [];
  if (data.encryptedEntryCount > 0) {
    findings.push(makeFinding({
      title: `ZIP 包含 ${data.encryptedEntryCount} 个加密条目`,
      severity: 'info',
      description: '归档条目设置了加密标志，离线静态分析无法读取其内容；需要口令或经授权解密后再分析。',
      verification: 'observed',
      method: '读取中央目录通用标志位 bit0',
      remediation: '在授权前提下获取口令并解密到隔离目录后再分析；不要尝试破解口令。',
      target: null,
      evidence: [makeEvidence('加密条目', 'zip-encrypted', parsed.entries.filter((e) => e.encrypted).slice(0, 10).map((e) => e.name).join('\n'))],
    }));
  }
  const evidence = [makeEvidence('ZIP 目录', 'zip-central-directory',
    `entries=${data.parsedEntries}/${data.entryCount} zip64=${data.zip64} scannedLocally=${data.scannedLocally}\n${data.entries.slice(0, 10).map((e) => `${e.name} (${e.uncompressedSize} B, ${e.method})`).join('\n')}`)];
  return { data, findings, evidence, warnings: parsed.warnings };
}

function pngMetadata(buffer) {
  const parsed = parsePng(buffer);
  const data = {
    format: 'png',
    width: parsed.width,
    height: parsed.height,
    bitDepth: parsed.bitDepth,
    colorType: parsed.colorTypeName,
    interlace: parsed.interlace,
    text: parsed.text,
    time: parsed.time,
    chunkCount: parsed.chunks.length,
    chunkTypes: [...new Set(parsed.chunks.map((c) => c.type))],
    truncated: parsed.truncated,
    notes: parsed.notes,
  };
  const evidence = [];
  if (parsed.time) evidence.push(makeEvidence('PNG tIME', 'png-time', JSON.stringify(parsed.time)));
  if (Object.keys(parsed.text).length > 0) evidence.push(makeEvidence('PNG 文本块', 'png-text', Object.entries(parsed.text).map(([k, v]) => `${k}: ${capStrings(v, 300)}`).join('\n')));
  return { data, findings: [], evidence, warnings: parsed.notes };
}

function jpegMetadata(buffer) {
  const parsed = parseJpeg(buffer);
  const exifFields = parsed.exif ? parsed.exif.fields : {};
  const data = {
    format: 'jpeg',
    width: parsed.width,
    height: parsed.height,
    components: parsed.components,
    hasExif: parsed.hasExif,
    exif: parsed.exif ? {
      byteOrder: parsed.exif.byteOrder,
      ifd0EntryCount: parsed.exif.ifd0EntryCount,
      exifIfdEntryCount: parsed.exif.exifIfdEntryCount,
      fields: exifFields,
    } : null,
    segments: parsed.segments.slice(0, 64),
    truncated: parsed.truncated,
    notes: parsed.notes,
  };
  const findings = [];
  const software = typeof exifFields.Software === 'string' ? exifFields.Software : null;
  const make = typeof exifFields.Make === 'string' ? exifFields.Make : null;
  const evidence = [];
  if (parsed.hasExif) {
    evidence.push(makeEvidence('EXIF 字段', 'jpeg-exif', Object.entries(exifFields).map(([k, v]) => `${k}: ${capStrings(String(v), 300)}`).join('\n')));
  }
  if (software) {
    findings.push(makeFinding({
      title: 'JPEG EXIF 包含制作软件标识',
      severity: 'info',
      description: `EXIF Software 字段为 ${software}${make ? `（设备厂商 ${make}）` : ''}；可辅助来源研判，但可被伪造。`,
      verification: 'observed',
      method: '解析 JPEG APP1 EXIF TIFF IFD',
      remediation: '仅作为来源线索；如需发布照片请清除 EXIF 隐私信息。',
      target: null,
      evidence: [makeEvidence('EXIF Software', 'jpeg-software', `Software=${software}${make ? ` Make=${make}` : ''}`)],
    }));
  }
  return { data, findings, evidence, warnings: parsed.notes };
}

function ole2Metadata(buffer) {
  const parsed = parseOle2(buffer);
  return {
    data: {
      format: 'ole2',
      majorVersion: parsed.majorVersion,
      sectorShift: parsed.sectorShift,
      miniSectorShift: parsed.miniSectorShift,
      streamHints: parsed.streamHints,
      notes: parsed.notes,
    },
    findings: [],
    evidence: parsed.streamHints.length > 0
      ? [makeEvidence('OLE2 流名线索', 'ole2-streams', parsed.streamHints.join(', '))]
      : [],
    warnings: parsed.notes,
  };
}

function gzipMetadata(buffer) {
  const parsed = parseGzip(buffer);
  return {
    data: {
      format: 'gzip',
      mtime: parsed.mtime,
      mtimeRaw: parsed.mtimeRaw,
      originalName: parsed.originalName,
      comment: parsed.comment || null,
      flags: parsed.flags,
      os: parsed.os,
      notes: parsed.notes,
    },
    findings: [],
    evidence: parsed.originalName
      ? [makeEvidence('gzip 原始文件名', 'gzip-name', `name=${parsed.originalName} mtime=${parsed.mtime ? parsed.mtime.iso : 'n/a'}`)]
      : [],
    warnings: parsed.notes,
  };
}

function pdfMetadata(buffer) {
  const parsed = parsePdf(buffer);
  return {
    data: {
      format: 'pdf',
      version: parsed.version,
      producer: parsed.producer,
      creator: parsed.creator,
      creationDate: parsed.creationDate,
      modDate: parsed.modDate,
      notes: parsed.notes,
    },
    findings: [],
    evidence: (parsed.producer || parsed.creator)
      ? [makeEvidence('PDF Info', 'pdf-info', `Producer=${parsed.producer || 'n/a'}\nCreator=${parsed.creator || 'n/a'}`)]
      : [],
    warnings: parsed.notes,
  };
}

/**
 * @returns {{summary:string, data:object, findings:Array, evidence:Array, warnings:string[]}}
 */
export function extractMetadata(buffer, typeInfo, limits, env = {}) {
  const type = typeInfo.type;
  let outcome;
  try {
    if (type === 'pe-executable' || type === 'pe-dll') outcome = peMetadata(buffer, limits, env);
    else if (type.startsWith('elf')) outcome = elfMetadata(buffer, limits);
    else if (type === 'mach-o' || type === 'mach-o-universal') outcome = machoMetadata(buffer, limits);
    else if (['zip', 'docx', 'xlsx', 'pptx', 'ooxml', 'apk', 'jar', 'epub', 'odf'].includes(type)) outcome = zipMetadata(buffer, limits, typeInfo);
    else if (type === 'png') outcome = pngMetadata(buffer);
    else if (type === 'jpeg') outcome = jpegMetadata(buffer);
    else if (type === 'ole2' || type === 'doc' || type === 'xls' || type === 'ppt' || type === 'msi-or-encrypted-ole2') outcome = ole2Metadata(buffer);
    else if (type === 'gzip') outcome = gzipMetadata(buffer);
    else if (type === 'pdf') outcome = pdfMetadata(buffer);
    else {
      outcome = {
        data: {
          format: type,
          category: typeInfo.category,
          mime: typeInfo.mime,
          note: `格式 ${type} 暂无结构化元数据解析器；可改用 forensics.hash / forensics.filetype / binary.strings。`,
          fileTypeDetails: typeInfo.details,
        },
        findings: [],
        evidence: [makeEvidence('文件类型', 'filetype', `${typeInfo.type} / ${typeInfo.mime} / confidence=${typeInfo.confidence}`)],
        warnings: [],
      };
    }
  } catch (err) {
    outcome = {
      data: { format: type, parseError: `解析异常：${err && err.message ? err.message : String(err)}`, note: '结构异常，返回结构化错误而不是崩溃。' },
      findings: [],
      evidence: [],
      warnings: [`元数据解析异常：${err && err.message ? err.message : String(err)}`],
    };
  }
  const sha256 = quickDigest(buffer, 'sha256');
  const data = {
    ...outcome.data,
    byteSize: buffer.length,
    fileType: { type: typeInfo.type, category: typeInfo.category, mime: typeInfo.mime, confidence: typeInfo.confidence },
    sha256,
  };
  const summary = buildMetadataSummary(data);
  return { summary, data, findings: outcome.findings, evidence: outcome.evidence, warnings: outcome.warnings || [] };
}

function buildMetadataSummary(data) {
  if (data.parseError) return `元数据解析失败（${data.format}）：${data.parseError}`;
  switch (data.format) {
    case 'pe':
      return [
        `PE 元数据：${data.machine || '未知架构'} ${data.bits || '?'} 位，${data.type}，子系统 ${data.subsystem || 'n/a'}，链接器 ${data.linkerVersion}。`,
        `编译时间 ${data.compiledAt || '无/为 0'}；镜像大小 ${data.sizeOfImage || 'n/a'} 字节；节 ${data.sections} 个；overlay ${data.overlay && data.overlay.present ? `${data.overlay.size} 字节` : '无'}。`,
        data.versionInfo && data.versionInfo.present
          ? `版本信息：${Object.entries(data.versionInfo.strings || {}).slice(0, 6).map(([k, v]) => `${k}=${capStrings(v, 80)}`).join('; ') || `固定版本 ${data.versionInfo.fixedFileInfo ? data.versionInfo.fixedFileInfo.fileVersion : 'n/a'}`}`
          : '无版本信息资源。',
        data.debug && data.debug.some((d) => d.pdbPath) ? `调试 PDB：${data.debug.find((d) => d.pdbPath).pdbPath}` : '',
      ].filter(Boolean).join('\n');
    case 'elf':
      return [
        `ELF 元数据：${data.machine} ${data.bits} 位，${data.type}，OSABI ${data.osabi}。`,
        `build-id ${data.buildId || '缺失'}；解释器 ${data.interpreter || '无'}；依赖 ${ (data.needed || []).join(', ') || '无'}；rpath=${data.rpath || 'n/a'} runpath=${data.runpath || 'n/a'}。`,
        data.note,
      ].join('\n');
    case 'macho':
      return [
        `Mach-O 元数据：${data.fat ? `universal（${data.archCount} 架构）` : `${data.slices[0] ? data.slices[0].arch : '?'} ${data.slices[0] ? data.slices[0].bits : '?'} 位`}。`,
        ...data.slices.slice(0, 4).map((s) => `${s.arch}: UUID=${s.uuid || '无'} types=${s.fileType} build=${s.buildVersion ? `${s.buildVersion.platformName}/${s.buildVersion.minos}` : 'n/a'} dylibs=${s.dylibCount}`),
        data.note,
      ].join('\n');
    case 'zip':
      return [
        `ZIP 元数据：子类型 ${data.subtype}，条目 ${data.parsedEntries}/${data.entryCount}，zip64=${data.zip64}，加密条目 ${data.encryptedEntryCount}，解压后总大小 ${data.totalUncompressed} 字节。`,
        data.comment ? `归档注释：${capStrings(data.comment, 200)}` : '',
        `示例条目：${data.entries.slice(0, 6).map((e) => e.name).join(', ')}`,
      ].filter(Boolean).join('\n');
    case 'png':
      return `PNG 元数据：${data.width}×${data.height}，位深 ${data.bitDepth}，颜色类型 ${data.colorType}，块 ${data.chunkCount} 个${data.time ? `，tIME=${data.time.iso}` : ''}。`;
    case 'jpeg':
      return `JPEG 元数据：${data.width}×${data.height}，EXIF=${data.hasExif ? '有' : '无'}${data.exif && data.exif.fields.Make ? `，Make=${data.exif.fields.Make}` : ''}${data.exif && data.exif.fields.Software ? `，Software=${data.exif.fields.Software}` : ''}，段 ${data.segments.length} 个。`;
    case 'ole2':
      return `OLE2/CFB 元数据：majorVersion=${data.majorVersion}，sectorShift=${data.sectorShift}，流名线索：${data.streamHints.join(', ') || '无'}。`;
    case 'gzip':
      return `gzip 元数据：mtime=${data.mtime ? data.mtime.iso : '无'}，原始文件名=${data.originalName || '无'}。`;
    case 'pdf':
      return `PDF 元数据：版本 ${data.version}，Producer=${data.producer || 'n/a'}，Creator=${data.creator || 'n/a'}，创建=${data.creationDate ? data.creationDate.iso : 'n/a'}。`;
    default:
      return `格式 ${data.format}：${data.note || '无结构化元数据。'}`;
  }
}
