// ArmorBreak - APK 签名方案检测（v1 META-INF / v2 / v3 / v3.1 签名块）
// 只做“读取与摘要”：提取签名块结构、签名证书 DER、证书 SHA-256 与主体信息。
// 不实现密码学验签（不验证 PKCS#7/SignedData 签名值），输出中明确标注。
import { createHash } from 'node:crypto';
import { readEntryData } from './zip.js';
import { sanitizeText } from './util.js';

export const APK_SIG_BLOCK_MAGIC = Buffer.from('APK Sig Block 42', 'latin1');
export const V2_BLOCK_ID = 0x7109871a;
export const V3_BLOCK_ID = 0xf05368c0;
export const V31_BLOCK_ID = 0x1b93ad61;

export class SignatureError extends Error {
  constructor(message, detail = null) {
    super(message);
    this.name = 'SignatureError';
    this.detail = detail;
  }
}

// ---------------------------------------------------------------------------
// 最小 DER/ASN.1 读取器（只覆盖证书与 PKCS#7 所需结构）
// ---------------------------------------------------------------------------

export function readTlv(buffer, offset, end = buffer.length) {
  if (offset < 0 || offset + 2 > end) return null;
  const tag = buffer[offset];
  let p = offset + 1;
  let lengthByte = buffer[p++];
  let length;
  if (lengthByte < 0x80) {
    length = lengthByte;
  } else {
    const n = lengthByte & 0x7f;
    if (n < 1 || n > 4 || p + n > end) return null;
    length = 0;
    for (let i = 0; i < n; i++) length = length * 256 + buffer[p++];
  }
  const valueStart = p;
  const valueEnd = p + length;
  if (valueEnd > end) return null;
  return { tag, start: offset, valueStart, valueEnd, value: buffer.subarray(valueStart, valueEnd), end: valueEnd };
}

export function tlvChildren(buffer, tlv, max = 256) {
  const children = [];
  let p = tlv.valueStart;
  while (p < tlv.valueEnd && children.length < max) {
    const child = readTlv(buffer, p, tlv.valueEnd);
    if (!child) break;
    children.push(child);
    p = child.end;
  }
  return children;
}

export function decodeOid(bytes) {
  if (bytes.length === 0) return '';
  const parts = [];
  let first = bytes[0];
  if (first < 40) parts.push(0, first);
  else if (first < 80) parts.push(1, first - 40);
  else parts.push(2, first - 80);
  let value = 0;
  for (let i = 1; i < bytes.length; i++) {
    value = value * 128 + (bytes[i] & 0x7f);
    if ((bytes[i] & 0x80) === 0) {
      parts.push(value);
      value = 0;
    }
  }
  if (value !== 0) parts.push(value);
  return parts.join('.');
}

const NAME_ATTRS = new Map([
  ['2.5.4.3', 'CN'],
  ['2.5.4.6', 'C'],
  ['2.5.4.7', 'L'],
  ['2.5.4.8', 'ST'],
  ['2.5.4.10', 'O'],
  ['2.5.4.11', 'OU'],
  ['1.2.840.113549.1.9.1', 'emailAddress'],
]);

function derStringValue(tlv) {
  if (!tlv) return null;
  const isStringTag =
    tlv.tag === 0x0c || // UTF8String
    tlv.tag === 0x13 || // PrintableString
    tlv.tag === 0x16 || // IA5String
    tlv.tag === 0x14 || // T61String
    tlv.tag === 0x1e; // BMPString
  if (!isStringTag) return null;
  if (tlv.tag === 0x1e) {
    try {
      return tlv.value.toString('utf16le');
    } catch {
      return null;
    }
  }
  return tlv.value.toString('utf8');
}

/** 解析 X.509 Name（SEQUENCE of RDN SET of {OID,value}）。 */
export function parseX509Name(buffer, nameTlv) {
  const out = {};
  const raw = [];
  if (!nameTlv || nameTlv.tag !== 0x30) return { name: out, raw };
  for (const rdnSet of tlvChildren(buffer, nameTlv, 64)) {
    if (rdnSet.tag !== 0x31) continue;
    for (const attrSeq of tlvChildren(buffer, rdnSet, 16)) {
      if (attrSeq.tag !== 0x30) continue;
      const parts = tlvChildren(buffer, attrSeq, 4);
      if (parts.length < 2 || parts[0].tag !== 0x06) continue;
      const oid = decodeOid(parts[0].value);
      const value = derStringValue(parts[1]);
      if (value === null) continue;
      const key = NAME_ATTRS.get(oid) || oid;
      if (!out[key]) out[key] = sanitizeText(value, 200);
      raw.push({ oid, name: key, value: sanitizeText(value, 200) });
    }
  }
  return { name: out, raw };
}

function parseDerTime(tlv) {
  if (!tlv) return null;
  const text = tlv.value.toString('latin1').replace(/Z$/, '');
  let year;
  let rest;
  if (tlv.tag === 0x17) {
    // UTCTime: YYMMDDHHMMSS[Z]
    if (!/^\d{10,}$/.test(text)) return null;
    const yy = Number(text.slice(0, 2));
    year = yy >= 50 ? 1900 + yy : 2000 + yy;
    rest = text.slice(2);
  } else if (tlv.tag === 0x18) {
    // GeneralizedTime: YYYYMMDDHHMMSS[.fff][Z]
    if (!/^\d{12,}$/.test(text)) return null;
    year = Number(text.slice(0, 4));
    rest = text.slice(4);
  } else {
    return null;
  }
  const month = Number(rest.slice(0, 2));
  const day = Number(rest.slice(2, 4));
  const hour = Number(rest.slice(4, 6) || '0');
  const minute = Number(rest.slice(6, 8) || '0');
  const second = Number(rest.slice(8, 10) || '0');
  if (![month, day, hour, minute, second].every(Number.isFinite)) return null;
  const iso = `${String(year).padStart(4, '0')}-${String(month).padStart(2, '0')}-${String(day).padStart(2, '0')}T${String(hour).padStart(2, '0')}:${String(minute).padStart(2, '0')}:${String(second).padStart(2, '0')}Z`;
  return iso;
}

/**
 * 解析 X.509 证书 DER 的最小公开字段。
 * @returns {{der:Buffer, sha256:string, serialHex:string|null, version:number, subject:object, issuer:object, notBefore:string|null, notAfter:string|null, signatureAlgorithm:string|null, subjectRaw:Array}|null}
 */
export function parseCertificate(der) {
  if (!Buffer.isBuffer(der) || der.length < 32) return null;
  const cert = readTlv(der, 0);
  if (!cert || cert.tag !== 0x30) return null;
  const certChildren = tlvChildren(der, cert, 8);
  const tbs = certChildren[0];
  if (!tbs || tbs.tag !== 0x30) return null;
  const tbsChildren = tlvChildren(der, tbs, 16);
  let version = 1;
  let idx = 0;
  if (tbsChildren[0] && tbsChildren[0].tag === 0xa0) {
    const versionInt = tlvChildren(der, tbsChildren[0], 2)[0];
    if (versionInt && versionInt.tag === 0x02) version = versionInt.value[versionInt.value.length - 1] + 1;
    idx = 1;
  }
  const serialTlv = tbsChildren[idx];
  const sigAlgTlv = tbsChildren[idx + 1] ?? certChildren[1];
  const issuerTlv = tbsChildren[idx + 2];
  const validityTlv = tbsChildren[idx + 3];
  const subjectTlv = tbsChildren[idx + 4];
  let serialHex = null;
  if (serialTlv && serialTlv.tag === 0x02) {
    let bytes = serialTlv.value;
    while (bytes.length > 1 && bytes[0] === 0x00) bytes = bytes.subarray(1);
    serialHex = bytes.toString('hex');
  }
  let notBefore = null;
  let notAfter = null;
  if (validityTlv && validityTlv.tag === 0x30) {
    const times = tlvChildren(der, validityTlv, 4);
    notBefore = parseDerTime(times[0]);
    notAfter = parseDerTime(times[1]);
  }
  let signatureAlgorithm = null;
  if (sigAlgTlv && sigAlgTlv.tag === 0x30) {
    const oidTlv = tlvChildren(der, sigAlgTlv, 2)[0];
    if (oidTlv && oidTlv.tag === 0x06) signatureAlgorithm = decodeOid(oidTlv.value);
  }
  const subject = parseX509Name(der, subjectTlv);
  const issuer = parseX509Name(der, issuerTlv);
  return {
    der,
    sha256: createHash('sha256').update(der).digest('hex'),
    serialHex,
    version,
    subject: subject.name,
    subjectRaw: subject.raw,
    issuer: issuer.name,
    notBefore,
    notAfter,
    signatureAlgorithm,
  };
}

// ---------------------------------------------------------------------------
// APK Signing Block（v2/v3/v3.1）
// ---------------------------------------------------------------------------

/**
 * 在中央目录前定位 APK Signing Block。
 * @returns {{offset:number, size:number, endOffset:number, pairs:Array<{id:number,idHex:string,size:number,value:Buffer}>}|null}
 */
export function findApkSigningBlock(buffer, centralDirOffset) {
  const end = centralDirOffset;
  if (!Number.isFinite(end) || end < 32 || end > buffer.length) return null;
  if (!buffer.subarray(end - 16, end).equals(APK_SIG_BLOCK_MAGIC)) return null;
  if (end < 24) return null;
  const sizeValue = buffer.readBigUInt64LE(end - 24);
  if (sizeValue > BigInt(buffer.length)) {
    throw new SignatureError(
      'APK Signing Block 大小字段越界（大于文件长度），签名块损坏。请用 apksigner verify 校验 APK。',
    );
  }
  const blockSize = Number(sizeValue);
  if (blockSize < 24) {
    throw new SignatureError(`APK Signing Block 大小字段异常（${blockSize} < 24），签名块损坏。`);
  }
  const offset = end - blockSize - 8;
  if (offset < 0) {
    throw new SignatureError('APK Signing Block 起始偏移为负，签名块损坏或被截断。');
  }
  const leadingSize = buffer.readBigUInt64LE(offset);
  if (leadingSize !== sizeValue) {
    throw new SignatureError(
      `APK Signing Block 前后大小字段不一致（${leadingSize} != ${sizeValue}），签名块损坏。`,
    );
  }
  const pairs = [];
  let p = offset + 8;
  const pairsEnd = end - 24;
  while (p + 4 <= pairsEnd) {
    if (p + 8 > pairsEnd) break;
    const pairSizeValue = buffer.readBigUInt64LE(p);
    if (pairSizeValue > BigInt(buffer.length)) break;
    const pairSize = Number(pairSizeValue);
    if (pairSize < 4 || p + 8 + pairSize > pairsEnd) break;
    const id = buffer.readUInt32LE(p + 8);
    const value = buffer.subarray(p + 12, p + 8 + pairSize);
    pairs.push({ id, idHex: `0x${id.toString(16).padStart(8, '0')}`, size: pairSize, value });
    p += 8 + pairSize;
  }
  return { offset, size: blockSize, endOffset: end, pairs };
}

/** 带边界检查的游标读取器。 */
class Cursor {
  constructor(buffer, start = 0, end = buffer.length) {
    this.buffer = buffer;
    this.pos = start;
    this.end = end;
    this.errors = [];
  }
  remaining() {
    return this.end - this.pos;
  }
  u32() {
    if (this.pos + 4 > this.end) {
      this.errors.push('读取 u32 越界');
      this.pos = this.end;
      return null;
    }
    const v = this.buffer.readUInt32LE(this.pos);
    this.pos += 4;
    return v;
  }
  lp() {
    const len = this.u32();
    if (len === null) return null;
    if (len > this.remaining()) {
      this.errors.push(`长度前缀 ${len} 超出剩余 ${this.remaining()} 字节`);
      this.pos = this.end;
      return null;
    }
    const slice = this.buffer.subarray(this.pos, this.pos + len);
    this.pos += len;
    return slice;
  }
}

/** 从 v2/v3 signer 的 signedData 中提取证书 DER 列表（不验签）。 */
function parseSignerBlock(value, blockLabel) {
  const outer = new Cursor(value);
  const signersLen = outer.u32();
  const certificates = [];
  const errors = [];
  let signerCount = 0;
  if (signersLen === null) return { signerCount: 0, certificates, errors: ['signers 长度缺失'] };
  if (signersLen > outer.remaining()) {
    return { signerCount: 0, certificates, errors: [`signers 长度 ${signersLen} 超出块大小 ${outer.remaining()}`] };
  }
  const signersRegion = value.subarray(outer.pos, outer.pos + signersLen);
  const signers = new Cursor(signersRegion);
  const maxSigners = 64;
  while (signers.remaining() > 0 && signerCount < maxSigners) {
    const signer = signers.lp();
    if (!signer) break;
    signerCount++;
    const sc = new Cursor(signer);
    const signedData = sc.lp();
    if (!signedData) {
      errors.push(`第 ${signerCount} 个 signer 的 signedData 缺失`);
      continue;
    }
    // signedData 结构：digests(lp) + certificates(lp) + ...（v2/v3/v3.1 此处一致）
    const sdc = new Cursor(signedData);
    const digests = sdc.lp();
    if (!digests) errors.push(`第 ${signerCount} 个 signer 缺少 digests`);
    const certsLp = sdc.lp();
    if (!certsLp) {
      errors.push(`第 ${signerCount} 个 signer 缺少 certificates`);
      continue;
    }
    const certs = new Cursor(certsLp);
    while (certs.remaining() > 0 && certificates.length < 32) {
      const certDer = certs.lp();
      if (!certDer) break;
      if (certDer.length === 0) continue;
      const parsed = parseCertificate(certDer);
      certificates.push(
        parsed || {
          der: certDer,
          sha256: createHash('sha256').update(certDer).digest('hex'),
          subject: {},
          issuer: {},
          notBefore: null,
          notAfter: null,
          parseError: `${blockLabel} 证书 DER 无法解析`,
        },
      );
    }
  }
  if (signers.remaining() > 0 && signerCount >= maxSigners) errors.push(`signer 数量超过上限 ${maxSigners}`);
  return { signerCount, certificates, errors };
}

function certSummary(cert) {
  return {
    sha256: cert.sha256,
    subject: cert.subject || {},
    issuer: cert.issuer || {},
    serialHex: cert.serialHex ?? null,
    version: cert.version ?? null,
    notBefore: cert.notBefore ?? null,
    notAfter: cert.notAfter ?? null,
    signatureAlgorithm: cert.signatureAlgorithm ?? null,
    derSize: cert.der ? cert.der.length : null,
    ...(cert.parseError ? { parseError: cert.parseError } : {}),
  };
}

/** 从 PKCS#7 SignedData（v1 META-INF/*.RSA|DSA|EC）中提取第一个证书 DER。 */
export function extractCertFromPkcs7(der) {
  const contentInfo = readTlv(der, 0);
  if (!contentInfo || contentInfo.tag !== 0x30) return { certificates: [], error: 'PKCS#7 ContentInfo 不是 SEQUENCE' };
  const ciChildren = tlvChildren(der, contentInfo, 8);
  if (ciChildren.length < 2) return { certificates: [], error: 'PKCS#7 ContentInfo 子结构不足' };
  const oidTlv = ciChildren[0];
  const contentType = oidTlv && oidTlv.tag === 0x06 ? decodeOid(oidTlv.value) : null;
  const explicit = ciChildren.find((c) => c.tag === 0xa0);
  if (!explicit) return { certificates: [], error: 'PKCS#7 缺少 [0] signedData 内容' };
  const signedDataWrapper = tlvChildren(der, explicit, 2)[0];
  if (!signedDataWrapper || signedDataWrapper.tag !== 0x30) {
    return { certificates: [], error: 'PKCS#7 signedData 不是 SEQUENCE' };
  }
  const sdChildren = tlvChildren(der, signedDataWrapper, 16);
  const certsTlv = sdChildren.find((c) => c.tag === 0xa0);
  if (!certsTlv) return { certificates: [], contentType, error: 'PKCS#7 未包含 certificates [0]' };
  const certificates = [];
  let p = certsTlv.valueStart;
  while (p < certsTlv.valueEnd && certificates.length < 32) {
    const certTlv = readTlv(der, p, certsTlv.valueEnd);
    if (!certTlv) break;
    if (certTlv.tag === 0x30) {
      const certDer = der.subarray(certTlv.start, certTlv.end);
      const parsed = parseCertificate(certDer);
      certificates.push(
        parsed || {
          der: certDer,
          sha256: createHash('sha256').update(certDer).digest('hex'),
          subject: {},
          issuer: {},
          parseError: 'v1 证书 DER 无法解析',
        },
      );
    }
    p = certTlv.end;
  }
  return { certificates, contentType, error: certificates.length === 0 ? 'PKCS#7 证书集合为空' : null };
}

const DEBUG_CERT_HINTS = [/android debug/i, /^android debug$/i, /debug\.keystore/i];

/** 分析 APK 签名（v1 + v2 + v3 + v3.1 检测）。 */
export function analyzeSigning(buffer, zip, opts = {}) {
  const maxCerts = Math.max(1, Math.min(opts.maxCerts ?? 16, 64));
  const warnings = [];
  const schemes = {
    v1: { present: false, files: [], certificates: [], errors: [] },
    v2: { present: false, blockId: null, signerCount: 0, certificates: [], errors: [] },
    v3: { present: false, blockId: null, signerCount: 0, certificates: [], errors: [] },
  };
  // v1：META-INF/*.RSA|DSA|EC
  const v1Entries = zip.entries.filter((e) => /^META-INF\/[^/]+\.(RSA|DSA|EC)$/i.test(e.name));
  const hasManifestMf = zip.entries.some((e) => e.name === 'META-INF/MANIFEST.MF');
  schemes.v1.present = v1Entries.length > 0;
  schemes.v1.hasManifestMf = hasManifestMf;
  if (hasManifestMf && v1Entries.length === 0) {
    warnings.push('存在 META-INF/MANIFEST.MF 但缺少 .RSA/.DSA/.EC 签名块文件：v1 签名可能已被剥离或仅部分保留。');
  }
  for (const entry of v1Entries.slice(0, maxCerts)) {
    schemes.v1.files.push(sanitizeText(entry.name, 200));
    try {
      const der = readEntryData(buffer, entry, { maxBytes: opts.maxEntryBytes ?? 4 * 1024 * 1024 });
      const extracted = extractCertFromPkcs7(der);
      if (extracted.error) schemes.v1.errors.push(`${sanitizeText(entry.name, 200)}: ${extracted.error}`);
      for (const cert of extracted.certificates) {
        if (schemes.v1.certificates.length < maxCerts) schemes.v1.certificates.push(certSummary(cert));
      }
    } catch (err) {
      schemes.v1.errors.push(`${sanitizeText(entry.name, 200)}: ${err.message}`);
    }
  }
  if (v1Entries.length > maxCerts) warnings.push(`v1 签名文件超过 ${maxCerts} 个，已截断。`);
  schemes.v1.certificates = schemes.v1.certificates.slice(0, maxCerts);

  // v2/v3：APK Signing Block
  let block = null;
  try {
    block = findApkSigningBlock(buffer, zip.centralDirOffset);
  } catch (err) {
    warnings.push(`APK Signing Block 解析失败：${err.message}`);
  }
  let signingBlock = null;
  if (block) {
    signingBlock = {
      offset: block.offset,
      size: block.size,
      pairCount: block.pairs.length,
      pairs: block.pairs.map((p) => ({ id: p.idHex, size: p.size })),
    };
    const v2Pair = block.pairs.find((p) => p.id === V2_BLOCK_ID);
    if (v2Pair) {
      schemes.v2.present = true;
      schemes.v2.blockId = v2Pair.idHex;
      const parsed = parseSignerBlock(v2Pair.value, 'v2');
      schemes.v2.signerCount = parsed.signerCount;
      schemes.v2.errors.push(...parsed.errors);
      for (const cert of parsed.certificates.slice(0, maxCerts)) schemes.v2.certificates.push(certSummary(cert));
    }
    const v3Pairs = block.pairs.filter((p) => p.id === V3_BLOCK_ID || p.id === V31_BLOCK_ID);
    if (v3Pairs.length > 0) {
      schemes.v3.present = true;
      schemes.v3.blockId = v3Pairs[0].idHex;
      for (const pair of v3Pairs) {
        const parsed = parseSignerBlock(pair.value, pair.id === V31_BLOCK_ID ? 'v3.1' : 'v3');
        schemes.v3.signerCount += parsed.signerCount;
        schemes.v3.errors.push(...parsed.errors);
        for (const cert of parsed.certificates) {
          if (schemes.v3.certificates.length < maxCerts) schemes.v3.certificates.push(certSummary(cert));
        }
      }
    }
  }

  const allCerts = [];
  const seenHashes = new Set();
  for (const scheme of ['v3', 'v2', 'v1']) {
    for (const cert of schemes[scheme].certificates) {
      if (seenHashes.has(cert.sha256)) continue;
      seenHashes.add(cert.sha256);
      allCerts.push({ scheme, ...cert });
    }
  }
  const debugHints = [];
  for (const cert of allCerts) {
    const subjectText = Object.values(cert.subject || {}).join(' ');
    const issuerText = Object.values(cert.issuer || {}).join(' ');
    if (DEBUG_CERT_HINTS.some((re) => re.test(subjectText) || re.test(issuerText))) {
      debugHints.push({ sha256: cert.sha256, scheme: cert.scheme, reason: '证书 subject/issuer 含 "Android Debug" 字样（通常为调试签名）' });
    }
  }
  if (!schemes.v1.present && !schemes.v2.present && !schemes.v3.present) {
    warnings.push('未发现 v1/v2/v3 签名记录：APK 可能未签名、签名已被剥离，或仅使用 APK Signature Scheme v4（.idsig 独立文件，不在此容器内）。');
  }
  if (schemes.v1.present && !schemes.v2.present && !schemes.v3.present) {
    warnings.push('仅存在 v1（JAR）签名：Android 7.0+ 建议 v2+，v1-only 更易受签名剥离/篡改影响。');
  }
  return {
    schemes,
    certificates: allCerts,
    certificateCount: allCerts.length,
    firstCertSha256: allCerts.length > 0 ? allCerts[0].sha256 : null,
    debugCertHint: debugHints.length > 0,
    debugCertDetails: debugHints,
    signingBlock,
    hasV1: schemes.v1.present,
    hasV2: schemes.v2.present,
    hasV3: schemes.v3.present,
    verifyingPolicy: '仅做结构与证书摘要，不执行密码学验签（v1 PKCS#7 / v2-v3 签名值均未验证）',
    warnings,
  };
}
