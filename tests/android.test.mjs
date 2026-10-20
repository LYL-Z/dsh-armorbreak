// ArmorBreak - android 域测试（node:test，零依赖，fixture 全部程序化构造）
// 覆盖：APK ZIP 结构、AXML 解码、DEX 解析、v1/v2/v3 签名证书提取、findings、畸形/截断/确定性。
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { deflateRawSync } from 'node:zlib';

import androidManifest from '../lib/analyzers/android/manifest.js';
import { parseAxml, findElements, attr } from '../lib/analyzers/android/axml.js';
import { parseZip } from '../lib/analyzers/android/zip.js';
import { parseDex } from '../lib/analyzers/android/dex.js';
import { enforceDataBudget } from '../lib/analyzers/android/util.js';

// ---------------------------------------------------------------------------
// 通用工具
// ---------------------------------------------------------------------------

function cap(id) {
  const found = androidManifest.capabilities.find((c) => c.id === id);
  assert.ok(found, `capability ${id} 必须存在`);
  return found;
}

function makeInput(buffer, options = {}, limits = {}) {
  return {
    targetPath: 'D:\\fixtures\\sample.apk',
    buffer,
    text: buffer ? buffer.toString('utf8') : null,
    options,
    limits: { maxBytes: 8 * 1024 * 1024, maxItems: 200, maxStrings: 500, maxFindings: 100, timeoutMs: 30000, ...limits },
    env: {
      signal: new AbortController().signal,
      workspaceRoot: 'D:\\fixtures',
      nowIso: '2026-01-01T00:00:00Z',
      log: () => {},
    },
  };
}

function sha256(buf) {
  return createHash('sha256').update(buf).digest('hex');
}

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(buf) {
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i++) crc = CRC_TABLE[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

function u16(buf, value, off) {
  buf.writeUInt16LE(value, off);
}
function u32(buf, value, off) {
  buf.writeUInt32LE(value, off);
}
function u64(buf, value, off) {
  buf.writeBigUInt64LE(BigInt(value), off);
}

// ---------------------------------------------------------------------------
// 最小 ZIP 写入器（store + deflate；可选 v2/v3 签名块）
// ---------------------------------------------------------------------------

function buildZip(entries, opts = {}) {
  const localParts = [];
  const localOffsets = [];
  const prepared = [];
  let offset = 0;
  for (const entry of entries) {
    const nameBuf = Buffer.from(entry.name, 'utf8');
    const raw = Buffer.isBuffer(entry.data) ? entry.data : Buffer.from(String(entry.data), 'utf8');
    const method = entry.method === 'deflate' ? 8 : 0;
    const stored = method === 8 ? deflateRawSync(raw) : raw;
    const crc = crc32(raw);
    const local = Buffer.alloc(30);
    u32(local, 0x04034b50, 0); // local file header sig
    u16(local, 20, 4); // version needed
    u16(local, 0x800, 6); // flags: UTF-8
    u16(local, method, 8);
    u16(local, 0, 10); // mod time
    u16(local, 0x21, 12); // mod date
    u32(local, crc, 14);
    u32(local, stored.length, 18);
    u32(local, raw.length, 22);
    u16(local, nameBuf.length, 26);
    u16(local, 0, 28); // extra len
    localOffsets.push(offset);
    const part = Buffer.concat([local, nameBuf, stored]);
    localParts.push(part);
    offset += part.length;
    prepared.push({ entry, nameBuf, method, stored, raw, crc });
  }
  const entriesEnd = offset;
  const signingBlock = opts.signingBlock ? Buffer.from(opts.signingBlock) : null;
  let cdOffset = entriesEnd;
  if (signingBlock) cdOffset += signingBlock.length;
  const centralParts = [];
  prepared.forEach((item, index) => {
    const central = Buffer.alloc(46);
    u32(central, 0x02014b50, 0); // central header sig
    u16(central, 0x031e, 4); // version made by (unix/3.0)
    u16(central, 20, 6); // version needed
    u16(central, 0x800, 8); // flags
    u16(central, item.method, 10);
    u16(central, 0, 12);
    u16(central, 0x21, 14);
    u32(central, item.crc, 16);
    u32(central, item.stored.length, 20);
    u32(central, item.raw.length, 24);
    u16(central, item.nameBuf.length, 28);
    u16(central, 0, 30); // extra
    u16(central, 0, 32); // comment
    u16(central, 0, 34); // disk start
    u16(central, 0, 36); // internal attrs
    u32(central, 0, 38); // external attrs
    u32(central, localOffsets[index], 42);
    centralParts.push(Buffer.concat([central, item.nameBuf]));
  });
  const cd = Buffer.concat(centralParts);
  const commentBuf = opts.comment ? Buffer.from(opts.comment, 'utf8') : Buffer.alloc(0);
  const eocd = Buffer.alloc(22);
  u32(eocd, 0x06054b50, 0);
  u16(eocd, 0, 4);
  u16(eocd, 0, 6);
  const parts = [...localParts];
  if (signingBlock) parts.push(signingBlock);
  parts.push(cd);
  if (opts.zip64) {
    // ZIP64 EOCD + locator + 带哨兵值的经典 EOCD
    const zip64EocdOffset = cdOffset + cd.length;
    const zip64 = Buffer.alloc(56);
    u32(zip64, 0x06064b50, 0);
    u64(zip64, 44, 4); // size of zip64 EOCD record - 12
    u16(zip64, 45, 12);
    u16(zip64, 45, 14);
    u32(zip64, 0, 16);
    u32(zip64, 0, 20);
    u64(zip64, prepared.length, 24);
    u64(zip64, prepared.length, 32);
    u64(zip64, cd.length, 40);
    u64(zip64, cdOffset, 48);
    const locator = Buffer.alloc(20);
    u32(locator, 0x07064b50, 0);
    u32(locator, 0, 4);
    u64(locator, zip64EocdOffset, 8);
    u32(locator, 1, 16);
    u16(eocd, 0xffff, 8);
    u16(eocd, 0xffff, 10);
    u32(eocd, 0xffffffff, 12);
    u32(eocd, 0xffffffff, 16);
    u16(eocd, 0, 20);
    parts.push(zip64, locator, eocd);
  } else {
    u16(eocd, prepared.length, 8);
    u16(eocd, prepared.length, 10);
    u32(eocd, cd.length, 12);
    u32(eocd, cdOffset, 16);
    u16(eocd, commentBuf.length, 20);
    parts.push(eocd, commentBuf);
  }
  return Buffer.concat(parts);
}

// ---------------------------------------------------------------------------
// DER / X.509 / PKCS#7 构造器（用于签名测试）
// ---------------------------------------------------------------------------

function derLength(length) {
  if (length < 0x80) return Buffer.from([length]);
  const bytes = [];
  let n = length;
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n >>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function der(tag, content) {
  return Buffer.concat([Buffer.from([tag]), derLength(content.length), content]);
}

function derSeq(...items) {
  return der(0x30, Buffer.concat(items));
}
function derSet(...items) {
  return der(0x31, Buffer.concat(items));
}
function derUtf8(text) {
  return der(0x0c, Buffer.from(text, 'utf8'));
}
function derUtcTime(text) {
  return der(0x17, Buffer.from(text, 'latin1'));
}
function derInt(value) {
  if (value === 0) return der(0x02, Buffer.from([0]));
  const bytes = [];
  let n = value;
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n >>= 8;
  }
  if (bytes[0] & 0x80) bytes.unshift(0);
  return der(0x02, Buffer.from(bytes));
}
function derBitString(bytes) {
  return der(0x03, Buffer.concat([Buffer.from([0]), bytes]));
}
function derOid(dotted) {
  const parts = dotted.split('.').map(Number);
  const bytes = [parts[0] * 40 + parts[1]];
  for (const part of parts.slice(2)) {
    const stack = [part & 0x7f];
    let n = part >> 7;
    while (n > 0) {
      stack.unshift((n & 0x7f) | 0x80);
      n >>= 7;
    }
    bytes.push(...stack);
  }
  return der(0x06, Buffer.from(bytes));
}

const SHA256_RSA_OID = '1.2.840.113549.1.1.11';
const RSA_OID = '1.2.840.113549.1.1.1';

/** 构造一张 CN=Android Debug, O=Android 的自签 DER 证书（仅结构可解析，签名值为占位）。 */
function buildDebugCertDer() {
  const sigAlg = derSeq(derOid(SHA256_RSA_OID), der(0x05, Buffer.alloc(0)));
  const name = derSeq(
    derSet(derSeq(derOid('2.5.4.3'), derUtf8('Android Debug'))),
    derSet(derSeq(derOid('2.5.4.10'), derUtf8('Android'))),
  );
  const validity = derSeq(derUtcTime('200101000000Z'), derUtcTime('491231235959Z'));
  const spki = derSeq(derSeq(derOid(RSA_OID), der(0x05, Buffer.alloc(0))), derBitString(Buffer.alloc(16, 0x42)));
  const tbs = derSeq(
    der(0xa0, derInt(2)), // version v3
    derInt(1), // serial
    sigAlg,
    name, // issuer
    validity,
    name, // subject
    spki,
  );
  return derSeq(tbs, sigAlg, derBitString(Buffer.alloc(32, 0x11)));
}

/** 构造最小 PKCS#7 SignedData（v1 META-INF/*.RSA 内容）。 */
function buildPkcs7(certDer) {
  const signedData = derSeq(
    derInt(1),
    derSet(), // digestAlgorithms
    derSeq(derOid('1.2.840.113549.1.7.1')), // contentType: data
    der(0xa0, certDer), // certificates
    derSet(), // signerInfos
  );
  return derSeq(derOid('1.2.840.113549.1.7.2'), der(0xa0, signedData));
}

function lpLE(buf) {
  const header = Buffer.alloc(4);
  header.writeUInt32LE(buf.length, 0);
  return Buffer.concat([header, buf]);
}

/** 构造 APK Signature Scheme v2 signer 数据结构（不验签，仅供结构解析）。 */
function buildV2Value(certDer) {
  const digest = Buffer.concat([Buffer.alloc(4), lpLE(Buffer.alloc(32, 0xab))]);
  // digest record: sigAlgId(u32) + length-prefixed digest
  const digestRecord = Buffer.concat([Buffer.alloc(4), lpLE(Buffer.alloc(32, 0xab))]);
  digestRecord.writeUInt32LE(0x0103, 0);
  const digests = lpLE(lpLE(digestRecord));
  const certs = lpLE(lpLE(certDer));
  const signedData = Buffer.concat([digests, certs, lpLE(Buffer.alloc(0))]);
  const signatureRecord = Buffer.concat([Buffer.alloc(4), lpLE(Buffer.alloc(64, 0xcd))]);
  signatureRecord.writeUInt32LE(0x0103, 0);
  const signatures = lpLE(lpLE(signatureRecord));
  const publicKey = lpLE(Buffer.alloc(32, 0x33));
  const signer = Buffer.concat([lpLE(signedData), lpLE(signatures), publicKey]);
  return lpLE(lpLE(signer));
}

function buildSigningBlock(pairs) {
  const encodedPairs = pairs.map((pair) => {
    const value = Buffer.isBuffer(pair.value) ? pair.value : Buffer.from(pair.value);
    const sizeBuf = Buffer.alloc(8);
    sizeBuf.writeBigUInt64LE(BigInt(value.length + 4), 0);
    const idBuf = Buffer.alloc(4);
    idBuf.writeUInt32LE(pair.id, 0);
    return Buffer.concat([sizeBuf, idBuf, value]);
  });
  const body = Buffer.concat(encodedPairs);
  const blockSize = body.length + 8 + 16;
  const sizeBuf = Buffer.alloc(8);
  sizeBuf.writeBigUInt64LE(BigInt(blockSize), 0);
  return Buffer.concat([sizeBuf, body, sizeBuf, Buffer.from('APK Sig Block 42', 'latin1')]);
}

// ---------------------------------------------------------------------------
// AXML 构造器
// ---------------------------------------------------------------------------

const ANDROID_NS = 'http://schemas.android.com/apk/res/android';
const ANDROID_PREFIX = 'android';

const ANDROID_ATTR_RES_IDS = {
  name: 0x01010003,
  label: 0x01010001,
  icon: 0x01010002,
  permission: 0x01010006,
  readPermission: 0x01010007,
  writePermission: 0x01010008,
  protectionLevel: 0x01010009,
  exported: 0x01010010,
  process: 0x01010011,
  taskAffinity: 0x01010012,
  authorities: 0x01010018,
  grantUriPermissions: 0x0101001b,
  debuggable: 0x0101000f,
  versionCode: 0x0101021b,
  versionName: 0x0101021c,
  minSdkVersion: 0x0101020c,
  targetSdkVersion: 0x01010270,
  allowBackup: 0x01010280,
  usesCleartextTraffic: 0x010104ec,
  networkSecurityConfig: 0x01010528,
  required: 0x0101028e,
  scheme: 0x01010027,
  host: 0x01010028,
  mimeType: 0x01010026,
};

function encodeLen8(length) {
  if (length < 0x80) return Buffer.from([length]);
  return Buffer.from([0x80 | (length >> 8), length & 0xff]);
}

function utf16Length(text) {
  let n = 0;
  for (const ch of text) n += ch.codePointAt(0) > 0xffff ? 2 : 1;
  return n;
}

function buildStringPool(strings, utf8 = true) {
  const encoded = strings.map((text) => {
    const data = Buffer.from(text, 'utf8');
    if (utf8) {
      return Buffer.concat([encodeLen8(utf16Length(text)), encodeLen8(data.length), data, Buffer.from([0])]);
    }
    const buf = Buffer.alloc(2 + data.length * 2 + 2);
    buf.writeUInt16LE(text.length, 0);
    buf.write(text, 2, 'utf16le');
    buf.writeUInt16LE(0, 2 + text.length * 2);
    return buf;
  });
  const headerSize = 28;
  const dataStart = headerSize + strings.length * 4;
  let dataSize = encoded.reduce((n, buf) => n + buf.length, 0);
  let chunkSize = dataStart + dataSize;
  chunkSize += (4 - (chunkSize % 4)) % 4;
  const chunk = Buffer.alloc(chunkSize);
  u16(chunk, 0x0001, 0);
  u16(chunk, headerSize, 2);
  u32(chunk, chunkSize, 4);
  u32(chunk, strings.length, 8);
  u32(chunk, 0, 12); // styleCount
  u32(chunk, utf8 ? 0x100 : 0, 16);
  u32(chunk, dataStart, 20);
  u32(chunk, 0, 24);
  let dataOffset = 0;
  encoded.forEach((buf, index) => {
    u32(chunk, dataOffset, headerSize + index * 4);
    buf.copy(chunk, dataStart + dataOffset);
    dataOffset += buf.length;
  });
  return chunk;
}

function buildResourceMap(strings) {
  const count = strings.length;
  const size = 8 + count * 4;
  const chunk = Buffer.alloc(size);
  u16(chunk, 0x0180, 0);
  u16(chunk, 8, 2);
  u32(chunk, size, 4);
  strings.forEach((text, index) => {
    const id = ANDROID_ATTR_RES_IDS[text] ?? 0;
    u32(chunk, id >>> 0, 8 + index * 4);
  });
  return chunk;
}

function namespaceChunk(type, prefixIndex, uriIndex) {
  const chunk = Buffer.alloc(24);
  u16(chunk, type, 0);
  u16(chunk, 16, 2);
  u32(chunk, 24, 4);
  u32(chunk, 1, 8); // lineNumber
  u32(chunk, 0xffffffff, 12); // comment
  u32(chunk, prefixIndex, 16);
  u32(chunk, uriIndex, 20);
  return chunk;
}

function buildAxml(root, opts = {}) {
  const utf8 = opts.utf8 !== false;
  const strings = [];
  const stringIndex = new Map();
  const addString = (text) => {
    if (!stringIndex.has(text)) {
      stringIndex.set(text, strings.length);
      strings.push(text);
    }
    return stringIndex.get(text);
  };
  const nsUri = addString(ANDROID_NS);
  const nsPrefix = addString(ANDROID_PREFIX);
  const attrValueStrings = new Map();

  const assignElement = (element) => {
    addString(element.name);
    for (const a of element.attrs || []) {
      addString(a.name);
      if (a.kind === 'string' && !attrValueStrings.has(a.value)) {
        attrValueStrings.set(a.value, addString(a.value));
      }
    }
    for (const child of element.children || []) assignElement(child);
  };
  assignElement(root);

  const pool = buildStringPool(strings, utf8);
  const resourceMap = buildResourceMap(strings);
  const chunks = [pool, resourceMap, namespaceChunk(0x0100, nsPrefix, nsUri)];

  const writeElement = (element) => {
    const attrs = element.attrs || [];
    const size = 16 + 20 + attrs.length * 20;
    const chunk = Buffer.alloc(size);
    u16(chunk, 0x0102, 0);
    u16(chunk, 16, 2);
    u32(chunk, size, 4);
    u32(chunk, 1, 8); // line
    u32(chunk, 0xffffffff, 12); // comment
    u32(chunk, 0xffffffff, 16); // element ns（测试用无命名空间元素）
    u32(chunk, stringIndex.get(element.name), 20);
    u16(chunk, 20, 24); // attributeStart（相对 body 起点）
    u16(chunk, 20, 26); // attributeSize
    u16(chunk, attrs.length, 28);
    u16(chunk, 0, 30); // idIndex
    u16(chunk, 0, 32); // classIndex
    u16(chunk, 0, 34); // styleIndex
    attrs.forEach((a, index) => {
      const base = 16 + 20 + index * 20;
      u32(chunk, nsUri, base); // 所有测试属性使用 android 命名空间
      u32(chunk, stringIndex.get(a.name), base + 4);
      let dataType = 0x03;
      let data = 0;
      let raw = 0xffffffff;
      if (a.kind === 'string') {
        dataType = 0x03;
        data = attrValueStrings.get(a.value);
        raw = data;
      } else if (a.kind === 'bool') {
        dataType = 0x12;
        data = a.value ? 0xffffffff : 0;
      } else if (a.kind === 'int') {
        dataType = 0x10;
        data = a.value >>> 0;
      } else if (a.kind === 'hex') {
        dataType = 0x11;
        data = a.value >>> 0;
      } else {
        throw new Error(`不支持的 AXML 属性类型 ${a.kind}`);
      }
      u32(chunk, raw, base + 8);
      u16(chunk, 8, base + 12); // Res_value.size
      chunk.writeUInt8(0, base + 14); // res0
      chunk.writeUInt8(dataType, base + 15);
      u32(chunk, data >>> 0, base + 16);
    });
    chunks.push(chunk);
    for (const child of element.children || []) writeElement(child);
    const end = Buffer.alloc(24);
    u16(end, 0x0103, 0);
    u16(end, 16, 2);
    u32(end, 24, 4);
    u32(end, 1, 8);
    u32(end, 0xffffffff, 12);
    u32(end, 0xffffffff, 16); // ns
    u32(end, stringIndex.get(element.name), 20);
    chunks.push(end);
  };
  writeElement(root);
  chunks.push(namespaceChunk(0x0101, nsPrefix, nsUri));

  const body = Buffer.concat(chunks);
  const header = Buffer.alloc(8);
  u16(header, 0x0003, 0);
  u16(header, 8, 2);
  u32(header, 8 + body.length, 4);
  return Buffer.concat([header, body]);
}

function sampleManifestTree() {
  return {
    name: 'manifest',
    attrs: [
      { name: 'package', value: 'com.example.app', kind: 'string' },
      { name: 'versionName', value: '1.2.3', kind: 'string' },
      { name: 'versionCode', value: 123, kind: 'int' },
    ],
    children: [
      {
        name: 'uses-sdk',
        attrs: [
          { name: 'minSdkVersion', value: 21, kind: 'int' },
          { name: 'targetSdkVersion', value: 33, kind: 'int' },
        ],
        children: [],
      },
      { name: 'uses-permission', attrs: [{ name: 'name', value: 'android.permission.INTERNET', kind: 'string' }], children: [] },
      { name: 'uses-permission', attrs: [{ name: 'name', value: 'android.permission.CAMERA', kind: 'string' }], children: [] },
      {
        name: 'permission',
        attrs: [
          { name: 'name', value: 'com.example.app.permission.CUSTOM', kind: 'string' },
          { name: 'protectionLevel', value: 'signature', kind: 'string' },
        ],
        children: [],
      },
      {
        name: 'application',
        attrs: [
          { name: 'debuggable', value: true, kind: 'bool' },
          { name: 'allowBackup', value: false, kind: 'bool' },
          { name: 'usesCleartextTraffic', value: true, kind: 'bool' },
          { name: 'label', value: 'Example App', kind: 'string' },
        ],
        children: [
          {
            name: 'activity',
            attrs: [
              { name: 'name', value: '.MainActivity', kind: 'string' },
              { name: 'exported', value: true, kind: 'bool' },
            ],
            children: [
              {
                name: 'intent-filter',
                attrs: [],
                children: [
                  { name: 'action', attrs: [{ name: 'name', value: 'android.intent.action.MAIN', kind: 'string' }], children: [] },
                  { name: 'category', attrs: [{ name: 'name', value: 'android.intent.category.LAUNCHER', kind: 'string' }], children: [] },
                ],
              },
            ],
          },
          {
            name: 'activity',
            attrs: [{ name: 'name', value: '.ShareActivity', kind: 'string' }],
            children: [
              {
                name: 'intent-filter',
                attrs: [],
                children: [
                  { name: 'action', attrs: [{ name: 'name', value: 'android.intent.action.VIEW', kind: 'string' }], children: [] },
                  { name: 'category', attrs: [{ name: 'name', value: 'android.intent.category.BROWSABLE', kind: 'string' }], children: [] },
                  { name: 'data', attrs: [{ name: 'scheme', value: 'myapp', kind: 'string' }, { name: 'host', value: 'open', kind: 'string' }], children: [] },
                ],
              },
            ],
          },
          {
            name: 'service',
            attrs: [
              { name: 'name', value: '.SyncService', kind: 'string' },
              { name: 'exported', value: true, kind: 'bool' },
            ],
            children: [],
          },
          {
            name: 'receiver',
            attrs: [
              { name: 'name', value: '.BootReceiver', kind: 'string' },
              { name: 'exported', value: true, kind: 'bool' },
            ],
            children: [],
          },
          {
            name: 'provider',
            attrs: [
              { name: 'name', value: '.DataProvider', kind: 'string' },
              { name: 'authorities', value: 'com.example.app.provider', kind: 'string' },
              { name: 'exported', value: true, kind: 'bool' },
            ],
            children: [],
          },
        ],
      },
      {
        name: 'uses-feature',
        attrs: [
          { name: 'name', value: 'android.hardware.camera', kind: 'string' },
          { name: 'required', value: true, kind: 'bool' },
        ],
        children: [],
      },
    ],
  };
}

// ---------------------------------------------------------------------------
// DEX 构造器
// ---------------------------------------------------------------------------

function uleb128(value) {
  const bytes = [];
  let n = value;
  do {
    let b = n & 0x7f;
    n >>>= 7;
    if (n !== 0) b |= 0x80;
    bytes.push(b);
  } while (n !== 0);
  return Buffer.from(bytes);
}

function buildDex() {
  const strings = [
    'Lcom/example/MainActivity;',
    'Landroid/app/Activity;',
    'hello world',
    '你好',
    'Ljava/lang/Object;',
    'MainActivity.java',
    'Lokhttp3/OkHttpClient;',
    'Ljavax/crypto/Cipher;',
  ];
  const stringIdsOff = 0x70;
  const stringDataStart = stringIdsOff + strings.length * 4;
  const encodedStrings = strings.map((text) => {
    const utf8 = Buffer.from(text, 'utf8');
    return Buffer.concat([uleb128(utf16Length(text)), utf8, Buffer.from([0])]);
  });
  let dataOffset = stringDataStart;
  const dataOffsets = [];
  for (const encoded of encodedStrings) {
    dataOffsets.push(dataOffset);
    dataOffset += encoded.length;
  }
  const typeIdsOff = (dataOffset + 3) & ~3;
  const typeStringIndexes = [0, 1, 4, 6]; // 类描述符
  const classDefsOff = typeIdsOff + typeStringIndexes.length * 4;
  const fileSize = classDefsOff + 32;
  const buf = Buffer.alloc(fileSize);
  buf.write('dex\n035\0', 0, 'latin1');
  buf.writeUInt32LE(0, 8); // checksum（测试不校验）
  buf.fill(0, 12, 32); // signature
  buf.writeUInt32LE(fileSize, 32);
  buf.writeUInt32LE(0x70, 36);
  buf.writeUInt32LE(0x12345678, 40);
  buf.writeUInt32LE(0, 44); // linkSize
  buf.writeUInt32LE(0, 48); // linkOff
  buf.writeUInt32LE(0, 52); // mapOff
  buf.writeUInt32LE(strings.length, 56);
  buf.writeUInt32LE(stringIdsOff, 60);
  buf.writeUInt32LE(typeStringIndexes.length, 64);
  buf.writeUInt32LE(typeIdsOff, 68);
  buf.writeUInt32LE(7, 72); // protoIdsSize
  buf.writeUInt32LE(0, 76);
  buf.writeUInt32LE(11, 80); // fieldIdsSize
  buf.writeUInt32LE(0, 84);
  buf.writeUInt32LE(23, 88); // methodIdsSize
  buf.writeUInt32LE(0, 92);
  buf.writeUInt32LE(1, 96); // classDefsSize
  buf.writeUInt32LE(classDefsOff, 100);
  buf.writeUInt32LE(0, 104); // dataSize
  buf.writeUInt32LE(0, 108); // dataOff
  dataOffsets.forEach((off, index) => buf.writeUInt32LE(off, stringIdsOff + index * 4));
  typeStringIndexes.forEach((stringIdx, index) => buf.writeUInt32LE(stringIdx, typeIdsOff + index * 4));
  // class_def
  buf.writeUInt32LE(0, classDefsOff); // classIdx -> Lcom/example/MainActivity;
  buf.writeUInt32LE(0x1, classDefsOff + 4); // public
  buf.writeUInt32LE(1, classDefsOff + 8); // superclass -> Landroid/app/Activity;
  buf.writeUInt32LE(0, classDefsOff + 12);
  buf.writeUInt32LE(5, classDefsOff + 16); // sourceFile -> MainActivity.java
  buf.writeUInt32LE(0, classDefsOff + 20);
  buf.writeUInt32LE(0, classDefsOff + 24);
  buf.writeUInt32LE(0, classDefsOff + 28);
  let cursor = stringDataStart;
  for (const encoded of encodedStrings) {
    encoded.copy(buf, cursor);
    cursor += encoded.length;
  }
  return buf;
}

// ---------------------------------------------------------------------------
// APK 组装
// ---------------------------------------------------------------------------

function baseEntries() {
  return [
    { name: 'AndroidManifest.xml', data: buildAxml(sampleManifestTree()), method: 'deflate' },
    { name: 'classes.dex', data: buildDex(), method: 'store' },
    { name: 'resources.arsc', data: Buffer.from([0x02, 0x00, 0x0c, 0x00, 0, 0, 0, 0]), method: 'store' },
    { name: 'lib/arm64-v8a/libnative.so', data: Buffer.alloc(64, 0x7f), method: 'store' },
    { name: 'assets/config.json', data: '{"debug":true}', method: 'store' },
    { name: 'META-INF/MANIFEST.MF', data: 'Manifest-Version: 1.0\r\n\r\n', method: 'store' },
  ];
}

function buildBaseApk() {
  return buildZip(baseEntries());
}

function buildV1Apk() {
  const certDer = buildDebugCertDer();
  const entries = baseEntries().concat([{ name: 'META-INF/CERT.RSA', data: buildPkcs7(certDer), method: 'store' }]);
  return { apk: buildZip(entries), certDer };
}

function buildV2V3Apk() {
  const certDer = buildDebugCertDer();
  const value = buildV2Value(certDer);
  const signingBlock = buildSigningBlock([
    { id: 0x7109871a, value },
    { id: 0xf05368c0, value },
  ]);
  return { apk: buildZip(baseEntries(), { signingBlock }), certDer };
}

function buildTextManifestApk() {
  const xml = `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.text.app" android:versionName="9.9" android:versionCode="99">
  <uses-sdk android:minSdkVersion="23" android:targetSdkVersion="30"/>
  <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>
  <application android:debuggable="false" android:allowBackup="true" android:label="Text &amp; App">
    <activity android:name=".TextActivity" android:exported="false"/>
  </application>
</manifest>`;
  return buildZip([{ name: 'AndroidManifest.xml', data: xml, method: 'store' }, { name: 'classes.dex', data: buildDex(), method: 'store' }]);
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

test('android: capability 清单符合契约（id/riskLevel/params schema）', () => {
  assert.equal(androidManifest.domain, 'android');
  assert.deepEqual(
    androidManifest.capabilities.map((c) => c.id),
    ['android.apk_structure', 'android.manifest', 'android.dex', 'android.signing', 'android.findings'],
  );
  for (const capability of androidManifest.capabilities) {
    assert.equal(capability.riskLevel, 'L0', `${capability.id} 必须是离线只读`);
    assert.equal(typeof capability.run, 'function');
    assert.ok(capability.title.length > 0);
    assert.ok(capability.description.length > 0);
    assert.equal(capability.params.type, 'object');
    assert.equal(capability.params.additionalProperties, false);
  }
});

test('android.apk_structure: 解析 ZIP 中央目录与 APK 分类', async () => {
  const apk = buildBaseApk();
  const result = await cap('android.apk_structure').run(makeInput(apk));
  assert.equal(result.data.isApk, true);
  assert.equal(result.data.entryCount, 6);
  assert.equal(result.data.declaredEntryCount, 6);
  assert.equal(result.data.dexFiles.length, 1);
  assert.equal(result.data.dexFiles[0].name, 'classes.dex');
  assert.equal(result.data.dexFiles[0].uncompressedSize, buildDex().length);
  assert.equal(result.data.hasResourcesArsc, true);
  assert.deepEqual(result.data.abis, ['arm64-v8a']);
  assert.equal(result.data.assets.count, 1);
  assert.equal(result.data.metaInf.hasManifestMf, true);
  assert.ok(result.data.topLevel.some((t) => t.name === 'lib/'));
  const manifestEntry = parseZip(apk).entries.find((e) => e.name === 'AndroidManifest.xml');
  assert.equal(manifestEntry.method, 8, 'manifest 应以 deflate 存储');
  assert.match(result.summary, /APK/);
  assert.match(result.summary, /6 个条目/);
  assert.equal(result.meta.truncated, false);
  // 确定性
  const again = await cap('android.apk_structure').run(makeInput(apk));
  assert.deepEqual(again.data, result.data);
});

test('android.apk_structure: includeEntries + maxEntries 截断', async () => {
  const apk = buildBaseApk();
  const full = await cap('android.apk_structure').run(makeInput(apk, { includeEntries: true }));
  assert.equal(full.data.entries.length, 6);
  assert.equal(full.data.entriesTruncated, false);
  assert.ok(full.data.entries.find((e) => e.name === 'AndroidManifest.xml').class === 'manifest');
  const limited = await cap('android.apk_structure').run(makeInput(apk, { includeEntries: true, maxEntries: 2 }));
  assert.equal(limited.data.entries.length, 2);
  assert.equal(limited.data.entriesTruncated, true);
  // 非 APK ZIP 不抛错，但标记 isApk=false
  const plainZip = buildZip([{ name: 'assets/readme.txt', data: 'hi', method: 'store' }]);
  const notApk = await cap('android.apk_structure').run(makeInput(plainZip));
  assert.equal(notApk.data.isApk, false);
  assert.equal(notApk.data.hasAndroidManifest, false);
  assert.match(notApk.summary, /非 APK/);
});

test('android.apk_structure: ZIP64 EOCD locator 定位与后续解析', async () => {
  const apk64 = buildZip(baseEntries(), { zip64: true });
  const zip = parseZip(apk64);
  assert.equal(zip.zip64, true);
  assert.equal(zip.declaredEntryCount, 6);
  assert.equal(zip.entries.length, 6);
  assert.equal(zip.entries[0].name, 'AndroidManifest.xml');
  const structure = await cap('android.apk_structure').run(makeInput(apk64));
  assert.equal(structure.data.zip64, true);
  assert.equal(structure.data.entryCount, 6);
  assert.equal(structure.data.isApk, true);
  const manifest = await cap('android.manifest').run(makeInput(apk64));
  assert.equal(manifest.data.package, 'com.example.app');
  assert.equal(manifest.data.minSdkVersion, 21);
});

test('android.manifest: 解码二进制 AXML 的包名/权限/组件/安全开关', async () => {
  const apk = buildBaseApk();
  const result = await cap('android.manifest').run(makeInput(apk));
  assert.equal(result.data.format, 'binary-axml');
  assert.equal(result.data.package, 'com.example.app');
  assert.equal(result.data.versionName, '1.2.3');
  assert.equal(result.data.versionCode, 123);
  assert.equal(result.data.minSdkVersion, 21);
  assert.equal(result.data.targetSdkVersion, 33);
  assert.equal(result.data.application.debuggable, true);
  assert.equal(result.data.application.allowBackup, false);
  assert.equal(result.data.application.usesCleartextTraffic, true);
  assert.equal(result.data.application.label, 'Example App');
  assert.deepEqual(result.data.permissions.map((p) => p.name), ['android.permission.INTERNET', 'android.permission.CAMERA']);
  assert.equal(result.data.customPermissions[0].name, 'com.example.app.permission.CUSTOM');
  assert.equal(result.data.customPermissions[0].protectionLevel, 'signature');
  assert.equal(result.data.stats.activityCount, 2);
  assert.equal(result.data.stats.providerCount, 1);
  assert.equal(result.data.stats.exportedCount, 5);
  assert.equal(result.data.stats.exportedWithoutPermissionCount, 5);
  assert.equal(result.data.features[0].name, 'android.hardware.camera');
  const main = result.data.components.activities.find((c) => c.name === '.MainActivity');
  assert.equal(main.exported, true);
  assert.equal(main.launchable, true);
  assert.equal(main.intentFilters[0].actions[0], 'android.intent.action.MAIN');
  const share = result.data.components.activities.find((c) => c.name === '.ShareActivity');
  assert.equal(share.exportedExplicit, null);
  assert.equal(share.exported, true, '有 intent-filter 未显式 exported 时按平台默认导出');
  assert.ok(share.intentFilters[0].data.some((d) => d.scheme === 'myapp' && d.host === 'open'));
  assert.ok(result.data.deepLinks.some((d) => d.scheme === 'myapp' && d.browsable === true));
  assert.equal(result.meta.compressed, true);
  assert.equal(result.meta.format, 'binary-axml');
  assert.equal(result.data.axml.truncated, false);
  // 确定性
  const again = await cap('android.manifest').run(makeInput(apk));
  assert.deepEqual(again.data, result.data);
});

test('android.manifest: parseAxml 直接校验字符串池/资源映射/类型化解码', () => {
  const axml = buildAxml(sampleManifestTree());
  const parsed = parseAxml(axml);
  assert.equal(parsed.truncated, false);
  assert.equal(parsed.utf8, true);
  assert.ok(parsed.stringCount > 10);
  assert.ok(parsed.resourceMapSize > 0);
  assert.equal(parsed.namespaces[0].uri, ANDROID_NS);
  assert.equal(parsed.root.name, 'manifest');
  const application = findElements(parsed.root, (el) => el.name === 'application')[0];
  const debuggable = attr(application, 'debuggable');
  assert.equal(debuggable.type, 0x12, '布尔类型应为 TYPE_INT_BOOLEAN');
  assert.equal(debuggable.value, true);
  const pkg = attr(parsed.root, 'package');
  assert.equal(pkg.value, 'com.example.app');
  assert.equal(pkg.resourceId, null, 'package 属性无 android 资源 id');
  const activity = findElements(parsed.root, (el) => el.name === 'activity')[0];
  assert.equal(attr(activity, 'name').resourceId, 0x01010003, 'android:name 应解析到资源 id 0x01010003');
  assert.ok(parsed.elementCount >= 10);
  // UTF-16LE 字符串池（老 aapt 风格）也应可解析
  const utf16 = parseAxml(buildAxml(sampleManifestTree(), { utf8: false }));
  assert.equal(utf16.truncated, false);
  assert.equal(utf16.utf8, false);
  assert.equal(utf16.root.name, 'manifest');
  assert.equal(attr(findElements(utf16.root, (el) => el.name === 'uses-sdk')[0], 'minSdkVersion').value, 21);
});

test('android.manifest: 文本 XML 清单回退解析', async () => {
  const apk = buildTextManifestApk();
  const result = await cap('android.manifest').run(makeInput(apk));
  assert.equal(result.data.format, 'text-xml');
  assert.equal(result.data.package, 'com.text.app');
  assert.equal(result.data.versionName, '9.9');
  assert.equal(result.data.versionCode, 99);
  assert.equal(result.data.minSdkVersion, 23);
  assert.equal(result.data.targetSdkVersion, 30);
  assert.deepEqual(result.data.permissions.map((p) => p.name), ['android.permission.ACCESS_FINE_LOCATION']);
  assert.equal(result.data.application.allowBackup, true);
  assert.equal(result.data.application.label, 'Text & App');
  assert.equal(result.data.components.activities[0].exported, false);
});

test('android.manifest: 畸形/缺失清单抛出可操作错误', async () => {
  const badAxml = buildZip([{ name: 'AndroidManifest.xml', data: Buffer.from('this is definitely not axml'), method: 'store' }]);
  await assert.rejects(
    () => cap('android.manifest').run(makeInput(badAxml)),
    (err) => {
      assert.match(err.message, /AXML/);
      assert.match(err.message, /AndroidManifest/);
      return true;
    },
  );
  const noManifest = buildZip([{ name: 'classes.dex', data: buildDex(), method: 'store' }]);
  await assert.rejects(
    () => cap('android.manifest').run(makeInput(noManifest)),
    (err) => {
      assert.match(err.message, /缺少 AndroidManifest\.xml/);
      return true;
    },
  );
});

test('android.dex: 解析 DEX 头/字符串/类描述符并命中库特征', async () => {
  const direct = buildDex();
  const result = await cap('android.dex').run(makeInput(direct, {}, { maxStrings: 50 }));
  assert.equal(result.data.dexFileCount, 1);
  assert.equal(result.data.dexFiles[0].version, '035');
  assert.equal(result.data.dexFiles[0].counts.stringIds, 8);
  assert.equal(result.data.dexFiles[0].counts.typeIds, 4);
  assert.equal(result.data.dexFiles[0].counts.classDefs, 1);
  assert.ok(result.data.dexFiles[0].strings.includes('hello world'));
  assert.ok(result.data.dexFiles[0].strings.includes('你好'), 'MUTF-8 非 ASCII 字符串应正确解码');
  assert.ok(result.data.dexFiles[0].classDescriptors.includes('Lcom/example/MainActivity;'));
  assert.equal(result.data.dexFiles[0].classDefs[0].name, 'Lcom/example/MainActivity;');
  assert.equal(result.data.dexFiles[0].classDefs[0].superclass, 'Landroid/app/Activity;');
  assert.equal(result.data.dexFiles[0].classDefs[0].sourceFile, 'MainActivity.java');
  const httpHint = result.data.libraryHints.find((h) => h.category === 'http-client');
  const cryptoHint = result.data.libraryHints.find((h) => h.category === 'crypto');
  assert.ok(httpHint, '应命中 okhttp3 特征');
  assert.ok(cryptoHint, '应命中 javax.crypto 特征');
  // 从 APK 内读取 classes.dex
  const fromApk = await cap('android.dex').run(makeInput(buildBaseApk()));
  assert.equal(fromApk.data.dexFiles[0].name, 'classes.dex');
  assert.match(fromApk.summary, /DEX 1 个/);
  // parseDex 直接调用可对齐字段
  const parsed = parseDex(direct);
  assert.equal(parsed.version, '035');
  assert.equal(parsed.strings[2], 'hello world');
  assert.equal(parsed.classDescriptorCount, 4);
});

test('android.dex: 非法输入与空输入报可操作错误', async () => {
  await assert.rejects(
    () => cap('android.dex').run(makeInput(Buffer.from('not a dex file at all, just text'))),
    (err) => {
      assert.match(err.message, /不是 DEX|需要 \.dex/);
      return true;
    },
  );
  await assert.rejects(
    () => cap('android.dex').run(makeInput(Buffer.alloc(0))),
    (err) => {
      assert.match(err.message, /缺少可分析字节/);
      return true;
    },
  );
  const noDex = buildZip([{ name: 'assets/x.txt', data: 'x', method: 'store' }]);
  await assert.rejects(
    () => cap('android.dex').run(makeInput(noDex)),
    (err) => {
      assert.match(err.message, /未找到 classes\*\.dex/);
      return true;
    },
  );
});

test('android.signing: v2+v3 签名块与证书 SHA-256/主体/调试证书提示', async () => {
  const { apk, certDer } = buildV2V3Apk();
  const result = await cap('android.signing').run(makeInput(apk));
  assert.equal(result.data.hasV2, true);
  assert.equal(result.data.hasV3, true);
  assert.equal(result.data.schemes.v2.present, true);
  assert.equal(result.data.schemes.v3.present, true);
  assert.equal(result.data.schemes.v2.signerCount, 1);
  assert.equal(result.data.certificateCount, 1, 'v2/v3 同一证书应去重');
  assert.equal(result.data.firstCertSha256, sha256(certDer));
  assert.equal(result.data.certificates[0].subject.CN, 'Android Debug');
  assert.equal(result.data.certificates[0].subject.O, 'Android');
  assert.equal(result.data.certificates[0].issuer.CN, 'Android Debug');
  assert.equal(result.data.certificates[0].notBefore, '2020-01-01T00:00:00Z');
  assert.equal(result.data.certificates[0].notAfter, '2049-12-31T23:59:59Z');
  assert.equal(result.data.debugCertHint, true);
  assert.equal(result.data.signingBlock.pairCount, 2);
  assert.ok(result.data.signingBlock.pairs.some((p) => p.id === '0x7109871a'));
  assert.ok(result.data.signingBlock.pairs.some((p) => p.id === '0xf05368c0'));
  assert.match(result.data.verifyingPolicy, /未验证/);
  assert.match(result.summary, /v2\+v3/);
  // 确定性
  const again = await cap('android.signing').run(makeInput(apk));
  assert.deepEqual(again.data, result.data);
});

test('android.signing: v1 META-INF 证书提取与未签名检测', async () => {
  const { apk, certDer } = buildV1Apk();
  const result = await cap('android.signing').run(makeInput(apk));
  assert.equal(result.data.hasV1, true);
  assert.equal(result.data.hasV2, false);
  assert.equal(result.data.hasV3, false);
  assert.deepEqual(result.data.schemes.v1.files, ['META-INF/CERT.RSA']);
  assert.equal(result.data.schemes.v1.hasManifestMf, true);
  assert.equal(result.data.schemes.v1.certificates.length, 1);
  assert.equal(result.data.schemes.v1.certificates[0].sha256, sha256(certDer));
  assert.equal(result.data.firstCertSha256, sha256(certDer));
  assert.equal(result.data.debugCertHint, true);
  assert.ok(result.meta.warnings.some((w) => /仅存在 v1|仅使用 v1/.test(w)));
  // 未签名 APK
  const unsigned = await cap('android.signing').run(makeInput(buildBaseApk()));
  assert.equal(unsigned.data.hasV1, false);
  assert.equal(unsigned.data.hasV2, false);
  assert.equal(unsigned.data.hasV3, false);
  assert.equal(unsigned.data.certificateCount, 0);
  assert.equal(unsigned.data.firstCertSha256, null);
  assert.ok(unsigned.meta.warnings.some((w) => /未发现 v1\/v2\/v3 签名/.test(w)));
});

test('android.dex: 截断 DEX 标记 truncated，大端 DEX 报可操作错误', async () => {
  const fullDex = buildDex();
  const truncatedDex = fullDex.subarray(0, 0x74);
  const truncatedResult = await cap('android.dex').run(makeInput(truncatedDex));
  assert.equal(truncatedResult.data.dexFiles[0].truncated, true);
  assert.ok(truncatedResult.data.dexFiles[0].warnings.some((w) => /截断/.test(w)));
  assert.equal(truncatedResult.meta.truncated, true);
  const bigEndian = Buffer.from(fullDex);
  bigEndian.writeUInt32LE(0x78563412, 40);
  await assert.rejects(
    () => cap('android.dex').run(makeInput(bigEndian)),
    (err) => {
      assert.match(err.message, /大端/);
      return true;
    },
  );
});

test('android.signing: 损坏的 APK Signing Block 只告警不崩溃', async () => {
  const { apk } = buildV2V3Apk();
  const zip = parseZip(apk);
  const corrupt = Buffer.from(apk);
  // 把签名块尾部 size 字段写成超大值，触发结构校验失败
  corrupt.writeBigUInt64LE(0xffffffffffffffffn, zip.centralDirOffset - 24);
  const result = await cap('android.signing').run(makeInput(corrupt));
  assert.equal(result.data.hasV2, false);
  assert.equal(result.data.hasV3, false);
  assert.equal(result.data.signingBlock, null);
  assert.ok(result.meta.warnings.some((w) => /APK Signing Block 解析失败/.test(w)));
  assert.match(result.summary, /未检测到 v1\/v2\/v3 签名/);
});

test('android.findings: 从清单/结构/签名推导诚实 findings（含验证等级）', async () => {
  const { apk } = buildV2V3Apk();
  const result = await cap('android.findings').run(makeInput(apk, { maxFindings: 100 }));
  assert.ok(Array.isArray(result.findings) && result.findings.length >= 5);
  assert.equal(result.data.findingsTotal, result.findings.length);
  const debugFinding = result.findings.find((f) => /可调试/.test(f.title));
  assert.ok(debugFinding, '应发现 debuggable=true');
  assert.equal(debugFinding.severity, 'high');
  assert.equal(debugFinding.verification, 'observed');
  assert.equal(debugFinding.cwe, 'CWE-489');
  const cleartextFinding = result.findings.find((f) => /明文/.test(f.title));
  assert.ok(cleartextFinding);
  assert.equal(cleartextFinding.cwe, 'CWE-319');
  assert.equal(cleartextFinding.verification, 'observed');
  const providerFinding = result.findings.find((f) => /ContentProvider/.test(f.title));
  assert.ok(providerFinding, '应发现导出无权限 provider');
  const debugCertFinding = result.findings.find((f) => /Debug 证书/.test(f.title));
  assert.ok(debugCertFinding, '应发现 Android Debug 证书签名');
  assert.equal(debugCertFinding.severity, 'medium');
  const dangerFinding = result.findings.find((f) => /危险权限/.test(f.title));
  assert.ok(dangerFinding, 'CAMERA 应计入危险权限提示');
  assert.equal(dangerFinding.severity, 'info');
  for (const finding of result.findings) {
    assert.ok(['critical', 'high', 'medium', 'low', 'info'].includes(finding.severity));
    assert.ok(['observed', 'corroborated', 'hypothesis', 'unverified'].includes(finding.verification));
    assert.ok(finding.cvss === null, '无明确向量时 cvss 必须为 null');
    assert.ok(finding.method.length > 0);
    assert.ok(finding.remediation.length > 0);
    assert.ok(Array.isArray(finding.evidence) && finding.evidence.length >= 1);
    assert.ok(finding.evidence[0].excerpt.length <= 2000);
  }
  const bySeverity = result.data.bySeverity;
  assert.equal(
    Object.values(bySeverity).reduce((sum, n) => sum + n, 0),
    result.data.findingsTotal,
  );
  // includeInfo=false + maxFindings 限制
  const limited = await cap('android.findings').run(makeInput(apk, { includeInfo: false, maxFindings: 2 }));
  assert.ok(limited.findings.length <= 2);
  assert.ok(limited.findings.every((f) => f.severity !== 'info'));
  // 确定性
  const again = await cap('android.findings').run(makeInput(apk, { maxFindings: 100 }));
  assert.deepEqual(again.data, result.data);
});

test('android: Result 契约（summary/data 体积/meta 与全部 capability 可执行）', async () => {
  const { apk } = buildV2V3Apk();
  const input = makeInput(apk);
  for (const capability of androidManifest.capabilities) {
    const result = await capability.run(input);
    assert.equal(typeof result.summary, 'string', `${capability.id} summary 必须是字符串`);
    assert.ok(result.summary.length > 0 && result.summary.length <= 4000, `${capability.id} summary 长度为 1..4000`);
    assert.ok(Array.isArray(result.findings), `${capability.id} findings 必须是数组`);
    assert.ok(result.data && typeof result.data === 'object' && !Array.isArray(result.data), `${capability.id} data 必须是对象`);
    const dataBytes = Buffer.byteLength(JSON.stringify(result.data), 'utf8');
    assert.ok(dataBytes <= 256 * 1024, `${capability.id} data 体积 ${dataBytes} 超过 256KiB`);
    assert.ok(result.meta && typeof result.meta === 'object', `${capability.id} meta 必须是对象`);
    for (const finding of result.findings) {
      for (const key of ['title', 'severity', 'description', 'verification', 'method', 'cwe', 'cvss', 'remediation', 'target', 'evidence']) {
        assert.ok(key in finding, `${capability.id} finding 缺字段 ${key}`);
      }
      assert.ok(Buffer.byteLength(finding.description, 'utf8') <= 2000);
    }
  }
});

test('android: data 超过 256KiB 时按预算裁剪并标记', () => {
  const data = { entries: Array.from({ length: 5000 }, (_, index) => ({ name: 'x'.repeat(100), index })) };
  const trimmed = enforceDataBudget(data, 256 * 1024);
  assert.ok(Buffer.byteLength(JSON.stringify(trimmed), 'utf8') <= 256 * 1024);
  assert.equal(trimmed.dataBudget.truncated, true);
  assert.ok(trimmed.entries.length < 5000);
  // 未超限对象保持原样、不加标记
  const small = { a: [1, 2, 3] };
  const untouched = enforceDataBudget(small, 256 * 1024);
  assert.deepEqual(untouched, { a: [1, 2, 3] });
});

test('android: 畸形/截断输入不崩溃且错误可操作', async () => {
  await assert.rejects(
    () => cap('android.apk_structure').run(makeInput(Buffer.from('PK\x03\x04 not really a zip'))),
    (err) => {
      assert.match(err.message, /EOCD|ZIP/);
      return true;
    },
  );
  const apk = buildBaseApk();
  await assert.rejects(
    () => cap('android.apk_structure').run(makeInput(apk.subarray(0, 120))),
    (err) => {
      assert.match(err.message, /EOCD|截断|ZIP/);
      return true;
    },
  );
  await assert.rejects(
    () => cap('android.findings').run(makeInput(Buffer.from('random bytes'))),
    (err) => {
      assert.match(err.message, /请确认目标类型|需要 APK/);
      return true;
    },
  );
  // 目录型/空 buffer
  await assert.rejects(
    () => cap('android.manifest').run({ targetPath: null, buffer: null, text: null, options: {}, limits: {}, env: {} }),
    (err) => {
      assert.match(err.message, /缺少可分析字节/);
      return true;
    },
  );
});
