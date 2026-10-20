// ArmorBreak - TLS 握手解析（纯 node:*）
// 从 TCP 单方向流中解析 TLS record + handshake：ClientHello（SNI/ALPN/版本/密码套件/扩展）与
// ServerHello（协商版本/密码套件）。不执行密码学运算，不验证证书链。
import { createHash } from 'node:crypto';
import { buildFlowStreams, formatEndpoint } from './flows.js';
import { sanitizeText, isoTime } from './util.js';

export const TLS_RECORD_TYPES = new Map([
  [20, 'change_cipher_spec'],
  [21, 'alert'],
  [22, 'handshake'],
  [23, 'application_data'],
  [24, 'heartbeat'],
]);

export const HANDSHAKE_TYPES = new Map([
  [1, 'client_hello'],
  [2, 'server_hello'],
  [4, 'new_session_ticket'],
  [8, 'encrypted_extensions'],
  [11, 'certificate'],
  [12, 'server_key_exchange'],
  [13, 'certificate_request'],
  [14, 'server_hello_done'],
  [15, 'certificate_verify'],
  [16, 'client_key_exchange'],
  [20, 'finished'],
  [24, 'key_update'],
]);

export const EXTENSION_NAMES = new Map([
  [0, 'server_name'],
  [1, 'max_fragment_length'],
  [5, 'status_request'],
  [10, 'supported_groups'],
  [11, 'ec_point_formats'],
  [13, 'signature_algorithms'],
  [16, 'application_layer_protocol_negotiation'],
  [21, 'padding'],
  [23, 'extended_master_secret'],
  [27, 'compress_certificate'],
  [35, 'session_ticket'],
  [43, 'supported_versions'],
  [45, 'psk_key_exchange_modes'],
  [51, 'key_share'],
  [65281, 'renegotiation_info'],
]);

const VERSION_NAMES = new Map([
  [0x0300, 'SSL 3.0'],
  [0x0301, 'TLS 1.0'],
  [0x0302, 'TLS 1.1'],
  [0x0303, 'TLS 1.2'],
  [0x0304, 'TLS 1.3'],
  [0x0305, 'TLS 1.3 (draft)'],
]);

const CIPHER_SUITE_NAMES = new Map([
  [0x000a, 'TLS_RSA_WITH_3DES_EDE_CBC_SHA'],
  [0x002f, 'TLS_RSA_WITH_AES_128_CBC_SHA'],
  [0x0035, 'TLS_RSA_WITH_AES_256_CBC_SHA'],
  [0x003c, 'TLS_RSA_WITH_AES_128_CBC_SHA256'],
  [0x009c, 'TLS_RSA_WITH_AES_128_GCM_SHA256'],
  [0x009d, 'TLS_RSA_WITH_AES_256_GCM_SHA384'],
  [0x009e, 'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256'],
  [0x009f, 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384'],
  [0x00ff, 'TLS_EMPTY_RENEGOTIATION_INFO_SCSV'],
  [0x1301, 'TLS_AES_128_GCM_SHA256'],
  [0x1302, 'TLS_AES_256_GCM_SHA384'],
  [0x1303, 'TLS_CHACHA20_POLY1305_SHA256'],
  [0xc009, 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA'],
  [0xc00a, 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA'],
  [0xc013, 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA'],
  [0xc014, 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA'],
  [0xc02b, 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256'],
  [0xc02c, 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384'],
  [0xc02f, 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'],
  [0xc030, 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384'],
  [0xcca8, 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256'],
  [0xcca9, 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256'],
]);

const HELLO_RETRY_REQUEST_RANDOM = Buffer.from(
  'cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c',
  'hex',
);

export function versionName(id) {
  return VERSION_NAMES.get(id) ?? `0x${id.toString(16).padStart(4, '0')}`;
}

export function cipherSuiteName(id) {
  return CIPHER_SUITE_NAMES.get(id) ?? `TLS_0x${id.toString(16).padStart(4, '0')}`;
}

export function extensionName(id) {
  return EXTENSION_NAMES.get(id) ?? `extension_${id}`;
}

export function isGrease(value) {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff) return false;
  const high = value >> 8;
  const low = value & 0xff;
  return high === low && (low & 0x0f) === 0x0a;
}

function readU24(buffer, offset) {
  return (buffer[offset] << 16) | (buffer[offset + 1] << 8) | buffer[offset + 2];
}

/**
 * 解析 TLS record 层并重组 handshake 消息。
 * @param {Buffer} buf 单方向 TCP 流
 * @param {{maxRecords?:number, maxHandshake?:number, maxBytes?:number}} opts
 */
export function parseTlsRecords(buf, opts = {}) {
  const maxRecords = Math.max(1, Math.min(opts.maxRecords ?? 1000, 20000));
  const maxHandshake = Math.max(1, Math.min(opts.maxHandshake ?? 64, 1000));
  const maxBytes = Math.max(1, Math.min(opts.maxBytes ?? 1024 * 1024, 16 * 1024 * 1024));
  const records = [];
  const handshakeChunks = [];
  let handshakeBytes = 0;
  let pos = 0;
  let truncated = false;
  const errors = [];
  while (pos + 5 <= buf.length && records.length < maxRecords) {
    const type = buf[pos];
    if (!TLS_RECORD_TYPES.has(type)) {
      errors.push(`偏移 ${pos} 处非法 TLS record 类型 ${type}`);
      break;
    }
    const version = buf.readUInt16BE(pos + 1);
    const length = buf.readUInt16BE(pos + 3);
    if (pos + 5 + length > buf.length) {
      truncated = true;
      errors.push(`TLS record 在偏移 ${pos} 声明 ${length} 字节但仅剩 ${buf.length - pos - 5} 字节`);
      break;
    }
    const body = buf.subarray(pos + 5, pos + 5 + length);
    records.push({ type, typeName: TLS_RECORD_TYPES.get(type), version, length });
    if (type === 22) {
      if (handshakeBytes + body.length <= maxBytes) {
        handshakeChunks.push(body);
        handshakeBytes += body.length;
      } else {
        truncated = true;
      }
    }
    pos += 5 + length;
  }
  if (pos < buf.length && records.length >= maxRecords) truncated = true;
  if (pos < buf.length && !truncated && pos + 5 > buf.length && buf.length - pos > 0) truncated = true;
  const hsBuf = handshakeChunks.length > 0 ? Buffer.concat(handshakeChunks, handshakeBytes) : Buffer.alloc(0);
  const messages = [];
  let p = 0;
  while (p + 4 <= hsBuf.length && messages.length < maxHandshake) {
    const type = hsBuf[p];
    const length = readU24(hsBuf, p + 1);
    messages.push({ type, typeName: HANDSHAKE_TYPES.get(type) ?? `handshake_${type}`, length, body: null, bodyStart: p + 4, bodyEnd: p + 4 + length });
    messages[messages.length - 1].body = hsBuf.subarray(p + 4, Math.min(p + 4 + length, hsBuf.length));
    if (p + 4 + length > hsBuf.length) {
      truncated = true;
      errors.push(`handshake 消息在偏移 ${p} 声明 ${length} 字节但数据不足`);
      break;
    }
    p += 4 + length;
  }
  return { records, messages, truncated, errors, recordCount: records.length, handshakeBytes };
}

function parseExtensions(buffer, start, totalLength) {
  const end = Math.min(start + totalLength, buffer.length);
  const extensions = [];
  let pos = start;
  while (pos + 4 <= end) {
    const type = buffer.readUInt16BE(pos);
    const length = buffer.readUInt16BE(pos + 2);
    const dataStart = pos + 4;
    if (dataStart + length > end) break;
    extensions.push({ type, name: extensionName(type), length, data: buffer.subarray(dataStart, dataStart + length) });
    pos = dataStart + length;
  }
  return extensions;
}

function parseSni(data) {
  if (!data || data.length < 2) return null;
  const listLength = data.readUInt16BE(0);
  let pos = 2;
  const end = Math.min(2 + listLength, data.length);
  while (pos + 3 <= end) {
    const nameType = data[pos];
    const nameLength = data.readUInt16BE(pos + 1);
    if (pos + 3 + nameLength > end) break;
    if (nameType === 0) {
      return sanitizeText(data.subarray(pos + 3, pos + 3 + nameLength).toString('utf8'), 255);
    }
    pos += 3 + nameLength;
  }
  return null;
}

function parseAlpn(data) {
  if (!data || data.length < 2) return [];
  const listLength = data.readUInt16BE(0);
  let pos = 2;
  const end = Math.min(2 + listLength, data.length);
  const protocols = [];
  while (pos < end && protocols.length < 16) {
    const length = data[pos];
    if (pos + 1 + length > end) break;
    protocols.push(sanitizeText(data.subarray(pos + 1, pos + 1 + length).toString('latin1'), 64));
    pos += 1 + length;
  }
  return protocols;
}

function parseU16List(data) {
  const values = [];
  if (!data || data.length < 2) return values;
  const length = data.readUInt16BE(0);
  const end = Math.min(2 + length, data.length);
  for (let pos = 2; pos + 2 <= end; pos += 2) values.push(data.readUInt16BE(pos));
  return values;
}

/**
 * 解析 ClientHello handshake 消息体。
 */
export function parseClientHello(body) {
  try {
    if (!body || body.length < 35) return { ok: false, reason: 'ClientHello 体过短' };
    let pos = 0;
    const legacyVersion = body.readUInt16BE(pos);
    pos += 2;
    const random = body.subarray(pos, pos + 32);
    pos += 32;
    const sessionIdLength = body[pos];
    pos += 1;
    if (pos + sessionIdLength > body.length) return { ok: false, reason: 'session_id 越界' };
    pos += sessionIdLength;
    if (pos + 2 > body.length) return { ok: false, reason: '密码套件长度缺失' };
    const cipherListLength = body.readUInt16BE(pos);
    pos += 2;
    if (pos + cipherListLength > body.length) return { ok: false, reason: '密码套件列表越界' };
    const cipherSuites = [];
    for (let p = pos; p + 2 <= pos + cipherListLength; p += 2) {
      const id = body.readUInt16BE(p);
      cipherSuites.push({ id, name: cipherSuiteName(id), grease: isGrease(id) });
    }
    pos += cipherListLength;
    if (pos + 1 > body.length) return { ok: false, reason: '压缩方法长度缺失' };
    const compressionLength = body[pos];
    pos += 1;
    if (pos + compressionLength > body.length) return { ok: false, reason: '压缩方法越界' };
    const compressionMethods = [...body.subarray(pos, pos + compressionLength)];
    pos += compressionLength;
    let extensions = [];
    if (pos + 2 <= body.length) {
      const extLength = body.readUInt16BE(pos);
      pos += 2;
      extensions = parseExtensions(body, pos, extLength);
    }
    let sni = null;
    let alpn = [];
    let supportedVersions = [];
    let supportedGroups = [];
    let pointFormats = [];
    let signatureAlgorithms = [];
    let keyShareGroups = [];
    for (const ext of extensions) {
      if (ext.type === 0) sni = parseSni(ext.data);
      else if (ext.type === 16) alpn = parseAlpn(ext.data);
      else if (ext.type === 43) {
        // ClientHello supported_versions: 1 字节长度 + u16 版本列表
        if (ext.data.length >= 1) {
          const len = Math.min(ext.data[0], ext.data.length - 1);
          for (let p = 1; p + 2 <= 1 + len; p += 2) supportedVersions.push(ext.data.readUInt16BE(p));
        }
      } else if (ext.type === 10) supportedGroups = parseU16List(ext.data);
      else if (ext.type === 11) {
        const len = ext.data.length >= 1 ? ext.data[0] : 0;
        pointFormats = [...ext.data.subarray(1, 1 + len)];
      } else if (ext.type === 13) signatureAlgorithms = parseU16List(ext.data);
      else if (ext.type === 51 && ext.data.length >= 2) {
        const listLen = ext.data.readUInt16BE(0);
        let p = 2;
        while (p + 4 <= Math.min(2 + listLen, ext.data.length) && keyShareGroups.length < 16) {
          keyShareGroups.push(ext.data.readUInt16BE(p));
          const keyLen = ext.data.readUInt16BE(p + 2);
          p += 4 + keyLen;
        }
      }
    }
    const cleanCiphers = cipherSuites.filter((c) => !c.grease).map((c) => c.id);
    const cleanExt = extensions.filter((e) => !isGrease(e.type)).map((e) => e.type);
    const cleanGroups = supportedGroups.filter((g) => !isGrease(g));
    const ja3Like = [
      legacyVersion,
      cleanCiphers.join('-'),
      cleanExt.join('-'),
      cleanGroups.join('-'),
      pointFormats.join('-'),
    ].join(',');
    return {
      ok: true,
      legacyVersion,
      legacyVersionName: versionName(legacyVersion),
      randomHex: random.toString('hex'),
      sessionIdLength,
      cipherSuites,
      cipherSuiteCount: cipherSuites.length,
      cipherSuitesNoGrease: cipherSuites.filter((c) => !c.grease).slice(0, 40),
      compressionMethods,
      sni,
      alpn,
      supportedVersions: supportedVersions.map((v) => ({ id: v, name: versionName(v), grease: isGrease(v) })),
      supportedGroups: supportedGroups.slice(0, 40),
      pointFormats,
      signatureAlgorithms: signatureAlgorithms.slice(0, 40),
      keyShareGroups: keyShareGroups.slice(0, 16),
      extensions: extensions.map((e) => ({ type: e.type, name: e.name, length: e.length })),
      ja3Like,
      ja3LikeSha256: createHash('sha256').update(ja3Like).digest('hex'),
    };
  } catch (err) {
    return { ok: false, reason: `ClientHello 解析异常：${err && err.message ? err.message : String(err)}` };
  }
}

/**
 * 解析 ServerHello handshake 消息体。
 */
export function parseServerHello(body) {
  try {
    if (!body || body.length < 38) return { ok: false, reason: 'ServerHello 体过短' };
    let pos = 0;
    const legacyVersion = body.readUInt16BE(pos);
    pos += 2;
    const random = body.subarray(pos, pos + 32);
    pos += 32;
    const sessionIdLength = body[pos];
    pos += 1;
    if (pos + sessionIdLength + 3 > body.length) return { ok: false, reason: 'ServerHello session_id/cipher 越界' };
    pos += sessionIdLength;
    const cipherSuite = body.readUInt16BE(pos);
    pos += 2;
    const compressionMethod = body[pos];
    pos += 1;
    let extensions = [];
    if (pos + 2 <= body.length) {
      const extLength = body.readUInt16BE(pos);
      pos += 2;
      extensions = parseExtensions(body, pos, extLength);
    }
    let selectedVersion = legacyVersion;
    let alpn = [];
    for (const ext of extensions) {
      if (ext.type === 43) {
        // ServerHello supported_versions: 直接是 2 字节选中的版本
        if (ext.data.length >= 2) selectedVersion = ext.data.readUInt16BE(0);
      } else if (ext.type === 16) {
        alpn = parseAlpn(ext.data);
      }
    }
    return {
      ok: true,
      legacyVersion,
      legacyVersionName: versionName(legacyVersion),
      selectedVersion,
      selectedVersionName: versionName(selectedVersion),
      randomHex: random.toString('hex'),
      isHelloRetryRequest: random.equals(HELLO_RETRY_REQUEST_RANDOM),
      sessionIdLength,
      cipherSuite,
      cipherSuiteName: cipherSuiteName(cipherSuite),
      compressionMethod,
      alpn,
      extensions: extensions.map((e) => ({ type: e.type, name: e.name, length: e.length })),
    };
  } catch (err) {
    return { ok: false, reason: `ServerHello 解析异常：${err && err.message ? err.message : String(err)}` };
  }
}

/**
 * 从流表扫描 TLS 会话（TCP 流重组 -> TLS record -> ClientHello/ServerHello）。
 * @param {Map} flowPackets buildFlows().flowPackets
 * @param {{maxSessions?:number, maxStreamBytes?:number}} opts
 */
export function scanTlsSessions(flowPackets, opts = {}) {
  const maxSessions = Math.max(1, Math.min(opts.maxSessions ?? 200, 5000));
  const maxStreamBytes = Math.max(1024, Math.min(opts.maxStreamBytes ?? 512 * 1024, 8 * 1024 * 1024));
  const sessions = [];
  const warnings = [];
  let candidateFlows = 0;
  let hitSessionLimit = false;
  const entries = [...flowPackets.values()]
    .filter((entry) => entry.flow.proto === 'tcp')
    .sort((a, b) => (a.flow.firstTs ?? 0) - (b.flow.firstTs ?? 0));
  for (const entry of entries) {
    if (sessions.length >= maxSessions) {
      hitSessionLimit = true;
      break;
    }
    const streams = buildFlowStreams(entry, { maxBytes: maxStreamBytes });
    if (!streams) continue;
    const { clientToServer, serverToClient } = streams;
    if (clientToServer.data.length < 5 && serverToClient.data.length < 5) continue;
    const clientRecords = parseTlsRecords(clientToServer.data, { maxRecords: 200, maxHandshake: 32 });
    const clientHelloMsg = clientRecords.messages.find((m) => m.type === 1);
    const serverRecords = parseTlsRecords(serverToClient.data, { maxRecords: 200, maxHandshake: 32 });
    const serverHelloMsg = serverRecords.messages.find((m) => m.type === 2);
    if (!clientHelloMsg && !serverHelloMsg) continue;
    candidateFlows++;
    const clientHello = clientHelloMsg ? parseClientHello(clientHelloMsg.body) : null;
    const serverHello = serverHelloMsg ? parseServerHello(serverHelloMsg.body) : null;
    const sni = clientHello && clientHello.ok ? clientHello.sni : null;
    const version = serverHello && serverHello.ok ? serverHello.selectedVersionName : clientHello && clientHello.ok ? clientHello.legacyVersionName : null;
    sessions.push({
      flowId: entry.flow.id,
      firstSeen: isoTime(entry.flow.firstTs),
      client: formatEndpoint(entry.flow.client),
      server: formatEndpoint(entry.flow.server),
      serverPort: entry.flow.serverPort,
      service: entry.flow.service,
      sni,
      alpn: clientHello && clientHello.ok ? clientHello.alpn : [],
      serverAlpn: serverHello && serverHello.ok ? serverHello.alpn : [],
      clientLegacyVersion: clientHello && clientHello.ok ? clientHello.legacyVersionName : null,
      clientSupportedVersions: clientHello && clientHello.ok ? clientHello.supportedVersions.map((v) => v.name) : [],
      selectedVersion: version,
      negotiatedCipherSuite: serverHello && serverHello.ok ? serverHello.cipherSuiteName : null,
      clientCipherSuiteCount: clientHello && clientHello.ok ? clientHello.cipherSuiteCount : null,
      clientCipherSuites: clientHello && clientHello.ok ? clientHello.cipherSuitesNoGrease.slice(0, 12) : [],
      ja3Like: clientHello && clientHello.ok ? clientHello.ja3Like : null,
      ja3LikeSha256: clientHello && clientHello.ok ? clientHello.ja3LikeSha256 : null,
      clientRecordCount: clientRecords.recordCount,
      serverRecordCount: serverRecords.recordCount,
      handshakeTypes: [...new Set([...clientRecords.messages, ...serverRecords.messages].map((m) => m.typeName))],
      helloRetryRequest: serverHello && serverHello.ok ? serverHello.isHelloRetryRequest : false,
      clientTruncated: clientRecords.truncated,
      serverTruncated: serverRecords.truncated,
      streamGaps: {
        clientToServer: clientToServer.gaps,
        serverToClient: serverToClient.gaps,
      },
      helloParsed: Boolean((clientHello && clientHello.ok) || (serverHello && serverHello.ok)),
      errors: [...clientRecords.errors.slice(0, 3), ...serverRecords.errors.slice(0, 3)].slice(0, 5),
    });
  }
  const sessionsTruncated = hitSessionLimit;
  return {
    sessions,
    candidateFlowCount: candidateFlows,
    sessionCount: sessions.length,
    truncated: sessionsTruncated,
    warnings,
  };
}
