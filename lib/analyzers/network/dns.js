// ArmorBreak - DNS 报文解析与统计（纯 node:*）
// 支持 UDP/TCP(2 字节长度前缀) DNS；压缩指针循环防护；全部结果有上限。
import { formatIpv4, formatIpv6, isoTime, sanitizeText } from './util.js';

export const DNS_TYPES = new Map([
  [1, 'A'],
  [2, 'NS'],
  [5, 'CNAME'],
  [6, 'SOA'],
  [12, 'PTR'],
  [15, 'MX'],
  [16, 'TXT'],
  [28, 'AAAA'],
  [33, 'SRV'],
  [35, 'NAPTR'],
  [41, 'OPT'],
  [43, 'DS'],
  [46, 'RRSIG'],
  [47, 'NSEC'],
  [48, 'DNSKEY'],
  [52, 'TLSA'],
  [64, 'SVCB'],
  [65, 'HTTPS'],
  [255, 'ANY'],
  [257, 'CAA'],
]);

export const RCODE_NAMES = new Map([
  [0, 'NOERROR'],
  [1, 'FORMERR'],
  [2, 'SERVFAIL'],
  [3, 'NXDOMAIN'],
  [4, 'NOTIMP'],
  [5, 'REFUSED'],
  [6, 'YXDOMAIN'],
  [7, 'YXRRSET'],
  [8, 'NXRRSET'],
  [9, 'NOTAUTH'],
  [10, 'NOTZONE'],
]);

export function qtypeName(type) {
  return DNS_TYPES.get(type) ?? `TYPE${type}`;
}

/**
 * 解码 DNS 域名（支持压缩指针）。
 * @returns {{name:string, next:number, ok:boolean, reason?:string}}
 */
export function decodeDnsName(buffer, offset, end, depth = 0) {
  if (depth > 16) return { name: '', next: offset, ok: false, reason: '压缩指针嵌套过深' };
  const parts = [];
  let pos = offset;
  let next = null;
  let guard = 0;
  while (pos < end) {
    if (++guard > 128) return { name: parts.join('.'), next: next ?? pos, ok: false, reason: '域名标签过多' };
    const len = buffer[pos];
    if (len === 0) {
      if (next === null) next = pos + 1;
      return { name: parts.join('.'), next, ok: true };
    }
    if ((len & 0xc0) === 0xc0) {
      if (pos + 1 >= end) return { name: parts.join('.'), next: pos, ok: false, reason: '压缩指针越界' };
      const pointer = ((len & 0x3f) << 8) | buffer[pos + 1];
      if (next === null) next = pos + 2;
      if (pointer >= end) return { name: parts.join('.'), next, ok: false, reason: '压缩指针指向越界' };
      const sub = decodeDnsName(buffer, pointer, end, depth + 1);
      if (sub.name) parts.push(sub.name);
      return { name: parts.join('.'), next, ok: sub.ok, ...(sub.ok ? {} : { reason: sub.reason }) };
    }
    if ((len & 0xc0) !== 0) return { name: parts.join('.'), next: next ?? pos, ok: false, reason: `非法标签长度 0x${len.toString(16)}` };
    if (pos + 1 + len > end) return { name: parts.join('.'), next: next ?? pos, ok: false, reason: '标签越过报文边界' };
    const label = buffer.subarray(pos + 1, pos + 1 + len).toString('latin1');
    parts.push(label);
    pos += 1 + len;
    if (parts.join('.').length > 255) return { name: parts.join('.'), next: pos, ok: false, reason: '域名超过 255 字节' };
  }
  return { name: parts.join('.'), next: next ?? pos, ok: false, reason: '域名未以 NUL 结束（截断）' };
}

function readRdata(buffer, start, length, type, messageEnd) {
  const end = start + length;
  if (end > messageEnd) return { value: null, error: 'rdata 越过报文边界' };
  try {
    switch (type) {
      case 1:
        if (length !== 4) return { value: null, error: `A 记录长度 ${length} != 4` };
        return { value: formatIpv4(buffer.subarray(start, start + 4)) };
      case 28:
        if (length !== 16) return { value: null, error: `AAAA 记录长度 ${length} != 16` };
        return { value: formatIpv6(buffer.subarray(start, start + 16)) };
      case 2:
      case 5:
      case 12: {
        const name = decodeDnsName(buffer, start, messageEnd);
        return { value: name.ok ? name.name : null, error: name.ok ? null : name.reason };
      }
      case 15: {
        if (length < 3) return { value: null, error: 'MX 记录过短' };
        const pref = buffer.readUInt16BE(start);
        const name = decodeDnsName(buffer, start + 2, messageEnd);
        return { value: name.ok ? `${pref} ${name.name}` : null, error: name.ok ? null : name.reason };
      }
      case 16: {
        const texts = [];
        let p = start;
        let guard = 0;
        while (p < end && guard++ < 64) {
          const len = buffer[p];
          if (p + 1 + len > end) break;
          texts.push(buffer.subarray(p + 1, p + 1 + len).toString('utf8'));
          p += 1 + len;
        }
        return { value: sanitizeText(texts.join(' '), 500) };
      }
      case 33: {
        if (length < 7) return { value: null, error: 'SRV 记录过短' };
        const priority = buffer.readUInt16BE(start);
        const weight = buffer.readUInt16BE(start + 2);
        const port = buffer.readUInt16BE(start + 4);
        const name = decodeDnsName(buffer, start + 6, messageEnd);
        return { value: name.ok ? `${priority} ${weight} ${port} ${name.name}` : null, error: name.ok ? null : name.reason };
      }
      case 6: {
        const mname = decodeDnsName(buffer, start, messageEnd);
        if (!mname.ok) return { value: null, error: mname.reason };
        const rname = decodeDnsName(buffer, mname.next, messageEnd);
        return { value: rname.ok ? `${mname.name} ${rname.name}` : null };
      }
      case 257: {
        if (length < 2) return { value: null, error: 'CAA 记录过短' };
        const tagLen = buffer[start + 1];
        if (start + 2 + tagLen > end) return { value: null, error: 'CAA tag 越界' };
        const tag = buffer.subarray(start + 2, start + 2 + tagLen).toString('latin1');
        const value = buffer.subarray(start + 2 + tagLen, end).toString('utf8');
        return { value: sanitizeText(`${tag}="${value}"`, 300) };
      }
      default:
        return { value: buffer.subarray(start, Math.min(end, start + 16)).toString('hex') };
    }
  } catch (err) {
    return { value: null, error: err && err.message ? err.message : 'rdata 解析异常' };
  }
}

/**
 * 解析单条 DNS 报文。
 * @param {Buffer} payload
 * @param {{isTcp?:boolean, maxAnswers?:number, maxQuestions?:number}} opts
 */
export function parseDnsMessage(payload, opts = {}) {
  const maxAnswers = Math.max(1, Math.min(opts.maxAnswers ?? 64, 512));
  const maxQuestions = Math.max(1, Math.min(opts.maxQuestions ?? 8, 32));
  let buf = payload;
  if (!Buffer.isBuffer(buf)) return { ok: false, reason: 'DNS 载荷不是 Buffer' };
  if (opts.isTcp) {
    if (buf.length < 2) return { ok: false, reason: 'TCP DNS 缺少 2 字节长度前缀' };
    const declared = buf.readUInt16BE(0);
    buf = buf.subarray(2, 2 + Math.min(declared, buf.length - 2));
  }
  if (buf.length < 12) return { ok: false, reason: `DNS 报文仅 ${buf.length} 字节，小于头部 12 字节` };
  const id = buf.readUInt16BE(0);
  const flags = buf.readUInt16BE(2);
  const isResponse = (flags & 0x8000) !== 0;
  const opcode = (flags >> 11) & 0x0f;
  const authoritative = (flags & 0x0400) !== 0;
  const truncatedFlag = (flags & 0x0200) !== 0;
  const recursionDesired = (flags & 0x0100) !== 0;
  const recursionAvailable = (flags & 0x0080) !== 0;
  const rcode = flags & 0x0f;
  const qdcount = buf.readUInt16BE(4);
  const ancount = buf.readUInt16BE(6);
  const nscount = buf.readUInt16BE(8);
  const arcount = buf.readUInt16BE(10);
  const warnings = [];
  let pos = 12;
  const questions = [];
  for (let i = 0; i < Math.min(qdcount, maxQuestions); i++) {
    const qname = decodeDnsName(buf, pos, buf.length);
    if (!qname.ok) return { ok: false, reason: `问题 ${i} 域名解析失败：${qname.reason}`, id, isResponse };
    if (qname.next + 4 > buf.length) return { ok: false, reason: `问题 ${i} 越界（截断）`, id, isResponse };
    const qtype = buf.readUInt16BE(qname.next);
    const qclass = buf.readUInt16BE(qname.next + 2);
    questions.push({ name: sanitizeText(qname.name, 255), type: qtype, typeName: qtypeName(qtype), class: qclass });
    pos = qname.next + 4;
  }
  if (qdcount > maxQuestions) warnings.push(`问题数 ${qdcount} 超过上限 ${maxQuestions}，已截断。`);

  // 跳过 authority 区（不解析），按 ancount 解析 answer
  const answers = [];
  for (let i = 0; i < Math.min(ancount, maxAnswers); i++) {
    const nameRes = decodeDnsName(buf, pos, buf.length);
    if (!nameRes.ok) {
      warnings.push(`答案 ${i} 域名解析失败：${nameRes.reason}`);
      break;
    }
    if (nameRes.next + 10 > buf.length) {
      warnings.push(`答案 ${i} 头部越界（截断）`);
      break;
    }
    const type = buf.readUInt16BE(nameRes.next);
    const cls = buf.readUInt16BE(nameRes.next + 2);
    const ttl = buf.readUInt32BE(nameRes.next + 4);
    const rdlength = buf.readUInt16BE(nameRes.next + 8);
    const rdataStart = nameRes.next + 10;
    if (rdataStart + rdlength > buf.length) {
      warnings.push(`答案 ${i} rdata 越界（截断）`);
      break;
    }
    const decoded = readRdata(buf, rdataStart, rdlength, type, buf.length);
    answers.push({
      name: sanitizeText(nameRes.name, 255),
      type,
      typeName: qtypeName(type),
      class: cls,
      ttl,
      value: decoded.value === null ? null : sanitizeText(String(decoded.value), 500),
      ...(decoded.error ? { error: decoded.error } : {}),
    });
    pos = rdataStart + rdlength;
  }
  if (ancount > maxAnswers) warnings.push(`答案数 ${ancount} 超过上限 ${maxAnswers}，已截断。`);
  return {
    ok: true,
    id,
    isResponse,
    opcode,
    authoritative,
    truncatedFlag,
    recursionDesired,
    recursionAvailable,
    rcode,
    rcodeName: RCODE_NAMES.get(rcode) ?? `RCODE${rcode}`,
    questionCount: qdcount,
    answerCount: ancount,
    authorityCount: nscount,
    additionalCount: arcount,
    questions,
    answers,
    warnings,
  };
}

/**
 * 从解码后的报文中汇集 DNS 统计。
 * @param {Array} packets
 * @param {{maxMessages?:number, maxAnswers?:number, maxNames?:number, maxSamples?:number}} opts
 */
export function collectDns(packets, opts = {}) {
  const maxMessages = Math.max(1, Math.min(opts.maxMessages ?? 2000, 20000));
  const maxAnswers = Math.max(1, Math.min(opts.maxAnswers ?? 32, 128));
  const maxNames = Math.max(1, Math.min(opts.maxNames ?? 200, 2000));
  const maxSamples = Math.max(1, Math.min(opts.maxSamples ?? 50, 200));
  const rcodeCounts = new Map();
  const qtypeCounts = new Map();
  const nameCounts = new Map();
  const nameFirstTs = new Map();
  const resolverPairs = new Map();
  const queries = [];
  const answersSample = [];
  const ipAnswers = new Map();
  let messageCount = 0;
  let queryCount = 0;
  let responseCount = 0;
  let nxdomainCount = 0;
  let servfailCount = 0;
  let tcpDnsCount = 0;
  let parseErrors = 0;
  let messagesTruncated = false;
  for (const packet of packets) {
    if (messageCount >= maxMessages) {
      messagesTruncated = true;
      break;
    }
    let parsed = null;
    if (packet.proto === 'udp' && (packet.srcPort === 53 || packet.dstPort === 53)) {
      parsed = parseDnsMessage(packet.payload, { maxAnswers });
    } else if (packet.proto === 'tcp' && (packet.srcPort === 53 || packet.dstPort === 53)) {
      tcpDnsCount++;
      parsed = parseDnsMessage(packet.payload, { isTcp: true, maxAnswers });
    }
    if (!parsed) continue;
    messageCount++;
    if (!parsed.ok) {
      parseErrors++;
      continue;
    }
    if (parsed.isResponse) {
      responseCount++;
      const rcodeName = parsed.rcodeName;
      rcodeCounts.set(rcodeName, (rcodeCounts.get(rcodeName) || 0) + 1);
      if (parsed.rcode === 3) nxdomainCount++;
      if (parsed.rcode === 2) servfailCount++;
    } else {
      queryCount++;
      const client = packet.src;
      const resolver = packet.dst;
      const pairKey = `${client}|${resolver}`;
      const pair = resolverPairs.get(pairKey) || { client, resolver, queries: 0 };
      pair.queries += 1;
      resolverPairs.set(pairKey, pair);
      for (const question of parsed.questions) {
        if (queries.length < maxSamples) {
          queries.push({
            tsIso: isoTime(packet.tsSeconds),
            tsSeconds: packet.tsSeconds,
            client,
            resolver,
            name: question.name,
            qtype: question.typeName,
          });
        }
        qtypeCounts.set(question.typeName, (qtypeCounts.get(question.typeName) || 0) + 1);
        const lower = question.name.toLowerCase();
        nameCounts.set(lower, (nameCounts.get(lower) || 0) + 1);
        if (!nameFirstTs.has(lower) && Number.isFinite(packet.tsSeconds)) nameFirstTs.set(lower, packet.tsSeconds);
      }
    }
    for (const answer of parsed.answers) {
      if (answersSample.length < maxSamples) {
        answersSample.push({
          name: answer.name,
          type: answer.typeName,
          ttl: answer.ttl,
          value: answer.value,
        });
      }
      const lower = answer.name.toLowerCase();
      if (!nameCounts.has(lower)) nameCounts.set(lower, 0);
      if (!nameFirstTs.has(lower) && Number.isFinite(packet.tsSeconds)) nameFirstTs.set(lower, packet.tsSeconds);
      if (answer.type === 1 || answer.type === 28) {
        const key = `${answer.typeName}:${answer.value}`;
        ipAnswers.set(key, (ipAnswers.get(key) || 0) + 1);
      }
      for (const part of [answer.name, typeof answer.value === 'string' ? answer.value : '']) {
        if (!part) continue;
        // MX/SRV/CNAME 的 value 中可能包含域名，简单提取
        for (const token of String(part).split(/[\s,;]+/)) {
          const cleaned = token.replace(/\.$/, '').toLowerCase();
          if (/^[a-z0-9_*-]+(\.[a-z0-9_*-]+)+$/.test(cleaned) && !/^\d+(\.\d+){3}$/.test(cleaned)) {
            if (!nameCounts.has(cleaned)) nameCounts.set(cleaned, 0);
            if (!nameFirstTs.has(cleaned) && Number.isFinite(packet.tsSeconds)) nameFirstTs.set(cleaned, packet.tsSeconds);
          }
        }
      }
    }
  }
  const topNames = [...nameCounts.entries()]
    .filter(([name]) => name.length > 0)
    .sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1))
    .slice(0, maxNames)
    .map(([name, count]) => ({ name, count, firstSeen: isoTime(nameFirstTs.get(name) ?? NaN) }));
  return {
    messageCount,
    queryCount,
    responseCount,
    nxdomainCount,
    servfailCount,
    tcpDnsCount,
    parseErrors,
    rcodeCounts: [...rcodeCounts.entries()]
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
      .map(([rcode, count]) => ({ rcode, count })),
    qtypeCounts: [...qtypeCounts.entries()]
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
      .map(([type, count]) => ({ type, count })),
    resolverPairs: [...resolverPairs.values()].sort((a, b) => b.queries - a.queries || a.client.localeCompare(b.client)).slice(0, maxNames),
    queries,
    answers: answersSample,
    names: topNames,
    ipAnswers: [...ipAnswers.entries()]
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
      .map(([key, count]) => {
        const [type, value] = key.split(':');
        return { type, value, count };
      }),
    truncated: messagesTruncated,
  };
}
