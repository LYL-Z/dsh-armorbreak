/**
 * Forensics — structural timestamp extraction into a deterministic sorted event list.
 * Only timestamps that exist in the file format itself are reported; text date scanning
 * is opt-in via options.includeTextScan and is labeled as hypothesis.
 */
import { parseElf } from '../binary/elf.js';
import { parseMachO } from '../binary/macho.js';
import { parsePe } from '../binary/pe.js';
import { extractAsciiStrings, extractUtf16Strings } from '../binary/util.js';
import { parseExifDate } from './util.js';
import { parseGzip, parseJpeg, parsePdf, parsePng } from './formats.js';
import { parseZip } from './zip.js';

function makeEvent({ time, epochSeconds = null, source, field, target = null, timezone = 'utc', verification = 'observed', note = null }) {
  const event = { time, epochSeconds, source, field, target, timezone, verification };
  if (note) event.note = note;
  return event;
}

function peEvents(buffer, maxEvents) {
  const events = [];
  const notes = [];
  const parsed = parsePe(buffer, { maxSections: 64 });
  if (!parsed.ok) return { events, notes: [parsed.reason] };
  if (parsed.coff.compiledAt) {
    events.push(makeEvent({
      time: parsed.coff.compiledAt,
      epochSeconds: parsed.coff.timeDateStamp,
      source: 'pe.coff',
      field: 'TimeDateStamp',
      target: 'PE COFF 头',
      timezone: 'utc',
    }));
  } else {
    notes.push('PE COFF 编译时间戳为 0 或越界，未生成事件。');
  }
  if (parsed.debug) {
    for (const entry of parsed.debug.entries) {
      if (entry.timestamp) {
        events.push(makeEvent({
          time: entry.timestamp,
          epochSeconds: entry.timestampRaw || null,
          source: 'pe.debug-directory',
          field: `IMAGE_DEBUG_DIRECTORY[${entry.index}].TimeDateStamp`,
          target: `调试目录 ${entry.typeName}`,
          timezone: 'utc',
          note: '调试目录时间戳可能来自构建工具而非编译时刻。',
        }));
      }
      if (entry.codeview && entry.codeview.timestamp) {
        events.push(makeEvent({
          time: entry.codeview.timestamp,
          epochSeconds: entry.codeview.timestampRaw || null,
          source: 'pe.codeview',
          field: 'NB10.Timestamp',
          target: entry.codeview.pdbPath || 'PDB',
          timezone: 'utc',
        }));
      }
    }
  }
  return { events: events.slice(0, maxEvents), notes };
}

function zipEvents(buffer, maxEvents) {
  const parsed = parseZip(buffer, { maxEntries: maxEvents });
  const events = [];
  const notes = [...parsed.warnings];
  for (const entry of parsed.entries) {
    if (events.length >= maxEvents) { notes.push(`ZIP 时间事件达到 maxEvents=${maxEvents} 上限，后续条目已截断。`); break; }
    const ts = entry.timestamp;
    if (ts && ts.iso) {
      events.push(makeEvent({
        time: ts.iso,
        epochSeconds: Number.isFinite(ts.epochSeconds) ? ts.epochSeconds : null,
        source: ts.source === 'extended-timestamp' ? 'zip.extra-field' : 'zip.central-directory',
        field: ts.source === 'extended-timestamp' ? 'extended timestamp (0x5455)' : 'DOS date/time',
        target: entry.name,
        timezone: ts.timezone || 'local-unassigned',
        note: ts.timezone === 'local-unassigned' ? 'DOS 时间无时区信息，按 UTC 字段值原样展示。' : null,
      }));
    }
    if (entry.extraTimes) {
      for (const [field, iso] of Object.entries(entry.extraTimes)) {
        if (!iso) continue;
        if (events.length >= maxEvents) break;
        const epoch = iso ? Math.floor(Date.parse(iso) / 1000) : null;
        events.push(makeEvent({
          time: iso,
          epochSeconds: epoch,
          source: 'zip.extra-field',
          field: `extended timestamp ${field}`,
          target: entry.name,
          timezone: 'utc',
        }));
      }
    }
  }
  return { events: events.slice(0, maxEvents), notes };
}

function pngEvents(buffer, maxEvents) {
  const png = parsePng(buffer);
  const events = [];
  if (png.time) {
    events.push(makeEvent({
      time: png.time.iso,
      epochSeconds: png.time.epochSeconds,
      source: 'png.time-chunk',
      field: 'tIME',
      target: 'PNG tIME 数据块',
      timezone: 'utc',
    }));
  }
  return { events: events.slice(0, maxEvents), notes: png.notes };
}

function jpegEvents(buffer, maxEvents) {
  const jpeg = parseJpeg(buffer);
  const events = [];
  const notes = [...jpeg.notes];
  if (jpeg.exif) {
    for (const field of ['DateTimeOriginal', 'DateTimeDigitized', 'DateTime']) {
      const raw = jpeg.exif.fields[field];
      if (typeof raw !== 'string') continue;
      const parsed = parseExifDate(raw);
      if (!parsed) continue;
      events.push(makeEvent({
        time: parsed.iso,
        epochSeconds: parsed.epochSeconds,
        source: 'jpeg.exif',
        field,
        target: 'EXIF IFD',
        timezone: 'local-unassigned',
        note: 'EXIF 时间无时区信息。',
      }));
      if (events.length >= maxEvents) break;
    }
  } else {
    notes.push('JPEG 无 EXIF 或未解析到 EXIF 日期字段。');
  }
  return { events: events.slice(0, maxEvents), notes };
}

function gzipEvents(buffer, maxEvents) {
  const gzip = parseGzip(buffer);
  const events = [];
  if (gzip.mtime) {
    events.push(makeEvent({
      time: gzip.mtime.iso,
      epochSeconds: gzip.mtime.epochSeconds,
      source: 'gzip.header',
      field: 'MTIME',
      target: gzip.originalName || 'gzip 头',
      timezone: 'utc',
    }));
  }
  return { events: events.slice(0, maxEvents), notes: gzip.notes };
}

function pdfEvents(buffer, maxEvents) {
  const pdf = parsePdf(buffer);
  const events = [];
  if (pdf.creationDate) {
    events.push(makeEvent({
      time: pdf.creationDate.iso,
      epochSeconds: pdf.creationDate.epochSeconds,
      source: 'pdf.info',
      field: 'CreationDate',
      target: 'PDF Info',
      timezone: pdf.creationDate.timezone,
    }));
  }
  if (pdf.modDate) {
    events.push(makeEvent({
      time: pdf.modDate.iso,
      epochSeconds: pdf.modDate.epochSeconds,
      source: 'pdf.info',
      field: 'ModDate',
      target: 'PDF Info',
      timezone: pdf.modDate.timezone,
    }));
  }
  return { events: events.slice(0, maxEvents), notes: pdf.notes };
}

/** Opt-in heuristic: ISO-like date strings found in extracted strings. */
function textDateEvents(buffer, maxEvents) {
  const ascii = extractAsciiStrings(buffer, { minLen: 10, max: Math.min(2000, maxEvents * 4) });
  const utf16 = extractUtf16Strings(buffer, { minLen: 10, max: Math.min(500, maxEvents * 2) });
  const re = /\b(20\d{2})[-/](\d{1,2})[-/](\d{1,2})[T ](\d{1,2}):(\d{2})(?::(\d{2}))?\b/g;
  const events = [];
  const seen = new Set();
  const scan = (list) => {
    for (const item of list) {
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(item.value)) !== null && events.length < maxEvents) {
        const [year, month, day, hour, minute, second] = [m[1], m[2], m[3], m[4], m[5], m[6] || '0'].map(Number);
        if (month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59 || second > 60) continue;
        const iso = `${String(year).padStart(4, '0')}-${String(month).padStart(2, '0')}-${String(day).padStart(2, '0')}T${String(hour).padStart(2, '0')}:${String(minute).padStart(2, '0')}:${String(second).padStart(2, '0')}`;
        const key = `${iso}:${item.offset}`;
        if (seen.has(key)) continue;
        seen.add(key);
        events.push(makeEvent({
          time: iso,
          epochSeconds: Math.floor(Date.parse(`${iso}Z`) / 1000),
          source: 'text.scan',
          field: 'embedded text date',
          target: `offset ${item.offset}`,
          timezone: 'local-unassigned',
          verification: 'hypothesis',
          note: '从字符串中扫描到的日期，非文件结构时间戳，可能为日志/配置/文档文本。',
        }));
        if (m.index === re.lastIndex) re.lastIndex += 1;
      }
    }
  };
  scan(ascii.strings);
  scan(utf16.strings);
  return events.slice(0, maxEvents);
}

/**
 * @returns {{format:string, events:Array, notes:string[], summary:string}}
 */
export function extractTimeline(buffer, typeInfo, limits, options = {}, env = {}) {
  const maxEvents = Math.max(1, Math.min(1000, Number.isFinite(options.maxEvents) ? Math.floor(options.maxEvents) : Math.min(limits.maxItems, 200)));
  const type = typeInfo.type;
  let collected = { events: [], notes: [] };
  let format = type;
  if (type === 'pe-executable' || type === 'pe-dll') { collected = peEvents(buffer, maxEvents); format = 'pe'; }
  else if (type.startsWith('elf')) {
    const parsed = parseElf(buffer, { maxSymbols: 0 });
    collected = { events: [], notes: ['ELF 结构不含时间戳字段；未生成结构时间事件。'] };
    if (!parsed.ok) collected.notes.push(parsed.reason);
    format = 'elf';
  } else if (type === 'mach-o' || type === 'mach-o-universal') {
    const parsed = parseMachO(buffer, { maxSymbols: 0 });
    collected = {
      events: [],
      notes: [parsed.ok
        ? 'Mach-O 结构不含时间戳字段（LC_BUILD_VERSION 只有版本号）；未生成结构时间事件。'
        : parsed.reason],
    };
    format = 'macho';
  } else if (['zip', 'docx', 'xlsx', 'pptx', 'ooxml', 'apk', 'jar', 'epub', 'odf'].includes(type)) { collected = zipEvents(buffer, maxEvents); format = 'zip'; }
  else if (type === 'png') { collected = pngEvents(buffer, maxEvents); format = 'png'; }
  else if (type === 'jpeg') { collected = jpegEvents(buffer, maxEvents); format = 'jpeg'; }
  else if (type === 'gzip') { collected = gzipEvents(buffer, maxEvents); format = 'gzip'; }
  else if (type === 'pdf') { collected = pdfEvents(buffer, maxEvents); format = 'pdf'; }
  else {
    collected = { events: [], notes: [`格式 ${type} 没有已知的结构化时间戳字段。`] };
  }
  if (options.includeTextScan === true && collected.events.length === 0 && buffer.length > 0) {
    const textEvents = textDateEvents(buffer, Math.min(maxEvents, 50));
    if (textEvents.length > 0) {
      collected.events.push(...textEvents);
      collected.notes.push('已启用文本日期扫描（hypothesis）：日期来自字符串而非结构字段。');
    }
  }
  const seen = new Set();
  const unique = [];
  for (const event of collected.events) {
    const key = `${event.time}|${event.source}|${event.field}|${event.target}`;
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push(event);
  }
  const sorted = unique.sort((a, b) => {
    const ea = Number.isFinite(a.epochSeconds) ? a.epochSeconds : Number.POSITIVE_INFINITY;
    const eb = Number.isFinite(b.epochSeconds) ? b.epochSeconds : Number.POSITIVE_INFINITY;
    if (ea !== eb) return ea - eb;
    if (a.time !== b.time) return a.time < b.time ? -1 : 1;
    if (a.source !== b.source) return a.source < b.source ? -1 : 1;
    return String(a.target).localeCompare(String(b.target));
  }).slice(0, maxEvents);
  const countsBySource = {};
  for (const e of sorted) countsBySource[e.source] = (countsBySource[e.source] || 0) + 1;
  const summary = sorted.length > 0
    ? [
      `从 ${format} 结构提取 ${sorted.length} 个时间事件${unique.length > sorted.length ? `（另有 ${unique.length - sorted.length} 个超出 maxEvents 被截断）` : ''}。`,
      `时间范围：${sorted[0].time} ~ ${sorted[sorted.length - 1].time}。`,
      `来源统计：${Object.entries(countsBySource).map(([k, v]) => `${k}=${v}`).join(', ')}。`,
      collected.notes.length > 0 ? `备注：${collected.notes.join('；')}` : '',
    ].filter(Boolean).join('\n')
    : `未从 ${format} 结构中找到时间戳。${collected.notes.length > 0 ? `\n备注：${collected.notes.join('；')}` : ''}`;
  return {
    format,
    summary,
    data: {
      format,
      eventCount: sorted.length,
      events: sorted,
      countsBySource,
      notes: collected.notes,
      includedTextScan: options.includeTextScan === true,
      maxEvents,
    },
    warnings: collected.notes,
  };
}
