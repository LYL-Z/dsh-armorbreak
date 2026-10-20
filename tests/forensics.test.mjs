/**
 * ArmorBreak — forensics domain tests.
 * Fixtures are built programmatically with Buffer (no binary files committed).
 * Run from armorbreak/: node --test tests/binary.test.mjs tests/forensics.test.mjs
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import manifest from '../lib/analyzers/forensics/manifest.js';
import { detectFileType } from '../lib/analyzers/forensics/filetype.js';
import { parseZip } from '../lib/analyzers/forensics/zip.js';
import { parsePng, parseJpeg } from '../lib/analyzers/forensics/formats.js';
import { RULES } from '../lib/analyzers/forensics/yara-lite.js';

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
// Fixture builders
// ---------------------------------------------------------------------------

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i += 1) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

const DOS_DATE = ((2021 - 1980) << 9) | (3 << 5) | 4; // 2021-03-04
const DOS_TIME = (5 << 11) | (6 << 5) | 4; // 05:06:08

/** Build a real (stored-method) ZIP archive with central directory and optional extra timestamps. */
function buildZip(entries) {
  const localParts = [];
  const centralParts = [];
  let offset = 0;
  for (const entry of entries) {
    const name = Buffer.from(entry.name, 'utf8');
    const data = Buffer.from(entry.data || '', 'utf8');
    const crc = crc32(data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0x0800, 6); // UTF-8 name
    local.writeUInt16LE(0, 8); // stored
    local.writeUInt16LE(DOS_TIME, 10);
    local.writeUInt16LE(DOS_DATE, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(name.length, 26);
    local.writeUInt16LE(0, 28);
    localParts.push(local, name, data);
    let extra = Buffer.alloc(0);
    if (entry.extraMtime) {
      extra = Buffer.alloc(9);
      extra.writeUInt16LE(0x5455, 0);
      extra.writeUInt16LE(5, 2);
      extra.writeUInt8(0x01, 4);
      extra.writeUInt32LE(entry.extraMtime, 5);
    }
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0x0800, 8);
    central.writeUInt16LE(0, 10);
    central.writeUInt16LE(DOS_TIME, 12);
    central.writeUInt16LE(DOS_DATE, 14);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(data.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt16LE(extra.length, 30);
    central.writeUInt16LE(0, 32);
    central.writeUInt16LE(0, 34);
    central.writeUInt16LE(0, 36);
    central.writeUInt32LE(0, 38);
    central.writeUInt32LE(offset, 42);
    centralParts.push(central, name, extra);
    offset += local.length + name.length + data.length;
  }
  const centralDir = Buffer.concat(centralParts);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(centralDir.length, 12);
  eocd.writeUInt32LE(offset, 16);
  eocd.writeUInt16LE(0, 20);
  return Buffer.concat([...localParts, centralDir, eocd]);
}

function buildPng() {
  const chunk = (type, data) => {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length, 0);
    const typeBuf = Buffer.from(type, 'latin1');
    const crcBuf = Buffer.alloc(4);
    crcBuf.writeUInt32BE(crc32(Buffer.concat([typeBuf, data])), 0);
    return Buffer.concat([len, typeBuf, data, crcBuf]);
  };
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(64, 0);
  ihdr.writeUInt32BE(32, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // RGBA
  ihdr[10] = 0;
  ihdr[11] = 0;
  ihdr[12] = 0;
  const text = Buffer.concat([Buffer.from('Comment'), Buffer.alloc(1), Buffer.from('armorbreak fixture')]);
  const time = Buffer.from([0x07, 0xe6, 7, 8, 9, 10, 11]); // 2022-07-08 09:10:11
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('tEXt', text),
    chunk('tIME', time),
    chunk('IDAT', Buffer.from([0x78, 0x9c, 0x01, 0x02, 0x03, 0x04])),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

function buildJpeg() {
  // Minimal EXIF TIFF: IFD0 with Make, DateTime, ExifIFD pointer; ExifIFD with DateTimeOriginal.
  const tiff = Buffer.alloc(128);
  tiff.write('II', 0, 'latin1');
  tiff.writeUInt16LE(42, 2);
  tiff.writeUInt32LE(8, 4); // IFD0 offset
  tiff.writeUInt16LE(3, 8); // entry count
  // entry 1: Make (ASCII) -> offset 58, value "AcmeCam\0" (8 bytes)
  tiff.writeUInt16LE(0x010f, 10);
  tiff.writeUInt16LE(2, 12);
  tiff.writeUInt32LE(8, 14);
  tiff.writeUInt32LE(58, 18);
  // entry 2: DateTime (ASCII) -> offset 66, "2020:01:02 03:04:05\0"
  tiff.writeUInt16LE(0x0132, 22);
  tiff.writeUInt16LE(2, 24);
  tiff.writeUInt32LE(20, 26);
  tiff.writeUInt32LE(66, 30);
  // entry 3: ExifIFDPointer (LONG) -> 86
  tiff.writeUInt16LE(0x8769, 34);
  tiff.writeUInt16LE(4, 36);
  tiff.writeUInt32LE(1, 38);
  tiff.writeUInt32LE(86, 42);
  tiff.writeUInt32LE(0, 46); // next IFD
  tiff.write('AcmeCam\u0000', 58, 'latin1');
  tiff.write('2020:01:02 03:04:05\u0000', 66, 'latin1');
  // ExifIFD at 86; string data at 104
  tiff.writeUInt16LE(1, 86);
  tiff.writeUInt16LE(0x9003, 88); // DateTimeOriginal
  tiff.writeUInt16LE(2, 90);
  tiff.writeUInt32LE(20, 92);
  tiff.writeUInt32LE(104, 96); // string offset within tiff
  tiff.writeUInt32LE(0, 100);
  tiff.write('2020:01:02 03:04:06\u0000', 104, 'latin1');
  const payload = Buffer.concat([Buffer.from('Exif\u0000\u0000', 'latin1'), tiff]);
  const app1 = Buffer.alloc(4 + payload.length);
  app1[0] = 0xff;
  app1[1] = 0xe1;
  app1.writeUInt16BE(payload.length + 2, 2);
  payload.copy(app1, 4);
  // SOF0: 320x200, 3 components
  const sof = Buffer.alloc(19);
  sof[0] = 0xff;
  sof[1] = 0xc0;
  sof.writeUInt16BE(17, 2);
  sof[4] = 8; // precision
  sof.writeUInt16BE(200, 5); // height
  sof.writeUInt16BE(320, 7); // width
  sof[9] = 3; // components
  sof.fill(0x11, 10, 19);
  return Buffer.concat([Buffer.from([0xff, 0xd8]), app1, sof, Buffer.from([0xff, 0xd9])]);
}

const PE_RICH_TIMESTAMP = 0x5f600000;

function utf16z(s) {
  return Buffer.from(`${s}\u0000`, 'utf16le');
}

function pad4(buf) {
  const pad = (4 - (buf.length % 4)) % 4;
  return pad === 0 ? buf : Buffer.concat([buf, Buffer.alloc(pad)]);
}

function buildVersionBlob() {
  const fixed = Buffer.alloc(52);
  fixed.writeUInt32LE(0xfeef04bd, 0);
  fixed.writeUInt32LE(0x00010000, 4);
  fixed.writeUInt32LE(0x00010002, 8); // fileVersionMS -> 1.2
  fixed.writeUInt32LE(0x00030004, 12); // fileVersionLS -> 3.4
  fixed.writeUInt32LE(0x00020003, 16); // productVersionMS -> 2.3
  fixed.writeUInt32LE(0x00040005, 20); // productVersionLS -> 4.5
  const parts = [pad4(Buffer.concat([Buffer.alloc(6), utf16z('VS_VERSION_INFO')])), fixed];
  const strings = {
    CompanyName: 'Acme Security Labs',
    FileDescription: 'Agent Updater',
    OriginalFilename: 'agent.exe',
    ProductName: 'Acme Agent',
  };
  for (const [key, value] of Object.entries(strings)) {
    parts.push(pad4(utf16z(key)), utf16z(value));
  }
  return Buffer.concat(parts);
}

/** PE32+ with import-free .text/.rdata/.rsrc, version resources and CodeView debug directory. */
function buildPeRich() {
  const fileSize = 0xc00;
  const base = Buffer.alloc(fileSize, 0xcc);
  base.fill(0, 0, 0x200);
  base.fill(0, 0x400, 0x800);
  base.fill(0, 0x800, fileSize);
  base.write('MZ', 0, 'latin1');
  base.writeUInt32LE(0x80, 0x3c);
  base.writeUInt32LE(0x00004550, 0x80);
  base.writeUInt16LE(0x8664, 0x84);
  base.writeUInt16LE(3, 0x86); // .text, .rdata, .rsrc
  base.writeUInt32LE(PE_RICH_TIMESTAMP, 0x88);
  base.writeUInt32LE(0, 0x8c);
  base.writeUInt32LE(0, 0x90);
  base.writeUInt16LE(0xf0, 0x94);
  base.writeUInt16LE(0x0022, 0x96);
  const opt = 0x98;
  base.writeUInt16LE(0x20b, opt);
  base[opt + 2] = 14;
  base.writeUInt32LE(0x200, opt + 4);
  base.writeUInt32LE(0x800, opt + 8);
  base.writeUInt32LE(0x1000, opt + 16);
  base.writeUInt32LE(0x1000, opt + 20);
  base.writeBigUInt64LE(0x140000000n, opt + 24);
  base.writeUInt32LE(0x1000, opt + 32);
  base.writeUInt32LE(0x200, opt + 36);
  base.writeUInt16LE(6, opt + 40);
  base.writeUInt16LE(6, opt + 48);
  base.writeUInt32LE(0x4000, opt + 56);
  base.writeUInt32LE(0x200, opt + 60);
  base.writeUInt16LE(3, opt + 68);
  base.writeUInt16LE(0x0140, opt + 70);
  base.writeUInt32LE(16, opt + 108);
  const dirs = opt + 112;
  base.writeUInt32LE(0x3000, dirs + 2 * 8); // resource
  base.writeUInt32LE(0x400, dirs + 2 * 8 + 4);
  base.writeUInt32LE(0x2200, dirs + 6 * 8); // debug
  base.writeUInt32LE(28, dirs + 6 * 8 + 4);
  // Section headers at 0x188
  const sh = (i, name, vsize, vaddr, rawSize, rawPtr, chars) => {
    const off = 0x188 + i * 40;
    base.write(name, off, 'latin1');
    base.writeUInt32LE(vsize, off + 8);
    base.writeUInt32LE(vaddr, off + 12);
    base.writeUInt32LE(rawSize, off + 16);
    base.writeUInt32LE(rawPtr, off + 20);
    base.writeUInt32LE(chars, off + 36);
  };
  sh(0, '.text', 0x200, 0x1000, 0x200, 0x200, 0x60000020);
  sh(1, '.rdata', 0x400, 0x2000, 0x400, 0x400, 0x40000040);
  sh(2, '.rsrc', 0x400, 0x3000, 0x400, 0x800, 0x40000040);
  // CodeView debug entry at RVA 0x2200 -> file 0x600, data at 0x630
  const pdbPath = 'D:\\build\\agent.pdb';
  const codeview = Buffer.concat([
    Buffer.from('RSDS', 'latin1'),
    Buffer.from('00112233445566778899aabbccddeeff', 'hex'),
    Buffer.from([1, 0, 0, 0]),
    Buffer.from(`${pdbPath}\u0000`, 'latin1'),
  ]);
  base.writeUInt32LE(2, 0x600 + 12); // Type = CODEVIEW
  base.writeUInt32LE(codeview.length, 0x600 + 16);
  base.writeUInt32LE(0x2230, 0x600 + 20);
  base.writeUInt32LE(0x630, 0x600 + 24);
  base.writeUInt32LE(0x5f600000, 0x600 + 4); // debug timestamp
  codeview.copy(base, 0x630);
  // Resource tree at 0x800 (RVA 0x3000)
  base.writeUInt16LE(1, 0x800 + 14); // one ID entry
  base.writeUInt32LE(16, 0x810); // type RT_VERSION
  base.writeUInt32LE(0x80000018, 0x814); // -> dir at rel 0x18
  base.writeUInt16LE(1, 0x818 + 14);
  base.writeUInt32LE(1, 0x828); // name id 1
  base.writeUInt32LE(0x80000030, 0x82c); // -> dir at rel 0x30
  base.writeUInt16LE(1, 0x830 + 14);
  base.writeUInt32LE(0x409, 0x840); // language
  base.writeUInt32LE(0x48, 0x844); // -> data entry at rel 0x48
  const blob = buildVersionBlob();
  base.writeUInt32LE(0x3058, 0x848); // data RVA
  base.writeUInt32LE(blob.length, 0x84c);
  base.writeUInt32LE(0x4b0, 0x850); // codepage
  blob.copy(base, 0x858);
  // .text payload with a couple of strings
  base.fill(0x90, 0x200, 0x208);
  base.write('VersionCheck', 0x220, 'latin1');
  return base;
}

/** Minimal 64-bit little-endian ELF (no sections/symbols). */
function buildElfMinimal() {
  const buf = Buffer.alloc(64, 0);
  buf.write('\u007fELF', 0, 'latin1');
  buf[4] = 2;
  buf[5] = 1;
  buf[6] = 1;
  buf.writeUInt16LE(2, 16); // ET_EXEC
  buf.writeUInt16LE(62, 18); // x86-64
  buf.writeUInt32LE(1, 20);
  buf.writeBigUInt64LE(0x401000n, 24);
  buf.writeBigUInt64LE(0n, 32); // phoff
  buf.writeBigUInt64LE(0n, 40); // shoff
  buf.writeUInt16LE(64, 52);
  buf.writeUInt16LE(56, 54);
  buf.writeUInt16LE(0, 56);
  buf.writeUInt16LE(64, 58);
  buf.writeUInt16LE(0, 60);
  buf.writeUInt16LE(0, 62);
  return buf;
}

/** Minimal thin 64-bit Mach-O (no load commands but valid header). */
function buildMachOMinimal() {
  const buf = Buffer.alloc(32, 0);
  buf.writeUInt32LE(0xfeedfacf, 0);
  buf.writeUInt32LE(0x01000007, 4);
  buf.writeUInt32LE(3, 8);
  buf.writeUInt32LE(2, 12); // MH_EXECUTE
  buf.writeUInt32LE(0, 16);
  buf.writeUInt32LE(0, 20);
  buf.writeUInt32LE(0, 24);
  return buf;
}

function buildGzip() {
  const name = Buffer.from('note.txt\u0000', 'latin1');
  const header = Buffer.alloc(10);
  header[0] = 0x1f;
  header[1] = 0x8b;
  header[2] = 0x08;
  header[3] = 0x08; // FNAME
  header.writeUInt32LE(1600000000, 4); // mtime
  header[8] = 0;
  header[9] = 3; // unix
  return Buffer.concat([header, name, Buffer.from([0x03, 0x00, 0, 0, 0, 0], 'latin1')]);
}

function buildPdf() {
  const text = [
    '%PDF-1.7',
    '1 0 obj << /Producer (Acme Writer 2.0) /Creator (Acme Editor)',
    '/CreationDate (D:20220103040506Z) /ModDate (D:20220104050607+02\'00\') >> endobj',
    'trailer << /Root 2 0 R >>',
    '%%EOF',
  ].join('\n');
  return Buffer.from(text, 'latin1');
}

function buildOle2() {
  const buf = Buffer.alloc(0x600, 0);
  Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]).copy(buf, 0);
  buf.writeUInt16LE(3, 26); // majorVersion
  buf.writeUInt16LE(9, 30); // sectorShift
  buf.writeUInt16LE(6, 32); // miniSectorShift
  Buffer.from('WordDocument', 'utf16le').copy(buf, 0x200);
  return buf;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test('forensics manifest: domain, six capability ids, schema and no external tools required', () => {
  assert.equal(manifest.domain, 'forensics');
  const ids = manifest.capabilities.map((c) => c.id).sort();
  assert.deepEqual(ids, [
    'forensics.filetype', 'forensics.hash', 'forensics.ioc', 'forensics.metadata', 'forensics.timeline', 'forensics.yara_lite',
  ]);
  for (const cap of manifest.capabilities) {
    assert.match(cap.id, /^forensics\.[a-z0-9_-]+$/);
    assert.equal(cap.riskLevel, 'L0');
    assert.equal(typeof cap.run, 'function');
    assert.ok(cap.params && cap.params.type === 'object');
    assert.equal(cap.params.additionalProperties, false);
    assert.ok(cap.title.length > 0 && cap.description.length > 20);
    assert.equal(cap.externalTools, undefined, 'forensics capabilities must be dependency-free');
  }
  assert.equal(RULES.length >= 10, true);
});

test('forensics.filetype: executable, archive, document, image, script and data detection', async () => {
  const cases = [
    [buildPeRich(), 'pe-executable', 'executable', 'application/vnd.microsoft.portable-executable'],
    [buildElfMinimal(), 'elf-executable', 'executable', 'application/x-executable'],
    [buildMachOMinimal(), 'mach-o', 'executable', 'application/x-mach-binary'],
    [buildZip([{ name: '[Content_Types].xml', data: '<Types/>' }, { name: 'word/document.xml', data: '<w:document/>' }]), 'docx', 'document'],
    [buildZip([{ name: 'META-INF/MANIFEST.MF', data: 'Manifest-Version: 1.0' }]), 'jar', 'package'],
    [buildPng(), 'png', 'image'],
    [buildJpeg(), 'jpeg', 'image'],
    [buildGzip(), 'gzip', 'archive'],
    [buildPdf(), 'pdf', 'document'],
    [buildOle2(), 'doc', 'document'],
    [Buffer.from('#!/bin/sh\necho hello\n', 'utf8'), 'script', 'script'],
    [Buffer.from('{"show": true, "count": 3}', 'utf8'), 'json', 'document'],
  ];
  for (const [buffer, type, category, mime] of cases) {
    const detected = detectFileType(buffer);
    assert.equal(detected.type, type, `buffer should be ${type}, got ${detected.type}`);
    assert.equal(detected.category, category);
    if (mime) assert.equal(detected.mime, mime);
  }
  const result = await runCap('forensics.filetype', inputFor(buildZip([{ name: 'a.txt', data: 'x' }])));
  assert.equal(result.data.type, 'zip');
  assert.equal(result.data.confidence, 'certain');
  assert.ok(result.data.details.entryCount === 1);
  assert.ok(Array.isArray(result.data.extensions) && result.data.extensions.includes('zip'));
  assert.match(result.summary, /文件类型/);

  const unknown = await runCap('forensics.filetype', inputFor(Buffer.from(Array.from({ length: 512 }, (_, i) => (i * 73 + 5) & 0xff))));
  assert.equal(unknown.data.type, 'data');
  assert.equal(unknown.data.confidence, 'low');
  assert.match(unknown.data.magic.hex, /^[0-9a-f]{16,64}$/);
});

test('forensics.hash: real digests, algorithm selection and truncation honesty', async () => {
  const abc = Buffer.from('abc', 'utf8');
  const all = await runCap('forensics.hash', inputFor(abc));
  assert.equal(all.data.digests.md5, '900150983cd24fb0d6963f7d28e17f72');
  assert.equal(all.data.digests.sha1, 'a9993e364706816aba3e25717850c26c9cd0d89d');
  assert.equal(all.data.digests.sha256, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(all.data.digests.sha512.length, 128);
  assert.equal(all.data.size, 3);
  assert.equal(all.data.truncated, null);

  const subset = await runCap('forensics.hash', inputFor(abc, { algorithms: ['sha256'] }));
  assert.deepEqual(subset.data.algorithms, ['sha256']);
  assert.equal(subset.data.digests.sha256, all.data.digests.sha256);
  assert.equal(subset.data.digests.md5, undefined);
  await assert.rejects(() => runCap('forensics.hash', inputFor(abc, { algorithms: ['crc32'] })), /不支持的哈希算法/);

  // Truncation: a 4-byte buffer from a 10-byte file must be flagged as truncated, not presented as full hash.
  const dir = mkdtempSync(join(tmpdir(), 'abm-forensics-'));
  try {
    const p = join(dir, 'sample.bin');
    writeFileSync(p, Buffer.from('0123456789', 'latin1'));
    const input = inputFor(Buffer.from('0123', 'latin1'));
    input.targetPath = p;
    const truncated = await runCap('forensics.hash', input);
    assert.equal(truncated.data.fileSize, 10);
    assert.equal(truncated.data.truncated, true);
    assert.equal(truncated.data.complete, false);
    assert.match(truncated.meta.warnings.join('\n'), /截断/);
    const fullInput = inputFor(Buffer.from('0123456789', 'latin1'));
    fullInput.targetPath = p;
    const full = await runCap('forensics.hash', fullInput);
    assert.equal(full.data.truncated, false);
    assert.equal(full.data.complete, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('forensics.metadata: PE timestamp, version resources, PDB path and resources', async () => {
  const pe = buildPeRich();
  const result = await runCap('forensics.metadata', inputFor(pe));
  assert.equal(result.data.format, 'pe');
  assert.equal(result.data.machine, 'x86-64');
  assert.equal(result.data.bits, 64);
  const expectedTime = new Date(PE_RICH_TIMESTAMP * 1000).toISOString().replace('.000Z', 'Z');
  assert.equal(result.data.compiledAt, expectedTime);
  assert.equal(result.data.compiledAtRaw, PE_RICH_TIMESTAMP);
  assert.equal(result.data.timestampZero, false);
  assert.equal(result.data.resources.present, true);
  assert.equal(result.data.resources.count, 1);
  assert.deepEqual(result.data.resources.types, [{ type: 'version', count: 1 }]);
  assert.equal(result.data.versionInfo.present, true);
  assert.equal(result.data.versionInfo.strings.CompanyName, 'Acme Security Labs');
  assert.equal(result.data.versionInfo.strings.FileDescription, 'Agent Updater');
  assert.equal(result.data.versionInfo.strings.OriginalFilename, 'agent.exe');
  assert.equal(result.data.versionInfo.fixedFileInfo.fileVersion, '1.2.3.4');
  assert.equal(result.data.versionInfo.fixedFileInfo.productVersion, '2.3.4.5');
  assert.equal(result.data.debug.length, 1);
  assert.equal(result.data.debug[0].pdbPath, 'D:\\build\\agent.pdb');
  assert.equal(result.data.debug[0].guid, '33221100-5544-7766-8899-aabbccddeeff');
  assert.ok(result.findings.some((f) => f.title.includes('PDB') && f.verification === 'observed'));
  assert.equal(result.data.sha256.length, 64);
  assert.match(result.summary, /PE 元数据/);
});

test('forensics.metadata: ELF, Mach-O, ZIP, PNG, JPEG, PDF, OLE2 and gzip', async () => {
  const elf = await runCap('forensics.metadata', inputFor(buildElfMinimal()));
  assert.equal(elf.data.format, 'elf');
  assert.equal(elf.data.machine, 'x86-64');
  assert.equal(elf.data.bits, 64);
  assert.equal(elf.data.type, 'executable');
  assert.deepEqual(elf.data.timestamps, []);
  assert.match(elf.data.note, /不包含.*时间戳/);

  const macho = await runCap('forensics.metadata', inputFor(buildMachOMinimal()));
  assert.equal(macho.data.format, 'macho');
  assert.equal(macho.data.slices.length, 1);
  assert.equal(macho.data.slices[0].arch, 'x86-64');
  assert.equal(macho.data.slices[0].bits, 64);
  assert.equal(macho.data.slices[0].fileType, 'execute');

  const zipBuffer = buildZip([
    { name: '[Content_Types].xml', data: '<Types/>' },
    { name: 'word/document.xml', data: '<w:document/>', extraMtime: 1617000000 },
  ]);
  const zip = await runCap('forensics.metadata', inputFor(zipBuffer));
  assert.equal(zip.data.format, 'zip');
  assert.equal(zip.data.subtype, 'docx');
  assert.equal(zip.data.entryCount, 2);
  assert.equal(zip.data.parsedEntries, 2);
  assert.equal(zip.data.zip64, false);
  assert.equal(zip.data.encryptedEntryCount, 0);
  assert.equal(zip.data.entries[0].name, '[Content_Types].xml');
  assert.equal(zip.data.totalUncompressed, Buffer.byteLength('<Types/>') + Buffer.byteLength('<w:document/>'));
  assert.equal(zip.data.entries[1].extraTimes.mtime, '2021-03-29T06:40:00Z');

  const png = await runCap('forensics.metadata', inputFor(buildPng()));
  assert.equal(png.data.format, 'png');
  assert.equal(png.data.width, 64);
  assert.equal(png.data.height, 32);
  assert.equal(png.data.bitDepth, 8);
  assert.equal(png.data.colorType, 'truecolor-alpha');
  assert.equal(png.data.text.Comment, 'armorbreak fixture');
  assert.equal(png.data.time.iso, '2022-07-08T09:10:11Z');

  const jpeg = await runCap('forensics.metadata', inputFor(buildJpeg()));
  assert.equal(jpeg.data.format, 'jpeg');
  assert.equal(jpeg.data.width, 320);
  assert.equal(jpeg.data.height, 200);
  assert.equal(jpeg.data.hasExif, true);
  assert.equal(jpeg.data.exif.fields.Make, 'AcmeCam');
  assert.equal(jpeg.data.exif.fields.DateTime, '2020:01:02 03:04:05');
  assert.equal(jpeg.data.exif.fields.DateTimeOriginal, '2020:01:02 03:04:06');

  const pdf = await runCap('forensics.metadata', inputFor(buildPdf()));
  assert.equal(pdf.data.format, 'pdf');
  assert.equal(pdf.data.version, '1.7');
  assert.equal(pdf.data.producer, 'Acme Writer 2.0');
  assert.equal(pdf.data.creationDate.iso, '2022-01-03T04:05:06Z');

  const ole = await runCap('forensics.metadata', inputFor(buildOle2()));
  assert.equal(ole.data.format, 'ole2');
  assert.equal(ole.data.majorVersion, 3);
  assert.ok(ole.data.streamHints.includes('WordDocument'));

  const gz = await runCap('forensics.metadata', inputFor(buildGzip()));
  assert.equal(gz.data.format, 'gzip');
  assert.equal(gz.data.originalName, 'note.txt');
  assert.equal(gz.data.mtime.iso, '2020-09-13T12:26:40Z');
});

test('forensics.timeline: PE, ZIP, PNG, JPEG events are real, sorted and deterministic', async () => {
  const pe = await runCap('forensics.timeline', inputFor(buildPeRich()));
  assert.equal(pe.data.format, 'pe');
  assert.equal(pe.data.eventCount, 2, JSON.stringify(pe.data.events));
  const peTime = new Date(PE_RICH_TIMESTAMP * 1000).toISOString().replace('.000Z', 'Z');
  assert.equal(pe.data.events[0].time, peTime);
  assert.equal(pe.data.events[0].source, 'pe.coff');
  assert.equal(pe.data.events[1].source, 'pe.debug-directory');
  assert.equal(pe.data.events[1].time, new Date(0x5f600000 * 1000).toISOString().replace('.000Z', 'Z'));
  assert.equal(pe.data.events[0].verification, 'observed');

  const zipBuffer = buildZip([
    { name: 'a.txt', data: 'aaa', extraMtime: 1617000000 },
    { name: 'b.txt', data: 'bb' },
  ]);
  const zip = await runCap('forensics.timeline', inputFor(zipBuffer));
  assert.equal(zip.data.format, 'zip');
  assert.equal(zip.data.eventCount, 3, JSON.stringify(zip.data.events));
  const times = zip.data.events.map((e) => e.time);
  assert.deepEqual([...times].sort(), times, 'timeline must be sorted ascending');
  assert.ok(times.includes('2021-03-04T05:06:08'));
  assert.ok(times.includes('2021-03-29T06:40:00Z'));
  assert.ok(zip.data.countsBySource['zip.extra-field'] >= 1);

  const png = await runCap('forensics.timeline', inputFor(buildPng()));
  assert.equal(png.data.eventCount, 1);
  assert.equal(png.data.events[0].time, '2022-07-08T09:10:11Z');
  assert.equal(png.data.events[0].source, 'png.time-chunk');

  const jpeg = await runCap('forensics.timeline', inputFor(buildJpeg()));
  assert.equal(jpeg.data.format, 'jpeg');
  assert.equal(jpeg.data.eventCount, 2, JSON.stringify(jpeg.data.events));
  assert.ok(jpeg.data.events.every((e) => e.timezone === 'local-unassigned'));

  const elf = await runCap('forensics.timeline', inputFor(buildElfMinimal()));
  assert.equal(elf.data.format, 'elf');
  assert.equal(elf.data.eventCount, 0);
  assert.match(elf.data.notes.join(';'), /不含时间戳/);

  const first = await runCap('forensics.timeline', inputFor(zipBuffer));
  const second = await runCap('forensics.timeline', inputFor(zipBuffer));
  assert.equal(JSON.stringify(first), JSON.stringify(second));
});

test('forensics.ioc: real indicator extraction, dedupe, flags and category filters', async () => {
  const text = [
    'GET http://c2.example.com:8080/gate.php?id=1 HTTP/1.1',
    'backup http://c2.example.com:8080/gate.php?id=1 again',
    'contact admin@corp.example.org or analyst@example.net',
    'beacon 198.51.100.7 and internal 192.168.1.10 and 10.0.0.5',
    'ipv6 2001:db8::1 and fe80::1',
    'md5 d41d8cd98f00b204e9800998ecf8427e',
    'sha1 da39a3ee5e6b4b0d3255bfef95601890afd80709',
    'sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater',
    'C:\\Users\\Public\\payload.exe and /tmp/dropper.sh',
    'wide.example.net',
  ].join('\n');
  const buffer = Buffer.concat([
    Buffer.from(text, 'latin1'),
    Buffer.from('wide-marker.example.net', 'utf16le'),
  ]);
  const result = await runCap('forensics.ioc', inputFor(buffer, { categories: undefined }));
  const c = result.data.counts;
  assert.equal(c.url.unique, 1, 'duplicate URL must be deduped');
  assert.equal(c.url.occurrences, 2);
  assert.equal(c.domain.unique >= 3, true, JSON.stringify(c.domain));
  assert.equal(c.email.unique, 2);
  assert.equal(c.ipv4.unique, 3);
  assert.equal(c.ipv4.occurrences, 3);
  assert.equal(c.md5.unique, 1);
  assert.equal(c.sha1.unique, 1);
  assert.equal(c.sha256.unique, 1);
  assert.equal(c.registryKey.unique, 1);
  assert.equal(c.registryKey.occurrences, 1);
  assert.equal(c.windowsPath.unique, 1);
  assert.equal(c.unixPath.unique, 1);
  assert.ok(c.ipv6.unique >= 1);
  const privateIp = result.data.iocs.ipv4.find((i) => i.value === '192.168.1.10');
  assert.ok(privateIp && privateIp.flags.private === true);
  const c2Url = result.data.iocs.url[0];
  assert.equal(c2Url.value, 'http://c2.example.com:8080/gate.php?id=1');
  assert.equal(c2Url.count, 2);
  const domainValues = result.data.iocs.domain.map((i) => i.value);
  assert.ok(domainValues.includes('c2.example.com'));
  assert.ok(domainValues.includes('wide-marker.example.net'), 'UTF-16LE indicators must be extracted');
  const runKey = result.data.iocs.registryKey[0];
  assert.equal(runKey.flags.hive, 'HKLM');
  assert.equal(runKey.flags.autorun, true);
  assert.ok(result.findings.some((f) => f.verification === 'hypothesis' && f.title.includes('自启动')));

  const filtered = await runCap('forensics.ioc', inputFor(buffer, { includePrivateIps: false }));
  assert.equal(filtered.data.iocs.ipv4.some((i) => i.value === '192.168.1.10'), false);
  assert.ok(filtered.data.iocs.ipv4.some((i) => i.value === '198.51.100.7'));

  const onlyHashes = await runCap('forensics.ioc', inputFor(buffer, { categories: ['md5', 'sha256'] }));
  assert.equal(onlyHashes.data.iocs.url.length, 0);
  assert.equal(onlyHashes.data.iocs.md5.length, 1);
  assert.equal(onlyHashes.data.iocs.sha256.length, 1);
  assert.equal(onlyHashes.data.totals.unique, 2);
});

test('forensics.yara_lite: bundled rules, wide-string matching, filters and honest verification', async () => {
  const upx = Buffer.from('UPX0\u0000UPX1\u0000UPX!\u0000some code here', 'latin1');
  const upxResult = await runCap('forensics.yara_lite', inputFor(upx));
  assert.ok(upxResult.data.matchedRules.some((r) => r.ruleId === 'upx-packer'), JSON.stringify(upxResult.data.matchedRules.map((r) => r.ruleId)));
  assert.equal(upxResult.data.matchedRules[0].verification, 'hypothesis');
  const upxFinding = upxResult.findings.find((f) => f.title.includes('UPX'));
  assert.ok(upxFinding);
  assert.equal(upxFinding.verification, 'hypothesis');
  assert.ok(upxFinding.evidence[0].excerpt.length > 0);

  const ps = Buffer.from('powershell.exe -EncodedCommand AAAA && Invoke-Expression (DownloadString) ', 'latin1');
  const psResult = await runCap('forensics.yara_lite', inputFor(ps));
  assert.ok(psResult.data.matchedRules.some((r) => r.ruleId === 'powershell-execution'));
  assert.equal(psResult.findings[0].severity, 'high');

  const clean = Buffer.from('hello world, nothing suspicious here at all', 'latin1');
  const cleanResult = await runCap('forensics.yara_lite', inputFor(clean));
  assert.equal(cleanResult.data.matchedCount, 0);
  assert.equal(cleanResult.findings.length, 0);
  assert.match(cleanResult.summary, /未命中/);

  // UTF-16LE-only rule strings must count as hits
  const wide = Buffer.from('UPX0UPX1', 'utf16le');
  const wideResult = await runCap('forensics.yara_lite', inputFor(wide, { ruleIds: ['upx-packer'] }));
  assert.equal(wideResult.data.matchedCount, 1);
  assert.equal(wideResult.data.matchedRules[0].matchedStrings[0].matchedEncoding, 'utf16le');

  const filterResult = await runCap('forensics.yara_lite', inputFor(Buffer.concat([upx, ps]), { ruleIds: ['upx-packer'] }));
  assert.equal(filterResult.data.matchedRules.length, 1);
  assert.equal(filterResult.data.ruleset.selectedRuleCount, 1);
  await assert.rejects(() => runCap('forensics.yara_lite', inputFor(upx, { ruleIds: ['no-such-rule'] })), /ruleIds/);

  const a = await runCap('forensics.yara_lite', inputFor(Buffer.concat([upx, ps])));
  const b = await runCap('forensics.yara_lite', inputFor(Buffer.concat([upx, ps])));
  assert.equal(JSON.stringify(a), JSON.stringify(b));
});

test('forensics: malformed/truncated inputs return structured results without crashes', async () => {
  const truncatedZip = buildZip([{ name: 'a.txt', data: 'hello' }]).subarray(0, 20);
  const zipResult = await runCap('forensics.metadata', inputFor(truncatedZip));
  assert.equal(zipResult.data.format, 'zip');
  assert.ok(Array.isArray(zipResult.data.warnings));

  const corruptPe = buildPeRich();
  corruptPe.writeUInt16LE(0xffff, 0x86);
  const peResult = await runCap('forensics.metadata', inputFor(corruptPe));
  assert.ok(['pe', 'data'].includes(peResult.data.format));
  assert.ok(typeof peResult.summary === 'string');

  const bogusJpeg = Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe1, 0xff, 0xff]), Buffer.from('garbage')]);
  const jpegResult = await runCap('forensics.metadata', inputFor(bogusJpeg));
  assert.equal(jpegResult.data.format, 'jpeg');
  assert.equal(jpegResult.data.hasExif, false);

  const truncatedPng = buildPng().subarray(0, 30);
  const png = parsePng(truncatedPng);
  assert.equal(png.truncated, true);
  const pngResult = await runCap('forensics.metadata', inputFor(truncatedPng));
  assert.equal(pngResult.data.format, 'png');
  assert.equal(pngResult.data.width, null);
  assert.equal(pngResult.data.truncated, true);

  const zipLocalOnly = buildZip([{ name: 'a.txt', data: 'hello' }]).subarray(0, 9);
  const parsed = parseZip(zipLocalOnly);
  assert.equal(parsed.ok, false);

  const pngChunks = parsePng(buildPng());
  assert.equal(pngChunks.chunks[0].type, 'IHDR');
  const jpegSegments = parseJpeg(buildJpeg());
  assert.equal(jpegSegments.segments[0].marker, 'APP1');
});

test('forensics: empty inputs throw actionable Errors for every capability', async () => {
  for (const cap of manifest.capabilities) {
    await assert.rejects(
      () => cap.run(inputFor(Buffer.alloc(0))),
      (err) => {
        assert.ok(err instanceof Error);
        assert.match(err.message, /0 字节|缺少可分析字节/);
        assert.match(err.message, /targetPath/);
        return true;
      },
      `${cap.id} should reject empty input with actionable error`,
    );
  }
});

test('forensics: every capability honors AbortSignal and is deterministic on fixtures', async () => {
  const controller = new AbortController();
  controller.abort();
  const samples = [
    buildPeRich(), buildZip([{ name: 'a.txt', data: 'hello' }]), buildPng(), buildJpeg(),
    Buffer.from('http://x.example.com 1.2.3.4 UPX0 UPX1', 'latin1'),
  ];
  for (const cap of manifest.capabilities) {
    for (const sample of samples.slice(0, 3)) {
      await assert.rejects(
        () => cap.run(inputFor(sample, {}, {}, { signal: controller.signal })),
        /中止/,
        `${cap.id} must honor abort`,
      );
    }
  }
  // Deterministic across repeated calls for all capabilities on a mixed sample.
  const sample = Buffer.concat([buildZip([{ name: 'a.txt', data: 'http://c2.example.net/x' }])]);
  for (const cap of manifest.capabilities) {
    const first = await cap.run(inputFor(sample));
    const second = await cap.run(inputFor(sample));
    assert.equal(JSON.stringify(first), JSON.stringify(second), `${cap.id} must be deterministic`);
  }
});

test('forensics: result data is JSON-serializable and bounded for all capabilities', async () => {
  const fixtures = [buildPeRich(), buildZip([{ name: 'word/document.xml', data: 'x'.repeat(1000) }]), buildJpeg(), buildPng()];
  for (const buffer of fixtures) {
    for (const cap of manifest.capabilities) {
      const result = await cap.run(inputFor(buffer));
      const json = JSON.stringify(result.data);
      assert.ok(json.length < 256 * 1024, `${cap.id} data too large: ${json.length}`);
      assert.equal(typeof result.summary, 'string');
      assert.ok(result.summary.length > 0 && result.summary.length <= 4000);
      assert.ok(Array.isArray(result.findings));
      for (const f of result.findings) {
        assert.ok(['critical', 'high', 'medium', 'low', 'info'].includes(f.severity));
        assert.ok(['observed', 'corroborated', 'hypothesis', 'unverified'].includes(f.verification));
        assert.ok(typeof f.title === 'string' && f.title.length > 0);
        assert.ok(typeof f.method === 'string' && f.method.length > 0);
        assert.ok(typeof f.remediation === 'string' && f.remediation.length > 0);
        assert.equal(f.cvss, null);
        assert.ok(Array.isArray(f.evidence));
        for (const e of f.evidence) {
          assert.ok(typeof e.title === 'string');
          assert.ok(typeof e.excerpt === 'string');
          assert.ok(e.excerpt.length <= 2000);
          assert.doesNotMatch(e.excerpt, /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/);
        }
      }
    }
  }
});
