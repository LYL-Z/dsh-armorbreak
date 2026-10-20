// ArmorBreak CTF domain tests — synthetic payloads only, real field assertions.
import test from 'node:test';
import assert from 'node:assert/strict';
import { gzipSync } from 'node:zlib';

import ctfManifest from '../lib/analyzers/ctf/manifest.js';
import { applyTransform, decodeChain, TRANSFORM_NAMES } from '../lib/analyzers/ctf/encoding.js';
import { detectBufferMagic } from '../lib/analyzers/ctf/filetype.js';
import { identifyHashToken } from '../lib/analyzers/ctf/hash_id.js';

const CAPS = new Map(ctfManifest.capabilities.map((capability) => [capability.id, capability]));

function defaults(overrides = {}) {
  return {
    targetPath: null,
    buffer: null,
    text: null,
    options: {},
    limits: { maxBytes: 1024 * 1024, maxFindings: 100, maxItems: 200 },
    env: { signal: { aborted: false }, nowIso: '2026-10-20T00:00:00.000Z', log: () => {} },
    ...overrides,
  };
}

async function runCapability(id, overrides = {}) {
  const capability = CAPS.get(id);
  assert.ok(capability, `capability ${id} must exist`);
  return capability.run(defaults(overrides));
}

function assertFindingShape(finding) {
  assert.equal(typeof finding.title, 'string');
  assert.ok(['critical', 'high', 'medium', 'low', 'info'].includes(finding.severity));
  assert.ok(['observed', 'corroborated', 'hypothesis', 'unverified'].includes(finding.verification));
  assert.ok(finding.cwe === null || /^CWE-\d+$/.test(finding.cwe));
  assert.ok(Array.isArray(finding.evidence));
}

function shiftLetters(text, shift) {
  return text.replace(/[a-zA-Z]/g, (ch) => {
    const base = ch <= 'Z' ? 65 : 97;
    return String.fromCharCode(base + ((ch.charCodeAt(0) - base + shift) % 26));
  });
}

test('ctf manifest shape: 5 offline capabilities with closed params schemas', () => {
  assert.equal(ctfManifest.domain, 'ctf');
  assert.deepEqual(
    ctfManifest.capabilities.map((capability) => capability.id),
    ['ctf.classify', 'ctf.decode', 'ctf.hash_id', 'ctf.crypto_basics', 'ctf.flag_scan'],
  );
  for (const capability of ctfManifest.capabilities) {
    assert.equal(capability.riskLevel, 'L0');
    assert.ok(capability.title.length > 0);
    assert.ok(capability.description.length > 20);
    assert.equal(capability.params.type, 'object');
    assert.equal(capability.params.additionalProperties, false);
    assert.equal(typeof capability.run, 'function');
  }
  assert.deepEqual(
    [...TRANSFORM_NAMES].sort(),
    ['base32', 'base64', 'base64url', 'binary', 'gzip', 'hex', 'inflate-raw', 'morse', 'rot13', 'url', 'utf16le', 'zlib'],
  );
});

test('ctf.decode: base64→gzip chain, intermediates, flag detection and artifact', async () => {
  const payload = Buffer.from('flag{chain_ok}', 'utf8');
  const encoded = gzipSync(payload).toString('base64');
  const result = await runCapability('ctf.decode', {
    text: encoded,
    options: { transforms: ['base64', 'gzip'] },
  });
  assert.equal(result.data.transforms.length, 2);
  assert.equal(result.data.steps.length, 2);
  assert.equal(result.data.steps[0].ok, true);
  assert.equal(result.data.steps[0].transform, 'base64');
  assert.equal(result.data.steps[1].transform, 'gzip');
  assert.equal(result.data.steps[1].printable, true);
  assert.equal(result.data.final.preview, 'flag{chain_ok}');
  assert.equal(result.artifacts.length, 1);
  assert.equal(result.artifacts[0].name, 'decoded.txt');
  assert.equal(result.artifacts[0].content, 'flag{chain_ok}');
  assert.ok(result.data.final.flags.includes('flag{chain_ok}'));
  assert.ok(result.findings.some((finding) => finding.title.includes('[ctf-flag]')));
  result.findings.forEach(assertFindingShape);
});

test('ctf.decode: all supported textual transforms behave correctly', async () => {
  const cases = [
    { transform: 'hex', input: Buffer.from('flag{hex}', 'utf8').toString('hex'), expected: 'flag{hex}' },
    { transform: 'base32', input: 'MZXW6YTBOI======', expected: 'foobar' },
    { transform: 'binary', input: '01001000 01101001', expected: 'Hi' },
    { transform: 'morse', input: '.... . .-.. .-.. --- / .-- --- .-. .-.. -..', expected: 'HELLO WORLD' },
    { transform: 'url', input: 'flag%7Burl%7D', expected: 'flag{url}' },
    { transform: 'rot13', input: 'synt{ebg13}', expected: 'flag{rot13}' },
    { transform: 'base64url', input: Buffer.from('flag{urlsafe}', 'utf8').toString('base64url'), expected: 'flag{urlsafe}' },
    {
      transform: 'utf16le',
      input: Buffer.from('flag{utf16}', 'utf16le').toString('hex'),
      transforms: ['hex', 'utf16le'],
      expected: 'flag{utf16}',
    },
    {
      transform: 'zlib',
      input: (await import('node:zlib')).deflateSync(Buffer.from('flag{zlib}', 'utf8')).toString('base64'),
      transforms: ['base64', 'zlib'],
      expected: 'flag{zlib}',
    },
    {
      transform: 'inflate-raw',
      input: (await import('node:zlib')).deflateRawSync(Buffer.from('flag{raw}', 'utf8')).toString('base64'),
      transforms: ['base64', 'inflate-raw'],
      expected: 'flag{raw}',
    },
  ];
  for (const entry of cases) {
    const result = await runCapability('ctf.decode', {
      text: entry.input,
      options: { transforms: entry.transforms ?? [entry.transform] },
    });
    assert.equal(
      result.data.final.preview,
      entry.expected,
      `transform ${entry.transform} should decode to ${entry.expected}`,
    );
    assert.equal(result.data.steps.every((step) => step.ok), true);
  }

  // Direct helper: binary transform state machine.
  const state = applyTransform('hex', { bytes: Buffer.from(Buffer.from('A').toString('hex')) });
  assert.deepEqual([...state.bytes], [0x41]);
});

test('ctf.decode: unknown/invalid chains fail with actionable errors, not crashes', async () => {
  await assert.rejects(
    () => runCapability('ctf.decode', { text: 'abc', options: { transforms: ['nope'] } }),
    /未知变换/,
  );
  await assert.rejects(
    () => runCapability('ctf.decode', { text: 'abc', options: {} }),
    /未指定 transforms|未指定变换链/,
  );
  const failure = await runCapability('ctf.decode', {
    text: 'not-base64!!!',
    options: { transforms: ['base64'] },
  });
  assert.equal(failure.data.steps[0].ok, false);
  assert.match(failure.data.steps[0].error, /Base64 解码失败/);
  assert.equal(failure.data.usedTransforms.length, 0);
  const truncatedChain = decodeChain(Buffer.from('aGk='), ['base64', 'hex'], { maxDepth: 1 });
  assert.equal(truncatedChain.truncated, true);
  assert.deepEqual(truncatedChain.usedTransforms, ['base64']);
  assert.equal(truncatedChain.finalBytes.toString(), 'hi');
});

test('ctf.classify: identifies base64 chain + flags, gzip/PNG/TAR magic', async () => {
  const base64Flag = Buffer.from('flag{test_flag_value}', 'utf8').toString('base64');
  const classified = await runCapability('ctf.classify', { text: base64Flag });
  assert.equal(classified.data.textEncodings[0].encoding, 'base64');
  assert.equal(classified.data.chain.length, 1);
  assert.equal(classified.data.chain[0].encoding, 'base64');
  assert.equal(classified.data.final.printable, true);
  assert.ok(classified.data.flags.some((flag) => flag.flag === 'flag{test_flag_value}'));
  assert.ok(classified.findings.some((finding) => finding.title.includes('[ctf-flag]')));
  resultShape(classified);

  const gzipBytes = gzipSync(Buffer.from('flag{gzip_layer}', 'utf8'));
  const gzipClassified = await runCapability('ctf.classify', { buffer: gzipBytes });
  assert.equal(gzipClassified.data.magic[0].kind, 'gzip');
  assert.equal(gzipClassified.data.chain[0].encoding, 'gzip');
  assert.ok(gzipClassified.data.flags.some((flag) => flag.flag === 'flag{gzip_layer}'));
  assert.equal(gzipClassified.data.isText, false);

  const png = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.alloc(64)]);
  const pngClassified = await runCapability('ctf.classify', { buffer: png });
  assert.equal(pngClassified.data.magic[0].kind, 'png');
  assert.equal(pngClassified.data.magic[0].mime, 'image/png');

  const tar = Buffer.alloc(512);
  tar.write('ustar', 257, 'latin1');
  tar.write('test.txt', 0, 'latin1');
  assert.equal(detectBufferMagic(tar).some((entry) => entry.kind === 'tar'), true);

  const highEntropy = Buffer.from(Array.from({ length: 256 }, (_, index) => (index * 73 + 41) % 256));
  const unknown = await runCapability('ctf.classify', { buffer: highEntropy });
  assert.equal(unknown.data.magic.length, 0);
  assert.ok(unknown.findings.some((finding) => finding.title.includes('[ctf-high-entropy]')));
  assert.equal(unknown.findings.every((finding) => finding.severity === 'info'), true);

  await assert.rejects(() => runCapability('ctf.classify', {}), /输入为空/);
});

function resultShape(result) {
  result.findings.forEach(assertFindingShape);
  assert.ok(['critical', 'high', 'medium', 'low', 'info'].includes(result.findings[0]?.severity ?? 'info'));
}

test('ctf.hash_id: length/charset/prefix identification with explicit ambiguity', async () => {
  const md5 = identifyHashToken('d41d8cd98f00b204e9800998ecf8427e');
  assert.equal(md5.charset, 'hex');
  assert.equal(md5.length, 32);
  assert.ok(md5.candidates.some((candidate) => candidate.algorithm === 'md5' && candidate.confidence === 'likely'));
  assert.ok(md5.candidates.some((candidate) => candidate.algorithm === 'ntlm'), 'ambiguity surfaced');

  const sha1 = identifyHashToken('da39a3ee5e6b4b0d3255bfef95601890afd80709');
  assert.ok(sha1.candidates.some((candidate) => candidate.algorithm === 'sha1' && candidate.confidence === 'likely'));
  const sha256 = identifyHashToken('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  assert.ok(sha256.candidates.some((candidate) => candidate.algorithm === 'sha256'));
  const bcrypt = identifyHashToken(`$2b$12$${'K'.repeat(53)}`);
  assert.equal(bcrypt.length, 60);
  assert.ok(bcrypt.candidates.some((candidate) => candidate.algorithm === 'bcrypt'));
  const uuid = identifyHashToken('123e4567-e89b-12d3-a456-426614174000');
  assert.equal(uuid.charset, 'uuid');
  assert.ok(uuid.candidates.some((candidate) => candidate.algorithm === 'uuid'));
  const jwt = identifyHashToken('eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnopqrstuvwxyz123456');
  assert.ok(jwt.candidates.some((candidate) => candidate.algorithm === 'jwt'));

  const multi = await runCapability('ctf.hash_id', {
    text: 'd41d8cd98f00b204e9800998ecf8427e\n5d41402abc4b2a76b9719d911017c592\n',
  });
  assert.equal(multi.data.hashCount, 2);
  assert.equal(multi.data.hashes[0].candidates[0].algorithm, 'md5');
  assert.ok(multi.findings.some((finding) => finding.title.includes('[ctf-hash-id]')));
  assert.equal(multi.findings[0].verification, 'hypothesis');
  assert.match(multi.data.disclaimer, /不代表已破解/);

  await assert.rejects(() => runCapability('ctf.hash_id', {}), /输入为空/);
});

test('ctf.crypto_basics: Caesar brute force finds the right rotation, honest labels', async () => {
  const plain = 'The quick brown fox jumps over the lazy dog and then keeps running through the forest';
  const cipher = shiftLetters(plain, 3);
  const result = await runCapability('ctf.crypto_basics', { text: cipher });
  assert.equal(result.data.caesar.bestShift, 23);
  assert.equal(result.data.caesar.candidates[0].shift, 23);
  assert.equal(result.data.frequency.length, 26);
  assert.ok(result.data.indexOfCoincidence.value > 0 && result.data.indexOfCoincidence.value < 0.2);
  const caesarFinding = result.findings.find((finding) => finding.title.includes('[ctf-caesar]'));
  assert.ok(caesarFinding);
  assert.equal(caesarFinding.verification, 'hypothesis');
  assert.match(result.data.disclaimer, /启发式/);
  result.findings.forEach(assertFindingShape);

  const again = await runCapability('ctf.crypto_basics', { text: cipher });
  assert.deepEqual(result.data, again.data);
});

test('ctf.crypto_basics: single-byte XOR brute force recovers hex key 0x42', async () => {
  const plain = Buffer.from('flag{xor_single_byte_is_easy_enough}', 'utf8');
  const key = 0x42;
  const cipherHex = Buffer.from(plain.map((byte) => byte ^ key)).toString('hex');
  const result = await runCapability('ctf.crypto_basics', {
    text: cipherHex,
    options: { encoding: 'hex' },
  });
  assert.equal(result.data.ciphertextEncoding, 'hex');
  assert.equal(result.data.xor.bestKey, 0x42);
  assert.equal(result.data.xor.bestKeyHex, '0x42');
  assert.ok(result.data.xor.candidates[0].preview.includes('flag{'));
  assert.equal(result.data.xor.candidates[0].printable, 1);
  const xorFinding = result.findings.find((finding) => finding.title.includes('[ctf-xor]'));
  assert.ok(xorFinding);
  assert.equal(xorFinding.verification, 'hypothesis');

  await assert.rejects(() => runCapability('ctf.crypto_basics', {}), /输入为空/);
});

test('ctf.flag_scan: finds known flag formats and entropy anomalies in text and binaries', async () => {
  const text = 'prefix picoCTF{abc_123} middle flag_underscore_value suffix';
  const result = await runCapability('ctf.flag_scan', { text });
  const flags = result.data.flags.map((flag) => flag.flag);
  assert.ok(flags.includes('picoCTF{abc_123}'));
  assert.ok(flags.includes('flag_underscore_value'));
  assert.ok(result.data.patternsTested.includes('picoctf'));
  assert.ok(result.findings.some((finding) => finding.title.includes('[ctf-flag]')));
  assert.equal(result.findings[0].verification, 'observed');
  assert.equal(result.data.scannedBytes, Buffer.byteLength(text));

  const highEntropyToken = 'QWxhZGRpbjpvcGVuIHNlc2FtZV9hbmRfaGlnaF9lbnRyb3B5MzQ1Njc4OTA=';
  const entropyResult = await runCapability('ctf.flag_scan', {
    text: `token candidate: ${highEntropyToken}`,
  });
  assert.ok(entropyResult.data.entropyCandidates.length >= 1);
  assert.ok(entropyResult.data.entropyCandidates[0].entropy >= 3.6);
  assert.ok(entropyResult.findings.some((finding) => finding.title.includes('[ctf-entropy]')));

  const binary = Buffer.concat([
    Buffer.from([0x00, 0xff, 0x10]),
    Buffer.from('hidden flag{binary_scan} here', 'utf8'),
    Buffer.from([0x00]),
  ]);
  const binaryResult = await runCapability('ctf.flag_scan', { buffer: binary });
  assert.ok(binaryResult.data.flags.some((flag) => flag.flag === 'flag{binary_scan}'));
  assert.equal(binaryResult.data.scannedBytes, binary.length);

  await assert.rejects(() => runCapability('ctf.flag_scan', {}), /输入为空/);
});

test('ctf.classify/report determinism: identical input yields identical structured data', async () => {
  const input = Buffer.from('flag{deterministic_check}', 'utf8').toString('base64');
  const first = await runCapability('ctf.classify', { text: input });
  const second = await runCapability('ctf.classify', { text: input });
  assert.deepEqual(first.data, second.data);
  assert.deepEqual(
    first.findings.map((finding) => finding.title),
    second.findings.map((finding) => finding.title),
  );
});
