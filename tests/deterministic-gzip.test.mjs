import assert from 'node:assert/strict'
import { gunzipSync } from 'node:zlib'
import test from 'node:test'

import { deterministicGzip } from '../scripts/v2/deterministic-gzip.mjs'

test('deterministic gzip uses a stable header and round-trips empty and ordinary input', () => {
  for (const input of [Buffer.alloc(0), Buffer.from('ArmorBreak deterministic artifact\n')]) {
    const first = deterministicGzip(input)
    const second = deterministicGzip(input)
    assert.deepEqual(first, second)
    assert.equal(first.readUInt32LE(4), 0)
    assert.equal(first[9], 0xff)
    assert.deepEqual(gunzipSync(first), input)
  }
})

test('deterministic gzip splits large payloads at the DEFLATE stored-block limit', () => {
  const input = Buffer.alloc(0x10000)
  for (let index = 0; index < input.length; index += 1) input[index] = index & 0xff

  const compressed = deterministicGzip(input)
  assert.equal(compressed[10], 0x00)
  assert.equal(compressed.readUInt16LE(11), 0xffff)
  assert.equal(compressed[10 + 5 + 0xffff], 0x01)
  assert.deepEqual(gunzipSync(compressed), input)
})
