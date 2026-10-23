const CRC32_TABLE = Uint32Array.from({ length: 256 }, (_, value) => {
  let current = value
  for (let bit = 0; bit < 8; bit += 1) current = (current & 1) ? (0xedb88320 ^ (current >>> 1)) : (current >>> 1)
  return current >>> 0
})

function crc32(bytes) {
  let value = 0xffffffff
  for (const byte of bytes) value = CRC32_TABLE[(value ^ byte) & 0xff] ^ (value >>> 8)
  return (value ^ 0xffffffff) >>> 0
}

/**
 * Encode a single-member gzip stream using stored DEFLATE blocks. The stream
 * intentionally trades compression ratio for byte-for-byte output that does
 * not depend on the host zlib version or platform.
 */
export function deterministicGzip(input) {
  const bytes = Buffer.isBuffer(input) ? input : Buffer.from(input)
  const chunks = [Buffer.from([0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0, 0xff])]
  const blockCount = Math.max(1, Math.ceil(bytes.length / 0xffff))

  for (let index = 0; index < blockCount; index += 1) {
    const start = index * 0xffff
    const end = Math.min(start + 0xffff, bytes.length)
    const length = end - start
    const blockHeader = Buffer.alloc(5)
    blockHeader[0] = index === blockCount - 1 ? 0x01 : 0x00 // BFINAL; BTYPE=00 (stored)
    blockHeader.writeUInt16LE(length, 1)
    blockHeader.writeUInt16LE(~length & 0xffff, 3)
    chunks.push(blockHeader, bytes.subarray(start, end))
  }

  const trailer = Buffer.alloc(8)
  trailer.writeUInt32LE(crc32(bytes), 0)
  trailer.writeUInt32LE(bytes.length >>> 0, 4)
  chunks.push(trailer)
  return Buffer.concat(chunks)
}
