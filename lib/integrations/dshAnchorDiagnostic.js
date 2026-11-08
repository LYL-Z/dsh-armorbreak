/** Read-only, literal-only anchor drift diagnostics for an explicit host file. */
import { open, lstat } from 'node:fs/promises'
import { constants } from 'node:fs'
import { isAbsolute, parse, resolve, sep } from 'node:path'

const MAX_TARGET = 4 * 1024 * 1024
const MAX_SPEC = 64 * 1024
const MAX_ANCHORS = 64
const ANCHOR_ID = /^[a-zA-Z][a-zA-Z0-9._-]{0,63}$/

async function checkPath(path) {
  if (typeof path !== 'string' || !isAbsolute(path)) throw new Error('expected absolute file path')
  const absolute = resolve(path)
  const root = parse(absolute).root
  let current = root
  for (const component of absolute.slice(root.length).split(sep).filter(Boolean)) {
    current = resolve(current, component)
    const info = await lstat(current)
    if (info.isSymbolicLink()) throw new Error('symlinked file or parent is not accepted')
  }
  return absolute
}

async function loadRegularFile(path, limit) {
  const safePath = await checkPath(path)
  let handle
  try {
    handle = await open(safePath, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0))
    const stat = await handle.stat()
    if (!stat.isFile()) throw new Error('input is not a regular file')
    if (stat.size > limit) throw new Error('input exceeds inspection byte limit')
    const content = await handle.readFile()
    if (content.length > limit) throw new Error('input grew beyond inspection byte limit')
    if (content.includes(0)) throw new Error('binary input is not supported')
    return content.toString('utf8')
  } finally {
    await handle?.close()
  }
}

function validateSpecification(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || value.schemaVersion !== 'armorbreak.anchor-spec/v1') {
    throw new Error('invalid anchor specification schema')
  }
  if (!Array.isArray(value.anchors) || value.anchors.length < 1 || value.anchors.length > MAX_ANCHORS) {
    throw new Error('anchor specification requires 1–64 anchors')
  }
  const names = new Set()
  return value.anchors.map((anchor) => {
    if (!anchor || typeof anchor !== 'object' || !ANCHOR_ID.test(anchor.id)) throw new Error('invalid anchor identifier')
    if (names.has(anchor.id)) throw new Error('duplicate anchor identifier')
    names.add(anchor.id)
    if (typeof anchor.literal !== 'string' || anchor.literal.length < 3 || anchor.literal.length > 1024 || anchor.literal.includes('\0')) {
      throw new Error('anchor literal length/content is invalid')
    }
    const expected = anchor.expectedCount ?? 1
    if (!Number.isSafeInteger(expected) || expected < 1 || expected > 32) throw new Error('invalid expectedCount')
    return { id: anchor.id, literal: anchor.literal, expectedCount: expected }
  })
}

function countOccurrences(text, literal, stopAt) {
  let count = 0
  let start = 0
  while (count < stopAt) {
    const index = text.indexOf(literal, start)
    if (index < 0) break
    count += 1
    start = index + literal.length
  }
  return count
}

/**
 * Reports bounded counts only, never host source text, anchor literals or
 * surrounding snippets. A PASS means counts match, not that a patch is safe.
 */
export async function diagnoseDshAnchors({ targetFile, specFile } = {}) {
  let specification
  try {
    specification = JSON.parse(await loadRegularFile(specFile, MAX_SPEC))
  } catch (error) {
    if (error instanceof SyntaxError) throw new Error('invalid anchor specification JSON')
    throw error
  }
  const anchors = validateSpecification(specification)
  const content = await loadRegularFile(targetFile, MAX_TARGET)
  const results = anchors.map(({ id, literal, expectedCount }) => {
    const found = countOccurrences(content, literal, expectedCount + 1)
    const status = found === expectedCount ? 'MATCH' : found === 0 ? 'MISSING' : found > expectedCount ? 'AMBIGUOUS' : 'COUNT_MISMATCH'
    return { id, status, found, expectedCount, countCapped: found > expectedCount }
  })
  return {
    schemaVersion: 'armorbreak.dsh-anchor-diagnostic/v1', mode: 'READ_ONLY',
    targetFile: resolve(targetFile),
    status: results.every((result) => result.status === 'MATCH') ? 'MATCHES_EXPECTATIONS' : 'REVIEW_REQUIRED',
    anchors: results,
    note: 'Textual anchor counts do not prove running host compatibility or authorize patching.',
  }
}
