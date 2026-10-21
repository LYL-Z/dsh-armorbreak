#!/usr/bin/env node
/** Build the V2 core pack lockfile. Usage: node scripts/v2/build-core-pack.mjs [--out path] */
import { writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { buildCorePack } from '../../lib/pack/corePack.js'

const outIndex = process.argv.indexOf('--out')
const out = outIndex >= 0 ? process.argv[outIndex + 1] : join(process.cwd(), 'docs/v2/core-pack.lock.json')
const lock = await buildCorePack({ root: process.cwd() })
await writeFile(out, `${JSON.stringify(lock, null, 2)}\n`)
console.log(JSON.stringify({ out, fileCount: lock.fileCount, totalBytes: lock.totalBytes, aggregateSha256: lock.aggregateSha256 }, null, 2))
