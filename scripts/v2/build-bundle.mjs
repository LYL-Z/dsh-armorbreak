#!/usr/bin/env node
/** Build the DSH bundle lockfile from the current repository. */
import { writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { compileBundle } from '../../lib/pack/bundleCompiler.js'

const outIndex = process.argv.indexOf('--out')
const out = outIndex >= 0 ? process.argv[outIndex + 1] : join(process.cwd(), 'docs/v2/bundle.lock.json')
const bundle = await compileBundle({ root: process.cwd() })
await writeFile(out, `${JSON.stringify(bundle, null, 2)}\n`)
console.log(JSON.stringify({ out, name: bundle.name, version: bundle.version, preset: bundle.preset, fileCount: bundle.fileCount, aggregateSha256: bundle.aggregateSha256 }, null, 2))
