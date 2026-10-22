#!/usr/bin/env node
/** Generate deterministic TypeScript contract types from the SDK client contract. */
import { mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(fileURLToPath(new URL('../..', import.meta.url)))
const contract = JSON.parse(readFileSync(resolve(root, 'packages/sdk-ts/schemas/client-contract.json'), 'utf8'))
const methods = Object.keys(contract.methods).sort()
const lines = [
  '// Generated from packages/sdk-ts/schemas/client-contract.json. Do not edit by hand.',
  `export type SdkMethod = ${methods.map((name) => `'${name}'`).join(' | ')}`,
  '',
  'export interface ClientContract {',
  '  schemaVersion: string',
  '  package: string',
  '  transports: string[]',
  '  methods: Record<SdkMethod, { params: string[]; result: string }>',
  '  security: { modelIsAuthority: boolean; tokenSource: string }',
  '}',
  '',
  'export declare const CONTRACT: ClientContract',
  '',
]
const out = resolve(root, 'packages/sdk-ts/generated/contract.d.ts')
const text = `${lines.join('\n')}`
if (process.argv.includes('--check')) {
  if (!existsSync(out) || readFileSync(out, 'utf8') !== text) { console.error('SDK contract types are stale'); process.exitCode = 1 }
  else console.log(JSON.stringify({ ok: true, methods }))
} else {
  mkdirSync(resolve(root, 'packages/sdk-ts/generated'), { recursive: true })
  writeFileSync(out, text)
  console.log(JSON.stringify({ generated: 'packages/sdk-ts/generated/contract.d.ts', methods }))
}
