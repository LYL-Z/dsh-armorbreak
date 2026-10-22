#!/usr/bin/env node
/** Generate a stable OpenAPI document for the MCP HTTP + SDK contract. */
import { readFileSync, writeFileSync, existsSync } from 'node:fs'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(fileURLToPath(new URL('../..', import.meta.url)))
const contract = JSON.parse(readFileSync(resolve(root, 'packages/sdk-ts/schemas/client-contract.json'), 'utf8'))
const doc = {
  openapi: '3.1.0',
  info: { title: 'ArmorBreak MCP HTTP', version: contract.schemaVersion },
  servers: [{ url: 'https://127.0.0.1:0/mcp' }],
  paths: {
    '/health': { get: { operationId: 'health', responses: { 200: { description: 'ok' } } } },
    '/mcp': {
      post: {
        operationId: 'mcp',
        requestBody: { required: true, content: { 'application/json': { schema: { type: 'object' } } } },
        responses: { 200: { description: 'JSON-RPC or SSE response' }, 401: { description: 'unauthorized' }, 403: { description: 'origin/host denied' } },
      },
    },
  },
  'x-armorbreak-methods': Object.keys(contract.methods).sort(),
  'x-armorbreak-security': contract.security,
}
const out = resolve(root, 'packages/sdk-ts/openapi.json')
const text = `${JSON.stringify(doc, null, 2)}\n`
if (process.argv.includes('--check')) {
  if (!existsSync(out) || readFileSync(out, 'utf8') !== text) { console.error('sdk OpenAPI is stale'); process.exitCode = 1 }
  else console.log(JSON.stringify({ ok: true, path: 'packages/sdk-ts/openapi.json' }))
} else {
  writeFileSync(out, text)
  console.log(JSON.stringify({ generated: 'packages/sdk-ts/openapi.json', methods: doc['x-armorbreak-methods'] }))
}
