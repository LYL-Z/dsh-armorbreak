import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..')
const roots = ['packages/core/index.js', 'packages/core/evidenceEnvelope.js']
const forbidden = [/@deepseek-ai/, /\bcordis\b/i, /\belectron\b/i, /globalThis\.(?:document|window)\b/, /typeof\s+(?:document|window)\b/]
const files = new Map()
const edges = new Map()
const external = new Set()
const forbiddenHits = []

function resolveLocal(fromFile, spec) {
  if (!spec.startsWith('.')) return null
  const base = resolve(dirname(resolve(root, fromFile)), spec)
  for (const candidate of [base, `${base}.js`, resolve(base, 'index.js')]) {
    try {
      if (readFileSync(candidate).length >= 0) return candidate.slice(root.length + 1).replaceAll('\\', '/')
    } catch { /* not this candidate */ }
  }
  return null
}

const queue = [...roots]
while (queue.length > 0 && files.size < 500) {
  const file = queue.shift()
  if (files.has(file)) continue
  const text = readFileSync(resolve(root, file), 'utf8')
  files.set(file, text)
  const specs = [...text.matchAll(/(?:from\s+|import\s*\()['"]([^'"]+)['"]/g)].map((match) => match[1])
  for (const spec of specs) for (const pattern of forbidden) if (pattern.test(spec)) forbiddenHits.push({ file, spec, pattern: String(pattern) })
  edges.set(file, [])
  for (const spec of specs) {
    const local = resolveLocal(file, spec)
    if (local) {
      edges.get(file).push(local)
      queue.push(local)
    } else if (!spec.startsWith('node:')) {
      external.add(spec)
    }
  }
}

const graph = {
  schemaVersion: 'armorbreak.core-dependency-graph/v1',
  roots,
  files: [...files.keys()].sort(),
  edges: Object.fromEntries([...edges.entries()].sort(([a], [b]) => a.localeCompare(b))),
  external: [...external].sort(),
  forbiddenHits,
}
writeFileSync(resolve(root, 'packages/core/dependency-graph.json'), `${JSON.stringify(graph, null, 2)}\n`)
console.log(JSON.stringify({ files: graph.files.length, external: graph.external.length, forbiddenHits: graph.forbiddenHits.length }, null, 2))
if (forbiddenHits.length) process.exitCode = 1
