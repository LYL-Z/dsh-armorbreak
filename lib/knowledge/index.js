/**
 * AB2-M2-07 knowledge index.
 *
 * Dependency-free inverted index used when SQLite FTS5 is unavailable. It is a
 * deliberate fallback, not a vector search: queries are lexical, every result
 * carries URI/version/retrievedAt/source/provenance and conflicts are explicit.
 */
import { createHash } from 'node:crypto'
import { readFile, rename, writeFile } from 'node:fs/promises'

const sha256 = (value) => createHash('sha256').update(value).digest('hex')

function tokenize(text) {
  return String(text ?? '').toLowerCase().split(/[^\p{L}\p{N}_-]+/u).filter((token) => token.length >= 2).slice(0, 5000)
}

export class KnowledgeIndex {
  /** @param {{file?: string|null}} [input] */
  constructor(input = {}) {
    this.file = input.file ?? null
    this.documents = new Map()
    this.terms = new Map()
    this.backend = 'json-memory-fallback'
    this.loaded = false
  }

  async load() {
    if (this.loaded) return this
    if (this.file) {
      try {
        const state = JSON.parse(await readFile(this.file, 'utf8'))
        for (const document of state.documents ?? []) this.add(document, { reindex: false })
      } catch { /* first run */ }
    }
    this.loaded = true
    return this
  }

  add(document, options = {}) {
    const id = String(document.id ?? sha256(`${document.uri ?? ''}|${document.version ?? ''}`)).slice(0, 200)
    const existing = this.documents.get(id)
    if (existing && existing.text !== document.text) {
      existing.conflicts = [...new Set([...(existing.conflicts ?? []), { version: document.version, retrievedAt: document.retrievedAt, source: document.source }])]
    }
    const record = {
      id,
      uri: String(document.uri ?? '').slice(0, 1000),
      title: String(document.title ?? '').slice(0, 300),
      text: String(document.text ?? '').slice(0, 200_000),
      version: String(document.version ?? '').slice(0, 100),
      retrievedAt: String(document.retrievedAt ?? '').slice(0, 60),
      source: String(document.source ?? 'unknown').slice(0, 300),
      trust: document.trust === 'verified' ? 'verified' : 'untrusted',
      license: String(document.license ?? 'unknown').slice(0, 100),
      conflicts: existing?.conflicts ?? [],
    }
    record.sha256 = sha256(`${record.uri}|${record.version}|${record.text}`)
    this.documents.set(id, record)
    if (options.reindex !== false) {
      this.terms.set(id, tokenize(`${record.title} ${record.text}`))
    }
    return record
  }

  async upsertMany(documents) {
    for (const document of documents) this.add(document)
    await this.save()
    return { count: this.documents.size }
  }

  /** Lexical search with simple term-frequency scoring and provenance. */
  search(query, options = {}) {
    const tokens = tokenize(query)
    if (tokens.length === 0) return []
    const limit = Math.max(1, Math.min(Number(options.limit ?? 20), 100))
    const results = []
    for (const [id, document] of this.documents) {
      if (options.trust && document.trust !== options.trust) continue
      const haystack = (this.terms.get(id) ?? tokenize(`${document.title} ${document.text}`))
      let score = 0
      for (const token of tokens) {
        for (const candidate of haystack) {
          if (candidate === token) score += 3
          else if (candidate.includes(token)) score += 1
        }
      }
      if (score > 0) results.push({ id, uri: document.uri, title: document.title, version: document.version, retrievedAt: document.retrievedAt, source: document.source, trust: document.trust, license: document.license, score, conflicts: document.conflicts })
    }
    return results.sort((a, b) => b.score - a.score || a.id.localeCompare(b.id)).slice(0, limit)
  }

  async save() {
    if (!this.file) return { saved: false }
    const body = `${JSON.stringify({ schemaVersion: 'armorbreak.knowledge-index/v1', backend: this.backend, documents: [...this.documents.values()] }, null, 2)}\n`
    const tmp = `${this.file}.${process.pid}.tmp`
    await writeFile(tmp, body)
    await rename(tmp, this.file)
    return { saved: true, documents: this.documents.size }
  }
}
