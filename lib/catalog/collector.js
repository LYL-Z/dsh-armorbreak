/**
 * AB2-M2-09 CatalogCollector (metadata only, never executes packages).
 *
 * Input is already-fetched metadata; this module never performs network I/O.
 * Canonicalization is host/owner/repo + commit so mirrors and .git URLs dedupe,
 * while different commits remain distinct candidates.
 */
function canonicalRepo(input) {
  const raw = String(input.url ?? input.repo ?? '').trim()
  if (!raw) return null
  let text = raw.replace(/^git\+/, '').replace(/\.git$/i, '').replace(/\/+$/, '')
  text = text.replace(/^git@([^:]+):/i, 'https://$1/')
  let url
  try { url = new URL(text) } catch { return null }
  if (!['github.com', 'gitlab.com'].includes(url.hostname.toLowerCase())) return null
  const parts = url.pathname.split('/').filter(Boolean).map((part) => decodeURIComponent(part))
  if (parts.length < 2) return null
  return `${url.hostname.toLowerCase()}/${parts[0].toLowerCase()}/${parts[1].toLowerCase()}`
}

function statusFor(entry) {
  if (entry.status === 404 || entry.error === 'not-found') return 'NOT_FOUND'
  if (entry.status === 429 || entry.error === 'rate-limited') return 'RATE_LIMITED'
  if (!entry.commit) return 'NEEDS_COMMIT'
  if (!entry.license) return 'MISSING_LICENSE'
  return 'OK'
}

export function collectCatalog(entries) {
  const items = []
  const byKey = new Map()
  const rejected = []
  for (const entry of Array.isArray(entries) ? entries : []) {
    const repo = canonicalRepo(entry)
    if (!repo) { rejected.push({ url: entry.url ?? entry.repo ?? null, reason: 'unsupported-or-invalid-repo' }); continue }
    const commit = String(entry.commit ?? '').trim().toLowerCase()
    const key = commit ? `${repo}@${commit}` : `${repo}@none`
    const item = {
      schemaVersion: 'armorbreak.catalog-item/v1',
      canonicalRepo: repo,
      commit: commit || null,
      license: entry.license ? String(entry.license).slice(0, 100) : null,
      version: entry.version ? String(entry.version).slice(0, 100) : null,
      source: entry.source ? String(entry.source).slice(0, 200) : 'catalog',
      sources: [entry.source ? String(entry.source).slice(0, 200) : 'catalog'],
      status: statusFor({ ...entry, commit, license: entry.license }),
      executable: false,
      metadataOnly: true,
    }
    if (byKey.has(key)) {
      byKey.get(key).sources.push(item.source)
      continue
    }
    items.push(item)
    byKey.set(key, item)
  }
  return { schemaVersion: 'armorbreak.catalog/v1', items, rejected, deduped: items.length }
}

export { canonicalRepo }
