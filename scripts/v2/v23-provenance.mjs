/** Paths that may be appended after a V2.3 source snapshot was committed. */
export const POST_SOURCE_FILES = Object.freeze([
  'docs/v2.3/acceptance-report.md',
  'docs/v2.3/threat-model.md',
  'docs/v2.3/compatibility-matrix.json',
  'docs/v2.3/migration-and-rollback.md',
  'docs/v2.3/evidence/p0-h/acceptance-manifest.json',
])

const allowedFiles = new Set(POST_SOURCE_FILES)
const evidenceDirectory = 'docs/v2.3/evidence/p0-h/'

export function isAllowedPostSourcePath(path) {
  return allowedFiles.has(path) || path.startsWith(evidenceDirectory)
}

export function findForbiddenPostSourcePaths(paths) {
  return paths.filter((path) => !isAllowedPostSourcePath(path))
}

export function isFullCommitSha(value) {
  return typeof value === 'string' && /^[a-f0-9]{40}$/i.test(value)
}
