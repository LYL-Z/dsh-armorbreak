import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { isDeepStrictEqual } from 'node:util'

const attributionFiles = ['LICENSE', 'NOTICE', 'LICENSES/MIT.txt', 'LICENSES/CC-BY-4.0.txt',
  'THIRD_PARTY_NOTICES.txt', 'REUSE.toml', 'CODE_OF_CONDUCT.md']
const required = ['package.json', 'npm-shrinkwrap.json', ...attributionFiles,
  'packages/core/index.js', 'packages/cli/index.js', 'packages/mcp-server/index.js',
  'packages/core/src/syntheticConfiguration.js', 'workbench/server.mjs']
const runtimeRoots = new Set(['lib', 'packages', 'plugins', 'skills', 'locale', 'workbench'])
const allowed = new Set([...attributionFiles, 'package.json', 'npm-shrinkwrap.json', 'index.js', 'tools.js',
  'skills.js', 'client.js', 'cordis.patch.yml', 'icon.svg', 'README.md', 'README.zh-CN.md',
  'CHANGELOG.md', 'SECURITY.md', 'CONTRIBUTING.md', 'AUTHORS.md', 'GOVERNANCE.md', 'SUPPORT.md',
  'TRADEMARK.md', 'ETHICAL_USE.md', 'ROADMAP.md', 'docs/v24/distribution.md'])
const licenseSha = 'e53a4f3c04d8f629aba65a67842952bd42fe4dc3104526d643b5150df01d2da6'
const hash = bytes => createHash('sha256').update(bytes).digest('hex')

export function checkDistributionPaths(paths) {
  if (!Array.isArray(paths) || paths.some(path => typeof path !== 'string') ||
      new Set(paths.map(path => path.toLowerCase())).size !== paths.length) {
    throw new Error('DISTRIBUTION_FILE_LIST_INVALID')
  }
  for (const path of required) {
    if (!paths.includes(path)) throw new Error('DISTRIBUTION_MISSING: ' + path)
  }
  for (const path of paths) {
    if (/[:\\\x00-\x1f]/.test(path) || path.split('/').some(part => part === '' || part === '.' || part === '..') ||
        !(allowed.has(path) || runtimeRoots.has(path.split('/')[0]))) {
      throw new Error('UNRELATED_DISTRIBUTION_FILE: ' + path)
    }
    if (/(^|\/)(node_modules|tests?|fixtures?|evidence|acceptance|\.git|\.armorbreak)(\/|$)|(^|\/)\.env(?:\.|$)|\.(?:pem|key|p12|pfx|pyc)$/i.test(path)) {
      throw new Error('SENSITIVE_DISTRIBUTION_PATH: ' + path)
    }
  }
}

export function checkDistributionAttribution({ source, installed, paths, packVersion }) {
  checkDistributionPaths(paths)
  const read = path => {
    const bytes = readFileSync(join(installed, path))
    if (!bytes.equals(readFileSync(join(source, path)))) throw new Error('DISTRIBUTION_SOURCE_MISMATCH: ' + path)
    return bytes
  }
  const json = path => JSON.parse(read(path))
  const pkg = json('package.json'), lock = json('npm-shrinkwrap.json')
  const lockRoot = lock.packages?.['']
  if (pkg.name !== 'dsh-armorbreak' || lock.name !== pkg.name || lockRoot?.name !== pkg.name ||
      packVersion !== pkg.version || lock.version !== pkg.version || lockRoot.version !== pkg.version ||
      !isDeepStrictEqual(pkg.dependencies, lockRoot.dependencies)) {
    throw new Error('DISTRIBUTION_VERSION_OR_LOCK_MISMATCH')
  }
  if (pkg.license !== 'MIT' || lockRoot.license !== 'MIT') throw new Error('DISTRIBUTION_PROJECT_LICENSE_INVALID')
  const notices = attributionFiles.map(path => {
    const bytes = read(path)
    if (!bytes.toString('utf8').trim()) throw new Error('DISTRIBUTION_NOTICE_EMPTY: ' + path)
    const sha256 = hash(bytes)
    if ((path === 'LICENSE' || path === 'LICENSES/MIT.txt') && sha256 !== licenseSha) {
      throw new Error('DISTRIBUTION_PROJECT_LICENSE_TEXT_CHANGED')
    }
    return { path, sha256 }
  })
  const internalPackages = paths.filter(path => /^(packages|plugins)\/.+\/package\.json$/.test(path)).sort().map(path => {
    const internal = json(path)
    if (internal.private !== true || internal.license !== 'MIT') {
      throw new Error('DISTRIBUTION_INTERNAL_LICENSE_INVALID: ' + path)
    }
    return { path, name: internal.name, version: internal.version, licenseDeclared: internal.license }
  })
  return { version: pkg.version, licenseDeclared: pkg.license, notices, internalPackages }
}
