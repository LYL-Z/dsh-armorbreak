import { isAbsolute, relative, resolve, sep, win32 } from 'node:path'

function windowsCanonicalPath(value) {
  let input = String(value)
  const lower = input.toLowerCase()
  if (lower.startsWith('\\\\?\\unc\\')) input = `\\\\${input.slice(8)}`
  else if (lower.startsWith('\\\\?\\')) input = input.slice(4)
  return win32.resolve(input).toLowerCase()
}

/** Compare filesystem paths while treating Windows extended paths as their DOS/UNC equivalent. */
export function sameFilesystemPath(left, right, platform = process.platform) {
  if (platform === 'win32') return windowsCanonicalPath(left) === windowsCanonicalPath(right)
  return resolve(String(left)) === resolve(String(right))
}

/** Check a path boundary after normalizing Windows extended path prefixes. */
export function isFilesystemPathWithin(root, candidate, platform = process.platform) {
  const base = platform === 'win32' ? windowsCanonicalPath(root) : resolve(String(root))
  const target = platform === 'win32' ? windowsCanonicalPath(candidate) : resolve(String(candidate))
  const pathRelative = platform === 'win32' ? win32.relative(base, target) : relative(base, target)
  const separator = platform === 'win32' ? win32.sep : sep
  const absolute = platform === 'win32' ? win32.isAbsolute(pathRelative) : isAbsolute(pathRelative)
  return pathRelative === '' || (pathRelative !== '..' && !pathRelative.startsWith(`..${separator}`) && !absolute)
}
