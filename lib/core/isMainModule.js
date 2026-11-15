/** npm's Unix bin entries are symlinks; compare real files before deciding to launch. */
import { realpathSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
export function isMainModule(url, entry = process.argv[1]) {
  if (!entry) return false
  try { return realpathSync(entry) === realpathSync(fileURLToPath(url)) } catch { return false }
}
