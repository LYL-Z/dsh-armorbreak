import { mkdtempSync, statSync } from 'node:fs'
import { mkdtemp } from 'node:fs/promises'
import { dirname, join, parse, resolve } from 'node:path'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'

const workspaceRoot = fileURLToPath(new URL('../..', import.meta.url))

function temporaryBase() {
  const systemTemp = tmpdir()
  const sameWindowsVolume = process.platform !== 'win32'
    || parse(resolve(workspaceRoot)).root.toLowerCase() === parse(resolve(systemTemp)).root.toLowerCase()
  if (sameWindowsVolume && statSync(workspaceRoot).dev === statSync(systemTemp).dev) return systemTemp
  const workspaceVolume = statSync(workspaceRoot).dev
  const parent = dirname(workspaceRoot)
  return statSync(parent).dev === workspaceVolume ? parent : workspaceRoot
}

export function makeTestTempDirectorySync(prefix) {
  return mkdtempSync(join(temporaryBase(), prefix))
}

export async function makeTestTempDirectory(prefix) {
  return await mkdtemp(join(temporaryBase(), prefix))
}
