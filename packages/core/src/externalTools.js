/**
 * External research tool resolution (v1.2.0).
 *
 * Tool discovery is explicit and bounded: environment override -> PATH -> known
 * installation locations. Execution always uses argv arrays (never a shell) and
 * a child environment whitelist. The `env.execExternal` seam exists for tests
 * only; adapters call `executeTool` with the resolved command.
 * @module dsh-armorbreak/lib/core/externalTools
 */
import { execFile } from 'node:child_process'
import { existsSync, readdirSync, statSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { createHash } from 'node:crypto'

export const EXTERNAL_TOOL_GUIDANCE = Object.freeze({
  tshark: '安装 Wireshark/TShark（https://www.wireshark.org/download.html），或设置 ARMORBREAK_TSHARK_PATH。',
  syft: '安装 Syft（https://github.com/anchore/syft），或设置 ARMORBREAK_SYFT_PATH。',
  jadx: '安装 JADX（https://github.com/skylot/jadx）及其 JRE，或设置 ARMORBREAK_JADX_PATH / ARMORBREAK_JADX_JAR。',
  ghidra: '安装 Ghidra（https://ghidra-sre.org/）与 JDK 21，或设置 ARMORBREAK_GHIDRA_HOME。',
  java: '安装 JDK 21（Temurin）或设置 ARMORBREAK_JAVA_PATH。',
})

export function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

function childEnv() {
  /** @type {Record<string,string>} */
  const env = {}
  for (const key of ['PATH', 'Path', 'SystemRoot', 'SYSTEMROOT', 'TEMP', 'TMP', 'USERPROFILE', 'HOME', 'APPDATA', 'LOCALAPPDATA', 'JAVA_HOME', 'PATHEXT', 'ComSpec', 'COMSPEC']) {
    if (typeof process.env[key] === 'string') env[key] = process.env[key]
  }
  return env
}

function pathDirs() {
  const raw = process.env.PATH ?? process.env.Path ?? ''
  return raw.split(';').map((entry) => entry.trim()).filter(Boolean)
}

function executableIn(dir, names) {
  for (const name of names) {
    const candidate = join(dir, name)
    try {
      if (existsSync(candidate) && statSync(candidate).isFile()) return candidate
    } catch {
      /* unreadable path entries are ignored */
    }
  }
  return null
}

/** @param {string[]} names @param {string[]} extraDirs */
export function findExecutable(names, extraDirs = []) {
  for (const dir of [...extraDirs, ...pathDirs()]) {
    const found = executableIn(dir, names)
    if (found) return found
  }
  return null
}

function winGetPackages() {
  const base = process.env.LOCALAPPDATA ? join(process.env.LOCALAPPDATA, 'Microsoft', 'WinGet', 'Packages') : null
  if (!base || !existsSync(base)) return []
  try {
    return readdirSync(base).map((name) => join(base, name))
  } catch {
    return []
  }
}

/** @param {string} pattern @param {string} suffix */
function findUnderWinGet(pattern, suffix) {
  for (const dir of winGetPackages()) {
    if (!pattern.test(dir)) continue
    const candidate = join(dir, suffix)
    if (existsSync(candidate)) return candidate
  }
  return null
}

export function resolveTshark(env = process.env) {
  const override = env.ARMORBREAK_TSHARK_PATH
  if (override && existsSync(override)) return override
  const found = findExecutable(['tshark.exe', 'tshark'], ['C:\\Program Files\\Wireshark'])
  if (!found) throw new Error(`tshark 未安装或不在 PATH。${EXTERNAL_TOOL_GUIDANCE.tshark}`)
  return found
}

export function resolveSyft(env = process.env) {
  const override = env.ARMORBREAK_SYFT_PATH
  if (override && existsSync(override)) return override
  const winget = findUnderWinGet(/Anchore\.Syft/i, 'syft.exe')
  const found = winget ?? findExecutable(['syft.exe', 'syft'])
  if (!found) throw new Error(`syft 未安装或不在 PATH。${EXTERNAL_TOOL_GUIDANCE.syft}`)
  return found
}

export function resolveJava(env = process.env) {
  const override = env.ARMORBREAK_JAVA_PATH
  if (override && existsSync(override)) return override
  if (env.JAVA_HOME) {
    const candidate = join(env.JAVA_HOME, 'bin', 'java.exe')
    if (existsSync(candidate)) return candidate
  }
  const adoptium = ['C:\\Program Files\\Eclipse Adoptium', 'C:\\Program Files\\Java']
  for (const base of adoptium) {
    if (!existsSync(base)) continue
    try {
      for (const dir of readdirSync(base)) {
        const candidate = join(base, dir, 'bin', 'java.exe')
        if (existsSync(candidate)) return candidate
      }
    } catch {
      /* ignore unreadable JDK directory */
    }
  }
  const found = findExecutable(['java.exe', 'java'])
  if (!found) throw new Error(`Java 未安装或不在 PATH。${EXTERNAL_TOOL_GUIDANCE.java}`)
  return found
}

/** Ghidra 12 requires JDK 21; prefer an explicit 21 installation over JAVA_HOME. */
export function resolveJava21(env = process.env) {
  const override = env.ARMORBREAK_JAVA21_PATH
  if (override && existsSync(override)) return override
  const base = 'C:\\Program Files\\Eclipse Adoptium'
  if (existsSync(base)) {
    try {
      for (const dir of readdirSync(base)) {
        if (!/jdk-21/i.test(dir)) continue
        const candidate = join(base, dir, 'bin', 'java.exe')
        if (existsSync(candidate)) return candidate
      }
    } catch {
      /* fall through */
    }
  }
  return resolveJava(env)
}

/** @returns {{home: string, launcher: string, javaHome: string}} */
export function resolveGhidra(env = process.env) {
  const candidates = []
  if (env.ARMORBREAK_GHIDRA_HOME) candidates.push(env.ARMORBREAK_GHIDRA_HOME)
  const toolsRoot = 'D:\\dsh-tools\\ghidra-dl'
  if (existsSync(toolsRoot)) {
    try {
      for (const dir of readdirSync(toolsRoot)) if (/^ghidra_.*_PUBLIC$/.test(dir)) candidates.push(join(toolsRoot, dir))
    } catch {
      /* ignore */
    }
  }
  for (const home of candidates) {
    const launcher = process.platform === 'win32' ? join(home, 'support', 'analyzeHeadless.bat') : join(home, 'support', 'analyzeHeadless')
    if (!existsSync(launcher)) continue
    const javaExe = resolveJava21(env)
    return { home, launcher, javaHome: dirname(dirname(javaExe)) }
  }
  throw new Error(`Ghidra 未安装或未找到 analyzeHeadless。${EXTERNAL_TOOL_GUIDANCE.ghidra}`)
}

/** @returns {{command: string, prefixArgs: string[], versionHint: string}} */
export function resolveJadx(env = process.env) {
  const override = env.ARMORBREAK_JADX_PATH
  if (override && existsSync(override)) return { command: override, prefixArgs: [], versionHint: override }
  let jar = env.ARMORBREAK_JADX_JAR && existsSync(env.ARMORBREAK_JADX_JAR) ? env.ARMORBREAK_JADX_JAR : null
  if (!jar) {
    for (const dir of winGetPackages()) {
      if (!/Skylot\.jadx/i.test(dir)) continue
      const lib = join(dir, 'lib')
      for (const name of readdirSyncSafe(lib)) {
        if (!/^jadx-gui-.*-all\.jar$/.test(name)) continue
        jar = join(lib, name)
        break
      }
      if (jar) break
    }
  }
  if (!jar || !existsSync(jar)) throw new Error(`JADX 未安装或未找到 CLI jar。${EXTERNAL_TOOL_GUIDANCE.jadx}`)
  return { command: resolveJava(env), prefixArgs: ['-cp', jar, 'jadx.cli.JadxCLI'], versionHint: jar }
}

function localWinGetDir(pattern) {
  for (const dir of winGetPackages()) if (pattern.test(dir)) return dir
  return ''
}

function readdirSyncSafe(dir) {
  try {
    return readdirSync(dir)
  } catch {
    return []
  }
}

/**
 * Execute a resolved tool with bounded output. Tests set env.execExternal.
 * @param {any} env capability env
 * @param {{command: string, prefixArgs?: string[]}} tool
 * @param {string[]} args
 * @param {{timeoutMs?: number, maxOutputBytes?: number, cwd?: string, envOverrides?: Record<string,string>}} [options]
 */
export async function executeTool(env, tool, args, options = {}) {
  const timeoutMs = Math.max(1000, Math.min(Number(options.timeoutMs ?? 120_000), 600_000))
  const maxOutputBytes = Math.max(1024 * 1024, Math.min(Number(options.maxOutputBytes ?? 16 * 1024 * 1024), 64 * 1024 * 1024))
  const command = tool.command
  const fullArgs = [...(tool.prefixArgs ?? []), ...args]
  if (typeof env?.execExternal === 'function') {
    const result = await env.execExternal(command, fullArgs, { timeoutMs })
    return { stdout: String(result?.stdout ?? ''), stderr: String(result?.stderr ?? ''), exitCode: Number(result?.exitCode ?? 0) }
  }
  return await new Promise((resolve, reject) => {
    execFile(command, fullArgs, { timeout: timeoutMs, windowsHide: true, maxBuffer: maxOutputBytes, env: { ...childEnv(), ...(options.envOverrides ?? {}) }, cwd: options.cwd }, (error, stdout, stderr) => {
      if (error) {
        const code = /** @type {any} */ (error).code
        const text = String(stderr || error.message || '').slice(0, 800)
        if (code === 'ENOENT') {
          reject(new Error(`${command} is not installed or not executable; check the tool installation or set its ARMORBREAK_*_PATH override`))
          return
        }
        reject(new Error(`${command} failed (${code ?? 'error'}): ${text}`))
        return
      }
      resolve({ stdout: String(stdout ?? ''), stderr: String(stderr ?? ''), exitCode: 0 })
    })
  })
}

/** @param {string} raw @param {string} tool */
export function parseJsonOutput(raw, tool) {
  try {
    return JSON.parse(raw)
  } catch {
    throw new Error(`${tool} output is not valid JSON; refusing to normalize an unparsable report`)
  }
}
