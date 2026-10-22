/**
 * Environment and dependency health: external security-tool discovery, version
 * probing (bounded), isolation-provider detection, and public snapshots.
 * @module dsh-armorbreak/lib/core/health
 */
import { execFile } from 'node:child_process'
import { accessSync, constants, existsSync, readdirSync } from 'node:fs'
import { homedir } from 'node:os'
import { delimiter, join } from 'node:path'
import { nowIso, redactText, resolveDshHome } from './util.js'

/** Known external tools: detection names, version flags, install guidance, capabilities served. */
export const EXTERNAL_TOOLS = [
  { id: 'ghidra', name: 'Ghidra', commands: ['analyzeHeadless', 'analyzeHeadless.bat'], versionArgs: null, serves: ['binary.structure', 'decompile'], install: { windows: 'Install Ghidra and add its support/ dir to PATH or set GHIDRA_HOME', unix: 'Install Ghidra, set GHIDRA_HOME or add support/ to PATH' }, alternative: '内置纯 JS 解析（binary.*）' },
  { id: 'rizin', name: 'Rizin', commands: ['rizin'], versionArgs: ['-v'], serves: ['disassembly', 'binary.structure'], install: { windows: 'winget install rizin', unix: 'brew install rizin / apt install rizin' }, alternative: '内置字符串/结构分析' },
  { id: 'radare2', name: 'radare2', commands: ['radare2', 'r2'], versionArgs: ['-v'], serves: ['disassembly'], install: { windows: 'Install from GitHub releases; add bin to PATH', unix: 'brew install radare2 / apt install radare2' }, alternative: '内置字符串/结构分析' },
  { id: 'yara', name: 'YARA', commands: ['yara', 'yara64'], versionArgs: ['--version'], serves: ['rule matching'], install: { windows: 'Download yara release and add to PATH', unix: 'brew install yara / apt install yara' }, alternative: '内置规则匹配（启发式）' },
  { id: 'jadx', name: 'JADX', commands: ['jadx', 'jadx.bat'], versionArgs: ['--version'], serves: ['android decompile'], install: { windows: 'Download JADX release, add bin to PATH', unix: 'brew install jadx' }, alternative: '内置 APK/DEX 结构分析' },
  { id: 'apktool', name: 'Apktool', commands: ['apktool', 'apktool.bat'], versionArgs: ['--version'], serves: ['android resources'], install: { windows: 'Download apktool jar + wrapper script into PATH', unix: 'brew install apktool' }, alternative: '内置 AXML/资源解析' },
  { id: 'adb', name: 'Android Debug Bridge', commands: ['adb', 'adb.exe'], versionArgs: ['version'], serves: ['android device'], install: { windows: 'Install platform-tools and add to PATH', unix: 'apt install android-tools-adb' }, alternative: '仅离线 APK 分析' },
  { id: 'frida', name: 'Frida', commands: ['frida', 'frida.exe'], versionArgs: ['--version'], serves: ['dynamic instrumentation'], install: { windows: 'pip install frida-tools', unix: 'pip install frida-tools' }, alternative: '不提供动态插桩（需授权设备）' },
  { id: 'semgrep', name: 'Semgrep', commands: ['semgrep', 'semgrep.exe'], versionArgs: ['--version'], serves: ['sast'], install: { windows: 'pip install semgrep', unix: 'brew install semgrep' }, alternative: '内置 SAST 规则引擎' },
  { id: 'codeql', name: 'CodeQL', commands: ['codeql', 'codeql.exe'], versionArgs: ['version'], serves: ['sast dataflow'], install: { windows: 'Download CodeQL CLI bundle', unix: 'Download CodeQL CLI bundle' }, alternative: '内置规则扫描' },
  { id: 'trivy', name: 'Trivy', commands: ['trivy', 'trivy.exe'], versionArgs: ['--version'], serves: ['dependency scan'], install: { windows: 'winget install aquasecurity.trivy', unix: 'brew install trivy' }, alternative: '内置依赖盘点（无漏洞库）' },
  { id: 'syft', name: 'Syft', commands: ['syft', 'syft.exe'], versionArgs: ['version'], serves: ['sbom'], install: { windows: 'winget install anchore.syft', unix: 'brew install syft' }, alternative: '内置 CycloneDX SBOM 生成' },
  { id: 'gitleaks', name: 'Gitleaks', commands: ['gitleaks', 'gitleaks.exe'], versionArgs: ['version'], serves: ['secrets'], install: { windows: 'winget install gitleaks', unix: 'brew install gitleaks' }, alternative: '内置密钥检测' },
  { id: 'tshark', name: 'TShark', commands: ['tshark', 'tshark.exe'], versionArgs: ['-v'], serves: ['pcap'], install: { windows: 'Install Wireshark (includes tshark)', unix: 'apt install tshark' }, alternative: '内置 PCAP/PCAPNG 解析' },
  { id: 'zeek', name: 'Zeek', commands: ['zeek'], versionArgs: ['--version'], serves: ['network logs'], install: { windows: 'Docker/WSL only', unix: 'brew install zeek' }, alternative: '内置流量分析' },
  { id: 'suricata', name: 'Suricata', commands: ['suricata'], versionArgs: ['-V'], serves: ['ids'], install: { windows: 'Docker/WSL only', unix: 'apt install suricata' }, alternative: '内置异常启发式' },
  { id: 'nmap', name: 'Nmap', commands: ['nmap', 'nmap.exe'], versionArgs: ['--version'], serves: ['network discovery'], install: { windows: 'Download nmap installer', unix: 'brew install nmap' }, alternative: '仅授权目标的主动探测（L2，需审批）' },
  { id: 'volatility3', name: 'Volatility 3', commands: ['vol', 'vol.py', 'volatility3'], versionArgs: ['--version'], serves: ['memory forensics'], install: { windows: 'pip install volatility3', unix: 'pip install volatility3' }, alternative: '内置文件级取证' },
  { id: 'capa', name: 'capa', commands: ['capa', 'capa.exe'], versionArgs: ['--version'], serves: ['capability detection'], install: { windows: 'pip install flare-capa', unix: 'pip install flare-capa' }, alternative: '内置启发式字符串/导入分析' },
  { id: 'floss', name: 'FLOSS', commands: ['floss', 'floss.exe'], versionArgs: ['--version'], serves: ['string deobfuscation'], install: { windows: 'pip install flare-floss', unix: 'pip install flare-floss' }, alternative: '内置 ASCII/UTF-16 字符串提取' },
  { id: 'docker', name: 'Docker', commands: ['docker', 'docker.exe'], versionArgs: ['--version'], serves: ['L1 isolation'], install: { windows: 'Install Docker Desktop and start it', unix: 'Install docker engine' }, alternative: '无隔离环境时 L1 动态分析保持拒绝' },
  { id: 'soffice', name: 'LibreOffice', commands: ['soffice', 'soffice.exe'], versionArgs: ['--version'], serves: ['pdf export'], install: { windows: 'winget install TheDocumentFoundation.LibreOffice', unix: 'apt install libreoffice' }, alternative: 'Markdown/HTML/JSON/SARIF 报告' },
  { id: 'objdump', name: 'GNU objdump', commands: ['objdump', 'objdump.exe'], versionArgs: ['--version'], serves: ['disassembly'], install: { windows: 'Install MinGW/binutils or use WSL', unix: 'apt install binutils' }, alternative: '内置结构分析' },
  { id: 'strings', name: 'GNU strings', commands: ['strings', 'strings.exe'], versionArgs: ['--version'], serves: ['strings'], install: { windows: 'Install MinGW/binutils', unix: 'apt install binutils' }, alternative: '内置字符串提取' },
  { id: 'python', name: 'Python', commands: ['python', 'python3', 'py'], versionArgs: ['--version'], serves: ['external adapters'], install: { windows: 'winget install Python.Python.3', unix: 'apt install python3' }, alternative: '内置 JS 实现' },
]

/** Environment variables passed to external tools; everything else is dropped. */
function toolEnvironment() {
  /** @type {Record<string, string>} */
  const env = {}
  for (const key of ['PATH', 'Path', 'SystemRoot', 'SYSTEMROOT', 'TEMP', 'TMP', 'windir', 'WINDIR', 'PATHEXT', 'ComSpec', 'COMSPEC', 'HOME', 'USERPROFILE', 'LANG']) {
    if (typeof process.env[key] === 'string') env[key] = process.env[key]
  }
  return env
}

export class HealthService {
  /**
   * @param {{stateRoot: string, timeoutMs?: number, versionTimeoutMs?: number}} options
   */
  constructor(options) {
    this.stateRoot = options.stateRoot
    this.timeoutMs = options.timeoutMs ?? 1500
    // Version probes are allowed longer than plain detection: Python/Java CLIs can
    // take a few seconds to start on a cold filesystem cache (e.g. Semgrep ~2.4 s).
    this.versionTimeoutMs = options.versionTimeoutMs ?? 5000
    /** @type {Map<string, any>} */
    this.cache = new Map()
    this.isolationCache = null
  }

  /** @returns {string[]} */
  pathDirs() {
    const raw = process.env.PATH ?? process.env.Path ?? ''
    return raw.split(delimiter).filter(Boolean)
  }

  /**
   * Find an executable on PATH (also honours GHIDRA_HOME for ghidra).
   * @param {string[]} commands
   * @returns {string|null}
   */
  findExecutable(commands) {
    const exts = process.platform === 'win32'
      ? (process.env.PATHEXT ?? '.EXE;.CMD;.BAT;.COM').split(';').map((ext) => ext.toLowerCase())
      : ['']
    for (const command of commands) {
      if (command.includes('/') || command.includes('\\')) {
        try {
          accessSync(command, constants.X_OK)
          return command
        } catch {
          continue
        }
      }
      for (const dir of this.pathDirs()) {
        for (const ext of exts) {
          const candidate = join(dir, `${command}${ext}`)
          try {
            accessSync(candidate, constants.F_OK)
            return candidate
          } catch {
            /* keep searching */
          }
        }
      }
    }
    return null
  }

  /** @param {string[]} args @returns {string[]} extra candidates for special tools */
  specialCandidates(toolId) {
    if (toolId === 'ghidra') {
      const roots = [process.env.GHIDRA_HOME, join(homedir(), 'ghidra'), 'C:\\ghidra', 'C:\\tools\\ghidra']
      /** @type {string[]} */
      const out = []
      for (const root of roots) {
        if (!root) continue
        if (existsSync(join(root, 'support'))) out.push(join(root, 'support'))
        if (existsSync(join(root, 'ghidraRun'))) out.push(join(root, 'support'))
      }
      return out
    }
    return []
  }

  /**
   * Probe one known external tool.
   * @param {string} toolId
   * @param {{version?: boolean, refresh?: boolean}} [opts]
   */
  async probe(toolId, opts = {}) {
    const known = EXTERNAL_TOOLS.find((tool) => tool.id === toolId)
    if (!known) return { id: toolId, found: false, reason: `unknown external tool "${toolId}"` }
    const cacheKey = `${toolId}:${opts.version === true ? 'v' : 'p'}`
    if (!opts.refresh && this.cache.has(cacheKey)) return this.cache.get(cacheKey)
    let foundPath = this.findExecutable(known.commands)
    if (!foundPath && toolId === 'ghidra') {
      const special = this.specialCandidates(toolId)
      for (const dir of special) {
        for (const command of known.commands) {
          const candidate = join(dir, command)
          if (existsSync(candidate)) {
            foundPath = candidate
            break
          }
        }
        if (foundPath) break
      }
    }
    let result
    if (!foundPath) {
      result = {
        id: known.id,
        name: known.name,
        found: false,
        path: null,
        version: null,
        serves: known.serves,
        install: known.install,
        alternative: known.alternative,
        reason: `${known.name} not found on PATH`,
      }
    } else {
      let version = null
      let versionError = null
      if (opts.version === true && known.versionArgs) {
        try {
          version = await this.runVersion(foundPath, known.versionArgs, this.versionTimeoutMs)
        } catch (error) {
          versionError = String(/** @type {any} */ (error)?.message ?? error)
        }
      }
      result = {
        id: known.id,
        name: known.name,
        found: true,
        path: foundPath,
        version,
        versionError,
        serves: known.serves,
        install: known.install,
        alternative: known.alternative,
        reason: null,
      }
    }
    this.cache.set(cacheKey, result)
    return result
  }

  /** @param {string} command @param {string[]} args @param {number} [timeoutMs] */
  runVersion(command, args, timeoutMs = this.timeoutMs) {
    return new Promise((resolvePromise, reject) => {
      execFile(
        command,
        args,
        { timeout: timeoutMs, windowsHide: true, maxBuffer: 64 * 1024, env: toolEnvironment() },
        (error, stdout, stderr) => {
          if (error && !stdout && !stderr) {
            reject(new Error(`version probe failed: ${error.message}`))
            return
          }
          const text = redactText(`${stdout ?? ''}\n${stderr ?? ''}`.trim())
          const first = text.split('\n').map((line) => line.trim()).filter(Boolean)[0] ?? ''
          resolvePromise(first.slice(0, 200) || 'present')
        },
      )
    })
  }

  /**
   * Detect an isolated execution provider (L1 gate). Docker only in v1, and the
   * daemon must answer — a CLI without a running daemon is not isolation.
   */
  async isolation() {
    if (this.isolationCache) return this.isolationCache
    const docker = await this.probe('docker', { version: true })
    if (!docker.found) {
      this.isolationCache = {
        available: false,
        provider: null,
        reason: 'no container runtime found (Docker CLI absent); L1 dynamic analysis is denied by default',
        tool: docker,
      }
      return this.isolationCache
    }
    try {
      const server = await new Promise((resolvePromise, reject) => {
        execFile(docker.path, ['info', '--format', '{{.ServerVersion}}'], { timeout: 3000, windowsHide: true, maxBuffer: 64 * 1024, env: toolEnvironment() }, (error, stdout) => {
          if (error) reject(new Error(error.message))
          else resolvePromise(String(stdout).trim())
        })
      })
      this.isolationCache = { available: server !== '', provider: 'docker', server, reason: null, tool: docker }
    } catch (error) {
      this.isolationCache = {
        available: false,
        provider: 'docker',
        reason: `Docker CLI found but daemon is not usable: ${String(/** @type {any} */ (error)?.message ?? error)}`,
        tool: docker,
      }
    }
    return this.isolationCache
  }

  /**
   * Full environment facts for reports and the health tool.
   */
  async environment() {
    const isolation = await this.isolation()
    return {
      generatedAt: nowIso(),
      platform: process.platform,
      arch: process.arch,
      node: process.version,
      dshVersion: process.env.DSH_CLIENT_VERSION ?? process.env.DSH_VERSION ?? 'unknown',
      profile: process.env.DSH_PROFILE ?? null,
      profileDir: process.env.DSH_PROFILE_DIR ?? null,
      dshHome: resolveDshHome(),
      stateRoot: this.stateRoot,
      cwd: process.cwd(),
      isolation,
    }
  }

  /**
   * Probe a list of tools (bounded concurrency is unnecessary: sequential with cache).
   * @param {string[]} toolIds
   * @param {{version?: boolean}} [opts]
   */
  async probeMany(toolIds, opts = {}) {
    const out = []
    for (const toolId of toolIds) out.push(await this.probe(toolId, opts))
    return out
  }

  /** All known tools without version probes. */
  async toolMatrix() {
    return this.probeMany(EXTERNAL_TOOLS.map((tool) => tool.id))
  }

  /**
   * The tools relevant to a capability list.
   * @param {Array<{externalTools?: string[]}>} capabilities
   */
  async forCapabilities(capabilities) {
    const ids = [...new Set(capabilities.flatMap((capability) => capability.externalTools ?? []))]
    return this.probeMany(ids)
  }
}

export default HealthService
