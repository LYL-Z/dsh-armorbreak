/**
 * Isolation provider manager (v1.2.0 Advanced Research).
 *
 * Detection is deliberately separated from execution: a CLI on PATH is not
 * isolation, and a running daemon is still only `DaemonReady` until a harmless
 * self-test has actually succeeded. WSL2 is detected but never treated as a
 * security sandbox. The L1 runner keeps using HealthService.isolation() until
 * the provider abstraction is wired into the execution gate (next increment).
 * @module dsh-armorbreak/lib/core/isolation
 */
import { execFile } from 'node:child_process'

export const PROVIDER_STATES = Object.freeze([
  'Unavailable',
  'Installed',
  'DaemonReady',
  'IsolationVerified',
  'Degraded',
  'Error',
])

export const PROVIDERS = Object.freeze([
  {
    id: 'docker',
    title: 'Docker',
    kind: 'container',
    commands: ['docker'],
    daemonArgs: ['info', '--format', '{{.ServerVersion}}'],
    isolation: 'container',
    installUrl: 'https://docs.docker.com/engine/install/',
  },
  {
    id: 'podman',
    title: 'Podman',
    kind: 'container',
    commands: ['podman'],
    daemonArgs: ['info', '--format', '{{.Host.Security.Rootless}}'],
    isolation: 'container-rootless',
    installUrl: 'https://podman.io/docs/installation',
  },
  {
    id: 'wsl2',
    title: 'WSL2',
    kind: 'vm',
    commands: ['wsl'],
    daemonArgs: ['--status'],
    isolation: 'vm',
    installUrl: 'https://learn.microsoft.com/windows/wsl/install',
    note: 'WSL2 可用不等于未知样本可安全执行；默认不把它作为安全沙箱，也不自动启用。',
  },
])

/** Minimal child environment shared with HealthService semantics. */
function toolEnvironment() {
  /** @type {Record<string,string>} */
  const env = {}
  for (const key of ['PATH', 'Path', 'SystemRoot', 'SYSTEMROOT', 'TEMP', 'TMP', 'USERPROFILE', 'HOME', 'PATHEXT', 'ComSpec', 'COMSPEC']) {
    if (typeof process.env[key] === 'string') env[key] = process.env[key]
  }
  return env
}

/** @param {string} command @param {string[]} args @param {number} timeoutMs */
export function defaultExec(command, args, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    execFile(command, args, { timeout: timeoutMs, windowsHide: true, maxBuffer: 256 * 1024, env: toolEnvironment() }, (error, stdout, stderr) => {
      if (error) {
        const code = /** @type {any} */ (error).code
        const wrapped = Object.assign(
          new Error(code === 'ENOENT' ? `${command} not found` : `${command} ${args.join(' ')} failed: ${String(stderr || error.message).slice(0, 400)}`),
          { code },
        )
        reject(wrapped)
        return
      }
      resolve({ stdout: String(stdout ?? ''), stderr: String(stderr ?? '') })
    })
  })
}

export class IsolationProviderManager {
  /**
   * @param {{exec?: (command: string, args: string[], timeoutMs: number) => Promise<{stdout:string,stderr:string}>, verifyImpl?: (provider: any) => Promise<{ok:boolean, reason?:string}>}} [options]
   */
  constructor(options = {}) {
    this.exec = options.exec ?? defaultExec
    this.verifyImpl = options.verifyImpl ?? null
    this.cache = null
    /** @type {Map<string,string>} */
    this.verified = new Map()
  }

  /** @param {any} provider */
  async probe(provider) {
    const command = provider.commands[0]
    let version = null
    try {
      const result = await this.exec(command, ['--version'], 5000)
      version = String(result.stdout || result.stderr || '').split(/\r?\n/).map((line) => line.trim()).filter(Boolean)[0]?.slice(0, 200) ?? 'present'
    } catch (error) {
      if (/** @type {any} */ (error).code === 'ENOENT') {
        return { id: provider.id, title: provider.title, state: 'Unavailable', reason: `${provider.title} CLI 未安装`, version: null, isolation: provider.isolation, installUrl: provider.installUrl, note: provider.note ?? null }
      }
      return { id: provider.id, title: provider.title, state: 'Error', reason: String(/** @type {any} */ (error)?.message ?? error).slice(0, 300), version: null, isolation: provider.isolation, installUrl: provider.installUrl, note: provider.note ?? null }
    }
    try {
      const daemon = await this.exec(command, provider.daemonArgs, 5000)
      const server = String(daemon.stdout ?? '').trim().split(/\r?\n/)[0] ?? ''
      const state = this.verified.get(provider.id) ? 'IsolationVerified' : provider.id === 'wsl2' ? 'Installed' : 'DaemonReady'
      return {
        id: provider.id,
        title: provider.title,
        state,
        reason: provider.id === 'wsl2' ? 'WSL2 已安装；默认不视为安全沙箱，未做隔离自检' : state === 'IsolationVerified' ? '隔离自检已通过（本进程记录）' : '守护进程可用；尚未执行隔离自检',
        version,
        server: server || null,
        isolation: provider.isolation,
        installUrl: provider.installUrl,
        note: provider.note ?? null,
      }
    } catch (error) {
      return { id: provider.id, title: provider.title, state: 'Installed', reason: `CLI 已安装，但守护进程不可用：${String(/** @type {any} */ (error)?.message ?? error).slice(0, 300)}`, version, isolation: provider.isolation, installUrl: provider.installUrl, note: provider.note ?? null }
    }
  }

  /** @param {{fresh?: boolean}} [options] */
  async diagnose(options = {}) {
    if (this.cache && !options.fresh) return this.cache
    const providers = []
    for (const provider of PROVIDERS) providers.push(await this.probe(provider))
    const verified = providers.find((provider) => provider.state === 'IsolationVerified')
    const ready = verified ?? providers.find((provider) => provider.state === 'DaemonReady')
    this.cache = {
      generatedAt: new Date().toISOString(),
      providers,
      recommended: ready?.id ?? null,
      l1: verified
        ? { available: true, verified: true, provider: verified.id, state: 'IsolationVerified', reason: '隔离自检已通过' }
        : ready
          ? { available: false, verified: false, provider: ready.id, state: 'DaemonReady', reason: '守护进程可用，但尚未执行隔离自检；L1 仍需通过 runner 的隔离门与平台审批' }
          : { available: false, verified: false, provider: null, state: 'Unavailable', reason: '没有可用的隔离提供者' },
      wsl2Note: 'WSL2 不是默认安全沙箱；检测到也不自动获得 L1 执行许可。',
    }
    return this.cache
  }

  /**
   * Run the provider self-test when an implementation is injected; otherwise be
   * explicit that ArmorBreak cannot claim IsolationVerified from detection alone.
   * @param {string} providerId
   */
  async verify(providerId) {
    const provider = PROVIDERS.find((item) => item.id === providerId)
    if (!provider) throw new Error(`unknown isolation provider: ${providerId}`)
    if (!this.verifyImpl) {
      return {
        provider: providerId,
        verified: false,
        reason: '未配置隔离自检实现；请用 scripts/verify-l1.mjs 在真实 daemon 上验证，或注入 verifyImpl。检测到 CLI/daemon 不等于 IsolationVerified。',
      }
    }
    const result = await this.verifyImpl(provider)
    if (!result?.ok) return { provider: providerId, verified: false, reason: result?.reason ?? '隔离自检失败' }
    this.verified.set(providerId, new Date().toISOString())
    this.cache = null
    return { provider: providerId, verified: true, reason: result.reason ?? '隔离自检通过' }
  }

  /**
   * Run the harmless provider self-test: a digest-pinned busybox "true" with no
   * network, read-only root, non-root user. Only success records IsolationVerified.
   * @param {string} providerId
   * @param {{image?: string}} [options]
   */
  async selfTest(providerId, options = {}) {
    const provider = PROVIDERS.find((item) => item.id === providerId)
    if (!provider || !['docker', 'podman'].includes(provider.id)) {
      return { provider: providerId, verified: false, reason: 'only container providers support a self-test' }
    }
    const diagnosis = await this.diagnose({ fresh: true })
    const entry = diagnosis.providers.find((item) => item.id === providerId)
    if (!entry) return { provider: providerId, verified: false, reason: 'provider not found' }
    if (entry.state === 'IsolationVerified') return { provider: providerId, verified: true, reason: 'already verified in this process' }
    if (entry.state !== 'DaemonReady') {
      return { provider: providerId, verified: false, reason: `self-test requires DaemonReady, got ${entry.state}: ${entry.reason}` }
    }
    const image = options.image ?? process.env.ARMORBREAK_SELFTEST_IMAGE ?? 'busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662'
    const args = ['run', '--rm', '--pull=never', '--network=none', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--user=65534:65534', '--pids-limit=64', '--memory=128m', '--cpus=1', image, 'true']
    try {
      await this.exec(providerId, args, 30_000)
      this.verified.set(providerId, new Date().toISOString())
      this.cache = null
      return { provider: providerId, verified: true, reason: 'harmless container self-test passed (network none, non-root, read-only)' }
    } catch (error) {
      return { provider: providerId, verified: false, reason: `self-test failed: ${String(/** @type {any} */ (error)?.message ?? error).slice(0, 400)}. Ensure the pinned image exists locally (docker pull ${image}).` }
    }
  }

  /** @param {string} [providerId] */
  installationGuide(providerId) {
    const selected = providerId ? PROVIDERS.filter((provider) => provider.id === providerId) : PROVIDERS
    return selected.map((provider) => ({
      id: provider.id,
      title: provider.title,
      installUrl: provider.installUrl,
      isolation: provider.isolation,
      note: provider.note ?? null,
    }))
  }
}
