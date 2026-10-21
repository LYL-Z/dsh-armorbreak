/**
 * AB2-M3-02 Python worker supervisor.
 *
 * Spawns the stdlib-only worker with an explicit environment allowlist, speaks
 * newline-delimited JSON, enforces per-request timeouts and reaps the process on
 * timeout/cancel/crash. A dead worker never leaves the Host with hanging
 * promises, and a new request starts a fresh worker.
 */
import { spawn } from 'node:child_process'
import { createInterface } from 'node:readline'
import { fileURLToPath } from 'node:url'

const DEFAULT_ALLOW = ['PATH', 'PYTHONPATH', 'PYTHONUNBUFFERED', 'LANG', 'LC_ALL', 'TEMP', 'TMP', 'HOME', 'USERPROFILE', 'SYSTEMROOT', 'WINDIR', 'COMSPEC', 'PATHEXT']
const DEFAULT_SCRIPT = fileURLToPath(new URL('../../scripts/aisec/worker.py', import.meta.url))

export class PythonWorker {
  /**
   * @param {{python?:string, script?:string, envAllowlist?:string[], env?:Record<string,string>, defaultTimeoutMs?:number}} [input]
   */
  constructor(input = {}) {
    this.python = input.python ?? process.env.ARMORBREAK_PYTHON ?? (process.platform === 'win32' ? 'python' : 'python3')
    this.script = input.script ?? DEFAULT_SCRIPT
    this.envAllowlist = input.envAllowlist ?? DEFAULT_ALLOW
    this.extraEnv = input.env ?? {}
    this.defaultTimeoutMs = Math.max(100, Number(input.defaultTimeoutMs ?? 5000))
    this.child = null
    this.pending = new Map()
    this.nextId = 1
    this.generation = 0
    this.stderr = ''
  }

  env() {
    const env = {}
    for (const key of this.envAllowlist) if (process.env[key] !== undefined) env[key] = process.env[key]
    return { ...env, ...this.extraEnv, PYTHONUNBUFFERED: '1' }
  }

  start() {
    if (this.child && this.child.exitCode === null) return this
    this.stderr = ''
    const generation = ++this.generation
    const child = spawn(this.python, [this.script], { env: this.env(), stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true })
    this.child = child
    child.stderr.on('data', (chunk) => { this.stderr = (this.stderr + chunk.toString('utf8')).slice(-4096) })
    child.once('exit', (code, signal) => {
      if (this.child === child) this.child = null
      const error = new Error(`AISEC worker exited (code=${code}, signal=${signal})`)
      error.code = 'WORKER_EXITED'
      for (const [id, entry] of this.pending) {
        if (entry.generation !== generation) continue
        clearTimeout(entry.timer)
        entry.reject(error)
        this.pending.delete(id)
      }
    })
    const lines = createInterface({ input: child.stdout })
    lines.on('line', (line) => {
      let message
      try { message = JSON.parse(line) } catch { return }
      const entry = this.pending.get(message.id)
      if (!entry || entry.generation !== generation) return
      clearTimeout(entry.timer)
      this.pending.delete(message.id)
      if (message.ok) entry.resolve(message.result)
      else {
        const error = new Error(message.error?.message ?? 'worker error')
        error.code = message.error?.code ?? 'WORKER_ERROR'
        entry.reject(error)
      }
    })
    return this
  }

  request(method, params = {}, options = {}) {
    this.start()
    const id = this.nextId++
    const generation = this.generation
    const timeoutMs = Math.max(100, Number(options.timeoutMs ?? this.defaultTimeoutMs))
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        if (!this.pending.has(id)) return
        this.pending.delete(id)
        const error = new Error(`AISEC worker timeout after ${timeoutMs}ms (${method})`)
        error.code = 'WORKER_TIMEOUT'
        reject(error)
        this.stop('timeout')
      }, timeoutMs)
      this.pending.set(id, { resolve, reject, timer, method, generation })
      const child = this.child
      if (!child) {
        clearTimeout(timer)
        this.pending.delete(id)
        reject(new Error('AISEC worker not running'))
        return
      }
      child.stdin.write(`${JSON.stringify({ id, method, params })}\n`, (error) => {
        if (!error) return
        clearTimeout(timer)
        this.pending.delete(id)
        reject(error)
      })
    })
  }

  cancelAll(reason = 'cancelled') {
    for (const [id, entry] of this.pending) {
      clearTimeout(entry.timer)
      const error = new Error(`AISEC worker request ${reason}`)
      error.code = 'WORKER_CANCELLED'
      entry.reject(error)
      this.pending.delete(id)
    }
    this.stop(reason)
  }

  stop(reason = 'shutdown') {
    const child = this.child
    if (!child) return
    if (this.child === child) this.child = null
    try { child.stdin?.destroy() } catch { /* gone */ }
    try { child.stdout?.destroy() } catch { /* gone */ }
    try { child.stderr?.destroy() } catch { /* gone */ }
    try { child.kill('SIGKILL') } catch { /* already gone */ }
    this.lastStopReason = reason
  }

  async shutdown() {
    this.cancelAll('shutdown')
  }

  status() {
    return { running: Boolean(this.child && this.child.exitCode === null), protocol: 'armorbreak.aisec-worker/v1', pending: this.pending.size, stderr: this.stderr.slice(-1000) }
  }
}
