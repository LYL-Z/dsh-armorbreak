/**
 * Authorized live-testing capabilities (L1/L2).
 *
 * These are the only capabilities that leave the offline boundary:
 *   - live.http_probe  (L2) sends an HTTP request to an explicitly authorized host
 *   - live.container_exec (L1) runs a command inside a disposable, network-less container
 *
 * The runner refuses to execute them without a matching authorization record and
 * a platform approval grant, so they are inert by default. Nothing here touches
 * the target unless the policy engine says the exact target is covered.
 * @module dsh-armorbreak/lib/analyzers/live/manifest
 */
import { execFile } from 'node:child_process'
import { createHash } from 'node:crypto'
import { basename, dirname } from 'node:path'

/** @param {string} value */
function redactHeaders(headers) {
  /** @type {Record<string, string>} */
  const out = {}
  const sensitive = /^(authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key)$/i
  for (const [key, value] of Object.entries(headers ?? {})) {
    out[key] = sensitive.test(key) ? '[REDACTED]' : String(value).slice(0, 300)
  }
  return out
}

/** @param {Buffer|string} value */
function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

/** Minimal env for child processes: never forward the host's full environment. */
function childEnv() {
  /** @type {Record<string, string>} */
  const env = {}
  for (const key of ['PATH', 'Path', 'SystemRoot', 'SYSTEMROOT', 'TEMP', 'TMP', 'USERPROFILE', 'HOME', 'DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_CONFIG', 'PATHEXT', 'ComSpec', 'COMSPEC']) {
    if (typeof process.env[key] === 'string') env[key] = process.env[key]
  }
  return env
}

/** @type {any} */
const httpProbe = {
  id: 'live.http_probe',
  title: '授权目标 HTTP 探测（L2）',
  description:
    '向一个已授权并已获批的主机发送单次 GET/HEAD 请求，记录状态码、脱敏响应头、响应体长度与哈希，用于验证授权范围内的 Web 行为。默认拒绝：需要 networkTargets 授权记录 + 平台审批。不跟随重定向，不发送凭据。',
  riskLevel: 'L2',
  targetKind: 'network',
  externalTools: [],
  networkTarget: (options) => {
    if (!options || typeof options.url !== 'string') throw new Error('live.http_probe needs options.url (http(s)://host/...)')
    const parsed = new URL(options.url)
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') throw new Error('only http(s) URLs are allowed')
    return parsed.host
  },
  params: {
    type: 'object',
    properties: {
      url: { type: 'string', description: 'Absolute http(s) URL to request once.' },
      method: { type: 'string', enum: ['GET', 'HEAD'], description: 'HTTP method. Default GET.' },
      timeoutMs: { type: 'number', description: 'Request timeout in ms (default 10000, max 30000).' },
      maxBodyBytes: { type: 'number', description: 'Read at most this many response bytes (default 262144).' },
    },
    required: ['url'],
    additionalProperties: false,
  },
  async run(input) {
    const options = input.options ?? {}
    const url = new URL(String(options.url))
    if (url.protocol !== 'http:' && url.protocol !== 'https:') throw new Error('only http(s) URLs are allowed')
    const timeoutMs = Math.max(1000, Math.min(Number(options.timeoutMs ?? 10_000), 30_000))
    const maxBodyBytes = Math.max(1024, Math.min(Number(options.maxBodyBytes ?? 262_144), 2 * 1024 * 1024))
    const method = options.method === 'HEAD' ? 'HEAD' : 'GET'
    const startedAt = Date.now()
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), timeoutMs)
    const onSignal = () => controller.abort()
    input.env.signal?.addEventListener('abort', onSignal, { once: true })
    try {
      const response = await fetch(url, { method, redirect: 'manual', signal: controller.signal, headers: { 'user-agent': 'ArmorBreak/1.0 (authorized security research)' } })
      const bytes = method === 'HEAD' ? Buffer.alloc(0) : Buffer.from(await response.arrayBuffer()).subarray(0, maxBodyBytes)
      const headers = redactHeaders(Object.fromEntries(response.headers.entries()))
      const excerpt = method === 'HEAD' ? '' : bytes.toString('utf8').replace(/[^\x09\x0a\x0d\x20-\x7e\u00a0-\uffff]/g, '').slice(0, 500)
      const location = response.headers.get('location')
      return {
        summary: `HTTP ${method} ${url.href} → ${response.status} ${response.statusText || ''}（${Date.now() - startedAt} ms，响应体 ${bytes.length} 字节${location ? `，重定向至 ${location}` : '，未跟随重定向'}）`,
        data: {
          url: url.href,
          method,
          status: response.status,
          statusText: response.statusText,
          headers,
          bodyBytes: bytes.length,
          bodySha256: sha256(bytes),
          excerpt,
          redirectLocation: location,
          durationMs: Date.now() - startedAt,
          requestSent: true,
        },
        evidence: [
          { title: `HTTP ${method} ${url.href} → ${response.status}`, kind: 'network-response', excerpt: `status=${response.status} headers=${JSON.stringify(headers).slice(0, 800)} bodyBytes=${bytes.length} sha256=${sha256(bytes)}` },
        ],
        findings: [],
        meta: { riskLevel: 'L2', approvalGated: true, redirectsFollowed: false },
      }
    } finally {
      clearTimeout(timer)
      input.env.signal?.removeEventListener('abort', onSignal)
    }
  },
}

/** @type {any} */
const containerExec = {
  id: 'live.container_exec',
  title: '隔离容器内受控执行（L1）',
  description:
    '在一次性、无网络、只读根文件系统的容器里运行一条命令并观察输出；样本目录只读挂载到 /sample。默认拒绝：需要可用的 Docker 守护进程 + 平台审批。用于授权样本的受控动态观察，不提供隐蔽/持久化/逃逸能力。',
  riskLevel: 'L1',
  targetKind: 'file',
  externalTools: ['docker'],
  params: {
    type: 'object',
    properties: {
      image: { type: 'string', description: 'Container image to use (must already be available locally or pullable in the approved environment).' },
      command: { type: 'array', items: { type: 'string' }, description: 'Command argv executed inside the container; the sample is at /sample/<filename>.' },
      timeoutMs: { type: 'number', description: 'Execution timeout in ms (default 30000, max 120000).' },
    },
    required: ['image', 'command'],
    additionalProperties: false,
  },
  async run(input) {
    const options = input.options ?? {}
    const image = String(options.image ?? '')
    const command = Array.isArray(options.command) ? options.command.map(String) : []
    if (!image) throw new Error('live.container_exec needs options.image (for example "alpine:3.20")')
    if (command.length === 0) throw new Error('live.container_exec needs options.command as an argv array')
    const samplePath = input.targetPath
    if (!samplePath) throw new Error('live.container_exec needs the sample file path as the analysis target')
    const sampleDir = dirname(samplePath)
    const sampleName = basename(samplePath)
    const timeoutMs = Math.max(1000, Math.min(Number(options.timeoutMs ?? 30_000), 120_000))
    const args = [
      'run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
      '--security-opt', 'no-new-privileges', '--pids-limit', '128', '--memory', '512m',
      '-v', `${sampleDir}:/sample:ro`, '-w', '/sample', image, ...command,
    ]
    const startedAt = Date.now()
    return new Promise((resolvePromise, reject) => {
      execFile(
        'docker',
        args,
        { timeout: timeoutMs, windowsHide: true, maxBuffer: 1024 * 1024, env: childEnv() },
        (error, stdout, stderr) => {
          if (error && /** @type {any} */ (error).code === 'ENOENT') {
            reject(new Error('Docker CLI is not installed; install Docker Desktop and pass its health check before using L1 dynamic analysis.'))
            return
          }
          const timedOut = Boolean(error && (/** @type {any} */ (error).killed || /** @type {any} */ (error).signal))
          const exitCode = error ? (typeof /** @type {any} */ (error).code === 'number' ? /** @type {any} */ (error).code : null) : 0
          const out = String(stdout ?? '').slice(0, 4000)
          const err = String(stderr ?? '').slice(0, 4000)
          const summary = timedOut
            ? `容器执行超时（${timeoutMs} ms）并被终止：image=${image} command=${command.join(' ')}`
            : `容器执行完成：exit=${exitCode} image=${image} command=${command.join(' ')}（stdout ${out.length} 字节，stderr ${err.length} 字节）`
          resolvePromise({
            summary,
            data: {
              image,
              command,
              sample: sampleName,
              exitCode,
              timedOut,
              stdoutExcerpt: out,
              stderrExcerpt: err,
              durationMs: Date.now() - startedAt,
              network: 'none',
              writes: 'blocked (read-only root, sample mounted ro)',
            },
            evidence: [
              { title: `container run ${image}`, kind: 'dynamic-execution', excerpt: `exit=${exitCode} timedOut=${timedOut} stdout=${out.slice(0, 500)} stderr=${err.slice(0, 500)}`, meta: { image, command: command.slice(0, 20) } },
            ],
            findings: timedOut
              ? [{ title: '样本在隔离容器中超出执行预算', severity: 'info', description: `命令在 ${timeoutMs} ms 内未结束，可能为阻塞/守护型行为；需人工复核。`, verification: 'hypothesis', method: 'container execution timeout', cwe: null, cvss: null, remediation: '提高预算前先确认样本预期行为；不要在生产主机执行。', target: sampleName, evidence: [{ title: 'timeout', excerpt: `timeoutMs=${timeoutMs}` }] }]
              : [],
            meta: { riskLevel: 'L1', approvalGated: true, isolation: 'docker' },
          })
        },
      )
    })
  },
}

export default {
  domain: 'live',
  capabilities: [httpProbe, containerExec],
}
