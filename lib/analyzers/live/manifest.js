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
import { createHash, randomUUID } from 'node:crypto'
import { lookup as dnsLookupCallback } from 'node:dns'
import { request as httpRequest } from 'node:http'
import { request as httpsRequest } from 'node:https'
import { isIP } from 'node:net'
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
    input.env?.signal?.addEventListener('abort', onSignal, { once: true })
    const resolvedIps = Array.isArray(input.env?.networkPolicy?.resolvedIps)
      ? input.env.networkPolicy.resolvedIps.filter((ip) => typeof ip === 'string' && isIP(ip) !== 0)
      : []
    // Pin the connection to the addresses the policy engine validated. Without
    // this, fetch()/request() would re-resolve and a rebinding answer could move
    // the connection to an address that was never checked.
    const pinnedLookup = (/** @type {string} */ hostname, /** @type {any} */ lookupOptions, /** @type {Function} */ callback) => {
      if (resolvedIps.length === 0) {
        dnsLookupCallback(hostname, lookupOptions, callback)
        return
      }
      const ip = resolvedIps.find((item) => isIP(item) === 4) ?? resolvedIps[0]
      const family = isIP(ip)
      if (lookupOptions && lookupOptions.all) callback(null, [{ address: ip, family }])
      else callback(null, ip, family)
    }
    try {
      const response = await new Promise((resolvePromise, rejectPromise) => {
        const transport = url.protocol === 'https:' ? httpsRequest : httpRequest
        const req = transport({
          protocol: url.protocol,
          hostname: url.hostname.replace(/^\[|\]$/g, ''),
          port: url.port || (url.protocol === 'https:' ? 443 : 80),
          path: `${url.pathname}${url.search}`,
          method,
          headers: {
            'user-agent': 'ArmorBreak/1.1 (authorized security research)',
            accept: '*/*',
            host: url.host,
          },
          lookup: pinnedLookup,
          servername: isIP(url.hostname) === 0 ? url.hostname : undefined,
          signal: controller.signal,
          timeout: timeoutMs,
          rejectUnauthorized: true,
        }, (res) => {
          const chunks = []
          let total = 0
          let truncated = false
          res.on('data', (chunk) => {
            if (truncated) return
            const remaining = maxBodyBytes - total
            if (chunk.length > remaining) {
              if (remaining > 0) chunks.push(chunk.subarray(0, remaining))
              total += Math.max(0, remaining)
              truncated = true
              res.destroy()
              resolvePromise({
                status: res.statusCode ?? 0,
                statusText: res.statusMessage ?? '',
                headers: res.headers,
                body: Buffer.concat(chunks),
                truncated: true,
                location: typeof res.headers.location === 'string' ? res.headers.location : null,
              })
              return
            }
            chunks.push(chunk)
            total += chunk.length
          })
          res.on('end', () => resolvePromise({
            status: res.statusCode ?? 0,
            statusText: res.statusMessage ?? '',
            headers: res.headers,
            body: Buffer.concat(chunks),
            truncated,
            location: typeof res.headers.location === 'string' ? res.headers.location : null,
          }))
          res.on('error', rejectPromise)
        })
        req.on('timeout', () => controller.abort())
        req.on('error', (error) => rejectPromise(error))
        req.end()
      })
      const headers = redactHeaders(response.headers)
      const bytes = method === 'HEAD' ? Buffer.alloc(0) : response.body.subarray(0, maxBodyBytes)
      const excerpt = method === 'HEAD' ? '' : bytes.toString('utf8').replace(/[^\x09\x0a\x0d\x20-\x7e\u00a0-\uffff]/g, '').slice(0, 500)
      return {
        summary: `HTTP ${method} ${url.href} → ${response.status} ${response.statusText || ''}（${Date.now() - startedAt} ms，响应体 ${bytes.length} 字节${response.truncated ? '，已截断' : ''}${response.location ? `，重定向至 ${response.location}（未跟随）` : ''}）`,
        data: {
          url: url.href,
          method,
          status: response.status,
          statusText: response.statusText,
          headers,
          bodyBytes: bytes.length,
          bodyTruncated: response.truncated,
          maxBodyBytes,
          bodySha256: sha256(bytes),
          excerpt,
          redirectLocation: response.location,
          redirectsFollowed: false,
          pinnedIp: resolvedIps[0] ?? null,
          durationMs: Date.now() - startedAt,
          requestSent: true,
        },
        evidence: [
          { title: `HTTP ${method} ${url.href} → ${response.status}`, kind: 'network-response', excerpt: `status=${response.status} headers=${JSON.stringify(headers).slice(0, 800)} bodyBytes=${bytes.length} truncated=${response.truncated} sha256=${sha256(bytes)}` },
        ],
        findings: [],
        meta: { riskLevel: 'L2', approvalGated: true, redirectsFollowed: false, connectionPinned: resolvedIps.length > 0 },
      }
    } catch (error) {
      if (controller.signal.aborted) throw new Error(`live.http_probe cancelled or timed out after ${timeoutMs} ms`)
      throw new Error(`live.http_probe failed: ${error?.code ?? 'request-error'} ${error?.message ?? error}`)
    } finally {
      clearTimeout(timer)
      input.env?.signal?.removeEventListener('abort', onSignal)
    }
  },
}

/** Container images that may be used for L1 dynamic analysis (name allowlist). */
export const CONTAINER_IMAGE_ALLOWLIST = Object.freeze(['alpine', 'busybox', 'debian', 'ubuntu', 'python', 'node'])

/**
 * Validate a digest-pinned container image. Mutable tags are rejected because
 * they can silently change the code that runs on a sample.
 * @param {string} image
 */
export function validateContainerImage(image) {
  const text = String(image ?? '').trim()
  const match = text.match(/^([a-z0-9][a-z0-9._/-]*(?::[a-z0-9._-]+)?)@sha256:[a-f0-9]{64}$/)
  if (!match) {
    throw new Error('container image must be digest-pinned as repository@sha256:<64 hex>; mutable tags are rejected for L1 execution')
  }
  const repository = match[1]
  const last = repository.split('/').pop() ?? ''
  const name = last.split(':')[0]
  if (!CONTAINER_IMAGE_ALLOWLIST.includes(name)) {
    throw new Error(`container image is not on the L1 allowlist (${CONTAINER_IMAGE_ALLOWLIST.join(', ')}): ${name}`)
  }
  return { image: text, repository, name }
}

/**
 * Build the hardened `docker run` argv. Exported for unit tests; every flag here
 * is part of the isolation contract.
 * @param {{image: string, command: string[], sampleDir: string, runId: string}} input
 */
export function buildContainerArgs(input) {
  const { image, command, sampleDir, runId } = input
  return [
    'run', '--rm', '--pull', 'never', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges', '--pids-limit', '128', '--memory', '512m', '--cpus', '1',
    '--user', '65534:65534',
    '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m',
    '--label', `armorbreak.run=${runId}`,
    '--name', `armorbreak-${runId}`,
    '-v', `${sampleDir}:/sample:ro`, '-w', '/sample', image, ...command,
  ]
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
      image: { type: 'string', description: 'Digest-pinned container image (repository@sha256:<64 hex>). Mutable tags are rejected; the image name must be on the L1 allowlist and must already exist locally (no automatic pull).' },
      command: { type: 'array', items: { type: 'string' }, description: 'Command argv executed inside the container; the sample is at /sample/<filename>. Max 64 args, each ≤ 512 chars.' },
      timeoutMs: { type: 'number', description: 'Execution timeout in ms (default 30000, max 120000).' },
    },
    required: ['image', 'command'],
    additionalProperties: false,
  },
  async run(input) {
    const options = input.options ?? {}
    const command = Array.isArray(options.command) ? options.command.map(String) : []
    if (command.length === 0) throw new Error('live.container_exec needs options.command as an argv array')
    if (command.length > 64 || command.some((item) => item.length > 512)) throw new Error('live.container_exec command exceeds the bounded argv policy (max 64 args, 512 chars each)')
    const validated = validateContainerImage(String(options.image ?? ''))
    const image = validated.image
    const samplePath = input.targetPath
    if (!samplePath) throw new Error('live.container_exec needs the sample file path as the analysis target')
    const sampleDir = dirname(samplePath)
    const sampleName = basename(samplePath)
    const timeoutMs = Math.max(1000, Math.min(Number(options.timeoutMs ?? 30_000), 120_000))
    const runId = randomUUID().slice(0, 12)
    const args = buildContainerArgs({ image, command, sampleDir, runId })
    const containerName = `armorbreak-${runId}`
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
          if (timedOut) {
            // The docker CLI may have been killed before removing the container;
            // best-effort cleanup, recorded in the result either way.
            execFile('docker', ['rm', '-f', containerName], { timeout: 15_000, windowsHide: true, env: childEnv() }, () => {})
          }
          const exitCode = error ? (typeof /** @type {any} */ (error).code === 'number' ? /** @type {any} */ (error).code : null) : 0
          const out = String(stdout ?? '').slice(0, 4000)
          const err = String(stderr ?? '').slice(0, 4000)
          const summary = timedOut
            ? `容器执行超时（${timeoutMs} ms）并被终止：image=${image} command=${command.join(' ')}（已请求清理 ${containerName}）`
            : `容器执行完成：exit=${exitCode} image=${image} command=${command.join(' ')}（stdout ${out.length} 字节，stderr ${err.length} 字节）`
          resolvePromise({
            summary,
            data: {
              image,
              imageDigestVerified: true,
              containerName,
              command,
              sample: sampleName,
              exitCode,
              timedOut,
              cleanupRequested: timedOut,
              stdoutExcerpt: out,
              stderrExcerpt: err,
              durationMs: Date.now() - startedAt,
              network: 'none',
              user: '65534:65534',
              writes: 'blocked (read-only root, tmpfs only, sample mounted ro)',
            },
            evidence: [
              { title: `container run ${image}`, kind: 'dynamic-execution', excerpt: `exit=${exitCode} timedOut=${timedOut} container=${containerName} stdout=${out.slice(0, 500)} stderr=${err.slice(0, 500)}`, meta: { image, command: command.slice(0, 20) } },
            ],
            findings: timedOut
              ? [{ title: '样本在隔离容器中超出执行预算', severity: 'info', description: `命令在 ${timeoutMs} ms 内未结束，可能为阻塞/守护型行为；需人工复核。`, verification: 'hypothesis', method: 'container execution timeout', cwe: null, cvss: null, remediation: '提高预算前先确认样本预期行为；不要在生产主机执行。', target: sampleName, evidence: [{ title: 'timeout', excerpt: `timeoutMs=${timeoutMs} container=${containerName}` }] }]
              : [],
            meta: { riskLevel: 'L1', approvalGated: true, isolation: 'docker', imagePinned: true },
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
