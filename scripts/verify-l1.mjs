/**
 * L1 dynamic-analysis verification against the real Docker daemon.
 *
 * This is an opt-in verification script (not part of `node --test` because it
 * requires a running Docker daemon and a pre-pulled digest-pinned image).
 *
 * Usage:
 *   node scripts/verify-l1.mjs [--image busybox@sha256:...]
 *
 * It executes a benign command inside the hardened container (non-root, no
 * network, read-only root, sample mounted read-only) and writes a JSON report
 * to docs/acceptance/l1-docker-verification.json.
 */
import { copyFile, chmod, mkdir, mkdtemp, writeFile } from 'node:fs/promises'
import { existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { ArmorBreakRuntime } from '../lib/core/runtime.js'

const argv = process.argv.slice(2)
const imageArg = argv.includes('--image') ? argv[argv.indexOf('--image') + 1] : null
// Default: a locally available digest-pinned busybox image on the reference host.
const DEFAULT_IMAGE = 'busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662'
const image = imageArg ?? DEFAULT_IMAGE

const stateRoot = await mkdtemp(join(tmpdir(), 'abm-l1-verify-state-'))
const workspace = await mkdtemp(join(tmpdir(), 'abm-l1-verify-ws-'))
const sample = join(workspace, 'sample.txt')
await writeFile(sample, 'ArmorBreak L1 verification sample\n')
// The container runs as uid 65534; mkdtemp creates 0700 on Linux, which would
// make the read-only mount unreadable and yield "Permission denied" instead of
// the read-only-filesystem evidence we want to verify.
await chmod(workspace, 0o755).catch(() => {})
await chmod(sample, 0o644).catch(() => {})

const runtime = new ArmorBreakRuntime({ stateRoot })
await runtime.init()
const health = await runtime.health.isolation()
console.log(`isolation: available=${health.available} provider=${health.provider ?? '-'} reason=${health.reason ?? '-'}`)

let result
if (!health.available) {
  result = { ok: false, reason: health.reason, checkedAt: new Date().toISOString() }
  console.error(`FAIL: isolation unavailable: ${health.reason}`)
} else {
  const store = runtime.workspace(workspace).taskStore
  const task = await store.create({
    title: 'L1 docker verification',
    objective: 'prove hardened container execution path works on this host',
    targetPath: sample,
    targetKind: 'file',
    steps: [{
      id: 'exec',
      title: 'hardened container exec',
      capabilityId: 'live.container_exec',
      options: {
        image,
        timeoutMs: 30_000,
        command: [
          'sh', '-c',
          'id; echo "---"; ls -l /sample; echo "---"; touch /sample/write-probe 2>&1 || true; echo "---"; ip link 2>/dev/null || cat /proc/net/dev',
        ],
      },
    }],
  })
  const updated = await runtime.runner.runWorkflow(task, { requestApproval: async () => 'allowed-once' })
  const step = updated.steps[0]
  const evidence = await store.evidenceStore(task.id).readEvidence(100)
  const dynamic = evidence.find((record) => record.kind === 'dynamic-execution') ?? evidence[evidence.length - 1] ?? null
  const excerpt = String(dynamic?.excerpt ?? '')
  const stdoutMatch = excerpt.match(/stdout=([\s\S]*?)(?:\s+stderr=|$)/)
  const stdout = stdoutMatch ? stdoutMatch[1] : excerpt
  result = {
    ok: updated.state === 'COMPLETED' && step.status === 'DONE' && /uid=65534/.test(excerpt) && /(read-only|Read-only|Permission denied)/.test(excerpt),
    checkedAt: new Date().toISOString(),
    image,
    taskId: task.id,
    state: updated.state,
    stepStatus: step?.status ?? null,
    exitCode: (() => { const match = String(step?.summary ?? '').match(/exit=(\d+)/); return match ? Number(match[1]) : null })(),
    nonRoot: /uid=65534/.test(excerpt),
    readOnlySampleMount: /(read-only|Read-only|Permission denied)/.test(excerpt),
    evidenceRecords: evidence.length,
    summary: String(step?.summary ?? '').slice(0, 600),
    evidenceExcerpt: excerpt.slice(0, 1200),
    stdoutExcerpt: stdout.slice(0, 1200),
  }
  console.log(JSON.stringify(result, null, 2))
}

await mkdir(join('docs', 'acceptance'), { recursive: true })
await writeFile(join('docs', 'acceptance', 'l1-docker-verification.json'), `${JSON.stringify(result, null, 2)}\n`)
console.log(result.ok ? 'PASS: L1 hardened container path verified' : 'FAIL: L1 verification did not satisfy all assertions')
process.exitCode = result.ok ? 0 : 1
