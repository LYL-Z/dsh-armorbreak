/**
 * AB2-M3-11 ResearchCampaign DAG.
 *
 * Standalone campaign runner with dependency ordering, cancellation, resume,
 * bounded retries and evidence deduplication. State is persisted atomically so a
 * new process can resume. It does not silently convert FAILED to DONE.
 */
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import { dirname } from 'node:path'

export class ResearchCampaign {
  /**
   * @param {{id:string, steps:Array<any>, stateFile?:string|null}} input
   */
  constructor(input) {
    this.id = input.id
    this.steps = input.steps ?? []
    this.stateFile = input.stateFile ?? null
    this.state = { schemaVersion: 'armorbreak.campaign/v1', campaignId: this.id, status: 'PENDING', steps: {}, evidence: [], startedAt: null, finishedAt: null, error: null }
    this.controller = null
    this.cancelled = false
  }

  validate() {
    const ids = new Set(this.steps.map((step) => step.id))
    for (const step of this.steps) {
      for (const dependency of step.dependsOn ?? []) if (!ids.has(dependency)) throw new Error(`step ${step.id} depends on unknown ${dependency}`)
    }
    return true
  }

  order() {
    const remaining = new Map(this.steps.map((step) => [step.id, step]))
    const done = new Set()
    const ordered = []
    while (remaining.size > 0) {
      const ready = [...remaining.values()].filter((step) => (step.dependsOn ?? []).every((dependency) => done.has(dependency)))
      if (ready.length === 0) throw new Error('campaign dependency cycle')
      for (const step of ready) {
        ordered.push(step)
        done.add(step.id)
        remaining.delete(step.id)
      }
    }
    return ordered
  }

  async load() {
    if (!this.stateFile) return this
    try {
      const state = JSON.parse(await readFile(this.stateFile, 'utf8'))
      if (state.campaignId === this.id) this.state = state
    } catch { /* first run */ }
    return this
  }

  async save() {
    if (!this.stateFile) return
    await mkdir(dirname(this.stateFile), { recursive: true })
    const tmp = `${this.stateFile}.${process.pid}.tmp`
    await writeFile(tmp, `${JSON.stringify(this.state, null, 2)}\n`)
    await rename(tmp, this.stateFile)
  }

  cancel() {
    this.cancelled = true
    this.controller?.abort()
  }

  /** @param {{execute:(step:any, context:any)=>Promise<any>, resume?:boolean}} input */
  async run(input) {
    this.validate()
    if (input.resume !== false) {
      this.cancelled = false
      await this.load()
    }
    for (const step of this.order()) {
      const existing = this.state.steps[step.id]
      if (existing?.status === 'DONE') continue
      if (this.cancelled) { this.state.status = 'CANCELLED'; break }
      const deps = step.dependsOn ?? []
      if (deps.some((dependency) => this.state.steps[dependency]?.status !== 'DONE')) {
        this.state.steps[step.id] = { status: 'BLOCKED', attempts: 0, evidenceIds: [] }
        continue
      }
      this.state.status = 'RUNNING'
      this.state.startedAt ??= new Date().toISOString()
      this.controller = new AbortController()
      const maxAttempts = Math.max(1, Math.min(Number(step.maxAttempts ?? 1), 5))
      let attempts = 0
      while (attempts < maxAttempts) {
        if (this.cancelled) break
        attempts += 1
        try {
          const result = await input.execute(step, { signal: this.controller.signal, attempt: attempts })
          const evidenceIds = this.dedupeEvidence(result?.evidence ?? [])
          this.state.steps[step.id] = { status: 'DONE', attempts, evidenceIds, finishedAt: new Date().toISOString(), output: result?.output ?? null }
          break
        } catch (error) {
          if (this.cancelled) {
            this.state.steps[step.id] = { status: 'CANCELLED', attempts, evidenceIds: [] }
            break
          }
          if (attempts >= maxAttempts) {
            this.state.steps[step.id] = { status: 'FAILED', attempts, error: String(error?.message ?? error).slice(0, 500), evidenceIds: [] }
          }
        }
      }
      if (this.cancelled) { this.state.status = 'CANCELLED'; await this.save(); break }
    }
    if (!this.cancelled) {
      const failed = Object.values(this.state.steps).some((step) => ['FAILED', 'BLOCKED'].includes(step.status))
      this.state.status = failed ? 'PARTIAL' : 'DONE'
      this.state.finishedAt = new Date().toISOString()
    }
    await this.save()
    return this.state
  }

  dedupeEvidence(items) {
    const ids = []
    for (const item of items) {
      const key = String(item.sha256 ?? item.id ?? JSON.stringify(item)).slice(0, 200)
      if (!this.state.evidence.some((entry) => entry.key === key)) {
        this.state.evidence.push({ key, sha256: item.sha256 ?? null, kind: item.kind ?? 'observation' })
        ids.push(key)
      } else {
        ids.push(key)
      }
    }
    return [...new Set(ids)]
  }
}
