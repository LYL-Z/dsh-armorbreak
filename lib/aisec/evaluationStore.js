/**
 * AB2-M4-01 persisted AISEC evaluation results for Workbench.
 * Each record is an immutable line; no raw harmful outputs are stored beyond the
 * bounded preview already produced by the evaluator.
 */
import { appendJsonl, readJsonl } from '../core/util.js'

export class EvaluationStore {
  constructor(file) {
    this.file = file
  }

  async append(result) {
    const record = { ...result, storedAt: new Date().toISOString() }
    await appendJsonl(this.file, record)
    return record
  }

  async list(limit = 20) {
    const records = await readJsonl(this.file, { limit: Math.max(1, Math.min(Number(limit) || 20, 100)) })
    return records.reverse()
  }
}
