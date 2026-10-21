/**
 * AB2-M3-07 JailbreakBench-style dataset boundary.
 *
 * Only aggregate statistics and fingerprints leave this module; raw harmful
 * records are never included in a report. Dataset use requires explicit
 * authorization/license metadata and a fixed fingerprint.
 */
import { createHash } from 'node:crypto'

const REQUIRED_FIELDS = ['id', 'category']

export function validateDataset(dataset) {
  const errors = []
  if (!dataset || typeof dataset !== 'object') return { valid: false, errors: ['dataset must be an object'] }
  if (dataset.authorized !== true) errors.push('dataset is not operator-authorized')
  if (!String(dataset.license ?? '').trim()) errors.push('dataset license is required')
  if (!String(dataset.source ?? '').trim()) errors.push('dataset source is required')
  if (!Array.isArray(dataset.records) || dataset.records.length === 0) errors.push('records must be non-empty')
  for (const [index, record] of (dataset.records ?? []).entries()) {
    for (const field of REQUIRED_FIELDS) if (!String(record?.[field] ?? '').trim()) errors.push(`records[${index}].${field} required`)
  }
  return { valid: errors.length === 0, errors }
}

export function datasetFingerprintRecords(records) {
  return createHash('sha256').update(JSON.stringify(records.map((record) => ({ id: record.id, category: record.category, hash: record.promptHash ?? null })))).digest('hex')
}

/** Returns aggregate-only output; no raw prompt/response fields. */
export function aggregateDataset(dataset) {
  const check = validateDataset(dataset)
  if (!check.valid) throw new Error(`dataset rejected: ${check.errors.join('; ')}`)
  const categories = {}
  let rawFieldCount = 0
  for (const record of dataset.records) {
    categories[record.category] = (categories[record.category] ?? 0) + 1
    if (record.prompt || record.response || record.output) rawFieldCount += 1
  }
  return {
    schemaVersion: 'armorbreak.jailbreak-aggregate/v1',
    source: String(dataset.source),
    license: String(dataset.license),
    fingerprint: datasetFingerprintRecords(dataset.records),
    recordCount: dataset.records.length,
    categories,
    rawPayloadsIncluded: false,
    rawPayloadRecordCount: rawFieldCount,
    policy: 'RAW_HARMFUL_CONTENT_NEVER_EXPORTED',
  }
}
