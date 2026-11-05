/**
 * Bounded, offline behavior-contract preparation and differential comparison.
 * These capabilities consume evidence/results supplied by the caller; they
 * never compile, launch, or otherwise execute a target implementation.
 */
import { createHash } from 'node:crypto'
import { checkAbort, makeEvidence, makeMeta } from '../binary/util.js'
import { redactText, sanitizeText, sha256 } from '../../../packages/core/src/util.js'

const MAX_INPUT_BYTES = 4 * 1024 * 1024
const MAX_CASES = 300
const MAX_OBSERVATIONS = 300
const MAX_OUTPUT_BYTES = 220 * 1024
const MAX_DEPTH = 32
const MAX_COLLECTION_ITEMS = 3000
const ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,119}$/
const CERTAINTY = new Set(['observed', 'inferred', 'unknown'])
const CASE_STATUSES = new Set(['complete', 'timeout', 'nondeterministic', 'unavailable', 'inconclusive'])
const ABSOLUTE_PATH_TEXT = /\b[A-Za-z]:[\\/][^\s"'<>|]+|\\\\[^\\/\s]+[\\/][^\s"'<>|]+|\/(?:Users|home|tmp|var|opt|workspace|private|mnt|root)\/[^\s"'<>|]+/gi

function cleanText(value, max = 1000) {
  return redactText(sanitizeText(String(value ?? ''), max))
    .replace(ABSOLUTE_PATH_TEXT, (path) => `[REDACTED_PATH:${sha256(path.toLowerCase()).slice(0, 12)}]`)
    .replace(/[\r\n\t ]+/g, ' ').trim()
}

function parseInput(input, expectedSchema) {
  if (!Buffer.isBuffer(input.buffer) || input.buffer.length === 0) throw new Error(`${expectedSchema} requires a non-empty local JSON file`)
  if (input.buffer.length > MAX_INPUT_BYTES) throw new Error(`input exceeds ${MAX_INPUT_BYTES} bytes`)
  if (input.env?.targetTruncated) throw new Error('Core truncated the input; retry with a larger bounded input allowance')
  let bundle
  try { bundle = JSON.parse(input.buffer.toString('utf8')) }
  catch { throw new Error('input is not valid UTF-8 JSON') }
  if (!bundle || bundle.schema !== expectedSchema) throw new Error(`schema must be ${expectedSchema}`)
  const allowed = expectedSchema === 'armorbreak.behavior-contract-source/v1'
    ? ['schema', 'artifact', 'observations']
    : ['schema', 'artifact', 'implementations', 'coverageScope', 'cases']
  rejectUnknown(bundle, allowed, 'bundle')
  return bundle
}

function rejectUnknown(value, allowed, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be an object`)
  const unknown = Object.keys(value).filter((key) => !allowed.includes(key))
  if (unknown.length) throw new Error(`${label} contains unsupported field: ${cleanText(unknown[0], 120)}`)
}

function validId(value, label) {
  const id = cleanText(value, 120)
  if (!ID.test(id)) throw new Error(`${label} must be a stable non-empty identifier (max 120 characters)`)
  return id
}

function stringList(value, label, maxItems = 50, maxText = 500) {
  if (value === undefined) return []
  if (!Array.isArray(value) || value.length > maxItems) throw new Error(`${label} must be an array of at most ${maxItems} strings`)
  return value.map((item, index) => {
    if (typeof item !== 'string' || !item.trim()) throw new Error(`${label}[${index}] must be a non-empty string`)
    return cleanText(item, maxText)
  })
}

function stableSerialize(value, depth = 0) {
  if (depth > MAX_DEPTH) throw new Error(`result JSON exceeds the maximum depth of ${MAX_DEPTH}`)
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) {
    if (value.length > MAX_COLLECTION_ITEMS) throw new Error(`result array exceeds ${MAX_COLLECTION_ITEMS} items`)
    return `[${value.map((item) => stableSerialize(item, depth + 1)).join(',')}]`
  }
  const keys = Object.keys(value).sort()
  if (keys.length > MAX_COLLECTION_ITEMS) throw new Error(`result object exceeds ${MAX_COLLECTION_ITEMS} properties`)
  return `{${keys.map((key) => `${JSON.stringify(key)}:${stableSerialize(value[key], depth + 1)}`).join(',')}}`
}

function jsonPointerPart(value) {
  return cleanText(String(value).replace(/~/g, '~0').replace(/\//g, '~1'), 120)
}

function collectDifferencePaths(left, right, path = '', out = [], depth = 0) {
  if (out.length >= 20 || depth > 20) return out
  if (Object.is(left, right)) return out
  if (!left || !right || typeof left !== 'object' || typeof right !== 'object' || Array.isArray(left) !== Array.isArray(right)) {
    out.push(path || '/')
    return out
  }
  if (Array.isArray(left)) {
    const length = Math.max(left.length, right.length)
    for (let index = 0; index < length && out.length < 20; index += 1) {
      if (index >= left.length || index >= right.length) out.push(`${path}/${index}`)
      else collectDifferencePaths(left[index], right[index], `${path}/${index}`, out, depth + 1)
    }
    return out
  }
  const keys = [...new Set([...Object.keys(left), ...Object.keys(right)])].sort()
  for (const key of keys) {
    if (out.length >= 20) break
    const child = `${path}/${jsonPointerPart(key)}`
    if (!Object.hasOwn(left, key) || !Object.hasOwn(right, key)) out.push(child)
    else collectDifferencePaths(left[key], right[key], child, out, depth + 1)
  }
  return out
}

function evidenceRefs(side, label) {
  const refs = stringList(side.evidenceRefs, `${label}.evidenceRefs`, 20, 200)
  return refs.map((ref, index) => validId(ref, `${label}.evidenceRefs[${index}]`))
}

function buildContract(input) {
  const bundle = parseInput(input, 'armorbreak.behavior-contract-source/v1')
  rejectUnknown(bundle.artifact, ['sha256'], 'artifact')
  if (typeof bundle.artifact?.sha256 !== 'string' || !/^[a-f0-9]{64}$/i.test(bundle.artifact.sha256)) throw new Error('artifact.sha256 must be a 64-character SHA-256 digest')
  if (!Array.isArray(bundle.observations) || bundle.observations.length > MAX_OBSERVATIONS) throw new Error(`observations must contain at most ${MAX_OBSERVATIONS} items`)
  const ids = new Set()
  const observations = bundle.observations.map((raw, index) => {
    rejectUnknown(raw, ['id', 'kind', 'statement', 'certainty', 'evidenceRefs', 'preconditions', 'inputs', 'outputs', 'errors', 'sideEffects'], `observations[${index}]`)
    const id = validId(raw?.id, `observations[${index}].id`)
    if (ids.has(id)) throw new Error(`duplicate observation id: ${id}`)
    ids.add(id)
    const kind = cleanText(raw?.kind, 40).toLowerCase()
    if (!['signature', 'api', 'cli', 'test', 'state-transition', 'error', 'constraint'].includes(kind)) throw new Error(`observations[${index}].kind is unsupported`)
    const certainty = CERTAINTY.has(raw?.certainty) ? raw.certainty : null
    if (!certainty) throw new Error(`observations[${index}].certainty must be observed, inferred, or unknown`)
    const statement = cleanText(raw?.statement, 2000)
    if (!statement) throw new Error(`observations[${index}].statement is required`)
    const evidenceRefs = stringList(raw?.evidenceRefs, `observations[${index}].evidenceRefs`, 20, 200)
    if (evidenceRefs.length === 0) throw new Error(`observations[${index}] requires at least one evidence reference`)
    return {
      id,
      kind,
      statement,
      certainty,
      evidenceRefs: evidenceRefs.map((ref, refIndex) => validId(ref, `observations[${index}].evidenceRefs[${refIndex}]`)),
      preconditions: stringList(raw?.preconditions, `observations[${index}].preconditions`),
      inputs: stringList(raw?.inputs, `observations[${index}].inputs`),
      outputs: stringList(raw?.outputs, `observations[${index}].outputs`),
      errors: stringList(raw?.errors, `observations[${index}].errors`),
      sideEffects: stringList(raw?.sideEffects, `observations[${index}].sideEffects`),
    }
  })
  const data = {
    schema: 'armorbreak.behavior-contract/v1',
    artifactSha256: bundle.artifact.sha256.toLowerCase(),
    observationCount: observations.length,
    observedCount: observations.filter((item) => item.certainty === 'observed').length,
    inferredCount: observations.filter((item) => item.certainty === 'inferred').length,
    unknownCount: observations.filter((item) => item.certainty === 'unknown').length,
    reviewStatus: 'not_independently_validated',
    observations,
    limitations: ['Only caller-supplied observations are normalized; ArmorBreak does not parse arbitrary source into a complete behavior specification.', 'Certainty labels and evidence references are supplied claims and are not independently authenticated.', 'No implementation is executed and no global equivalence claim is made.'],
  }
  return data
}

function compareBundle(input) {
  const bundle = parseInput(input, 'armorbreak.behavior-comparison-bundle/v1')
  rejectUnknown(bundle.artifact, ['sha256'], 'artifact')
  rejectUnknown(bundle.implementations, ['reference', 'candidate'], 'implementations')
  if (typeof bundle.artifact?.sha256 !== 'string' || !/^[a-f0-9]{64}$/i.test(bundle.artifact.sha256)) throw new Error('artifact.sha256 must be a 64-character SHA-256 digest')
  const coverageScope = cleanText(bundle.coverageScope, 1000)
  if (!coverageScope) throw new Error('coverageScope is required and must describe the finite case set')
  if (!Array.isArray(bundle.cases) || bundle.cases.length === 0 || bundle.cases.length > MAX_CASES) throw new Error(`cases must contain 1-${MAX_CASES} items`)
  const ids = new Set()
  const cases = bundle.cases.map((item, index) => {
    rejectUnknown(item, ['id', 'inputSha256', 'environmentComparable', 'reference', 'candidate'], `cases[${index}]`)
    rejectUnknown(item?.reference, ['status', 'value', 'evidenceRefs'], `cases[${index}].reference`)
    rejectUnknown(item?.candidate, ['status', 'value', 'evidenceRefs'], `cases[${index}].candidate`)
    const id = validId(item?.id, `cases[${index}].id`)
    if (ids.has(id)) throw new Error(`duplicate case id: ${id}`)
    ids.add(id)
    if (typeof item?.inputSha256 !== 'string' || !/^[a-f0-9]{64}$/i.test(item.inputSha256)) throw new Error(`cases[${index}].inputSha256 must be a 64-character SHA-256 digest`)
    const referenceStatus = CASE_STATUSES.has(item?.reference?.status) ? item.reference.status : 'unavailable'
    const candidateStatus = CASE_STATUSES.has(item?.candidate?.status) ? item.candidate.status : 'unavailable'
    const reference = { ...item.reference, status: referenceStatus }
    const candidate = { ...item.candidate, status: candidateStatus }
    const refs = { reference: evidenceRefs(reference, `cases[${index}].reference`), candidate: evidenceRefs(candidate, `cases[${index}].candidate`) }
    if (item?.environmentComparable === false) return { id, inputSha256: item.inputSha256.toLowerCase(), status: 'INCONCLUSIVE', reason: 'environment_not_comparable', referenceStatus, candidateStatus, evidenceRefs: refs }
    if (referenceStatus !== 'complete' || candidateStatus !== 'complete') return { id, inputSha256: item.inputSha256.toLowerCase(), status: 'INCONCLUSIVE', reason: 'result_incomplete_or_nondeterministic', referenceStatus, candidateStatus, evidenceRefs: refs }
    if (!Object.hasOwn(reference, 'value') || !Object.hasOwn(candidate, 'value')) return { id, inputSha256: item.inputSha256.toLowerCase(), status: 'INCONCLUSIVE', reason: 'result_value_missing', referenceStatus, candidateStatus, evidenceRefs: refs }
    if (refs.reference.length === 0 || refs.candidate.length === 0) return { id, inputSha256: item.inputSha256.toLowerCase(), status: 'INCONCLUSIVE', reason: 'result_evidence_missing', referenceStatus, candidateStatus, evidenceRefs: refs }
    const referenceJson = stableSerialize(reference.value)
    const candidateJson = stableSerialize(candidate.value)
    const equal = referenceJson === candidateJson
    return {
      id,
      inputSha256: item.inputSha256.toLowerCase(),
      status: equal ? 'PASS' : 'FAIL',
      reason: equal ? null : 'output_mismatch',
      referenceStatus,
      candidateStatus,
      referenceSha256: createHash('sha256').update(referenceJson).digest('hex'),
      candidateSha256: createHash('sha256').update(candidateJson).digest('hex'),
      referenceBytes: Buffer.byteLength(referenceJson),
      candidateBytes: Buffer.byteLength(candidateJson),
      differingPaths: equal ? [] : collectDifferencePaths(reference.value, candidate.value),
      evidenceRefs: refs,
    }
  })
  const casesPassed = cases.filter((item) => item.status === 'PASS').length
  const casesFailed = cases.filter((item) => item.status === 'FAIL').length
  const casesInconclusive = cases.filter((item) => item.status === 'INCONCLUSIVE').length
  const data = {
    schema: 'armorbreak.behavior-comparison/v1',
    artifactSha256: bundle.artifact.sha256.toLowerCase(),
    implementations: {
      reference: validId(bundle.implementations?.reference, 'implementations.reference'),
      candidate: validId(bundle.implementations?.candidate, 'implementations.candidate'),
    },
    casesTotal: cases.length,
    casesExecuted: casesPassed + casesFailed,
    casesCompared: casesPassed + casesFailed,
    casesPassed,
    casesFailed,
    casesInconclusive,
    coverageScope,
    equivalenceClaim: casesFailed > 0 ? 'MISMATCHES_FOUND' : casesPassed > 0 && casesInconclusive === 0 ? 'MATCHES_BOUNDED_SUPPLIED_CASES' : 'INSUFFICIENT_EVIDENCE',
    executionByArmorBreak: false,
    resultProvenance: 'caller_supplied_unverified_observations',
    cases,
    limitations: ['This capability compares already-produced result values; it does not run either implementation.', 'casesExecuted counts pairs of complete supplied results, not executions performed by ArmorBreak.', 'Caller-supplied output/evidence provenance is not independently authenticated.', 'A bounded case-set match is not a claim of global or state-space equivalence.'],
  }
  return data
}

function packageResult(capabilityId, input, data, artifactName) {
  const json = JSON.stringify(data, null, 2)
  if (Buffer.byteLength(json) > MAX_OUTPUT_BYTES) throw new Error(`result exceeds ${MAX_OUTPUT_BYTES} bytes; reduce observations/cases`)
  const summary = capabilityId === 'rebuild.contract'
    ? `规范化 ${data.observationCount} 条行为观察：observed=${data.observedCount}, inferred=${data.inferredCount}, unknown=${data.unknownCount}；未独立验证。`
    : `有限用例比较 ${data.casesCompared}/${data.casesTotal}：PASS=${data.casesPassed}, FAIL=${data.casesFailed}, INCONCLUSIVE=${data.casesInconclusive}；${data.equivalenceClaim}。未执行目标实现。`
  return {
    summary,
    findings: [],
    evidence: [makeEvidence(capabilityId === 'rebuild.contract' ? '行为契约输入摘要' : '行为对照摘要', 'behavioral-reconstruction', `${summary} inputSha256=${sha256(input.buffer)}`, { artifactSha256: data.artifactSha256, caseCount: data.casesTotal ?? data.observationCount, executionByArmorBreak: false })],
    data,
    artifacts: [{ name: artifactName, contentType: 'application/json', content: json }],
    meta: { ...makeMeta(capabilityId, 'behavioral-reconstruction', { analyzedBytes: input.buffer.length, source: 'local-precomputed-json', truncated: false }, []), inputSha256: sha256(input.buffer), executionByArmorBreak: false },
  }
}

export default {
  domain: 'rebuild',
  capabilities: [
    {
      id: 'rebuild.contract',
      title: '行为契约观察整理',
      description: '将明确授权来源中的 API/CLI/测试观察整理为带 observed/inferred/unknown 和 evidenceRefs 的有限契约；只规范化调用方提供的观察，不自动推断完整程序行为、不执行样本。',
      riskLevel: 'L0',
      targetKind: 'file',
      params: { type: 'object', properties: {}, additionalProperties: false },
      async run(input) {
        checkAbort(input.env, 'rebuild.contract')
        const data = buildContract(input)
        checkAbort(input.env, 'rebuild.contract')
        return packageResult('rebuild.contract', input, data, 'behavior-contract.json')
      },
    },
    {
      id: 'rebuild.compare',
      title: '有限用例行为差异比较',
      description: '比较两个已运行实现提供的 JSON 结果、输入哈希与证据引用；缺失/超时/随机或环境不匹配记为 INCONCLUSIVE。只比较预先生成的离线结果，不执行候选或参考程序。',
      riskLevel: 'L0',
      targetKind: 'file',
      params: { type: 'object', properties: {}, additionalProperties: false },
      async run(input) {
        checkAbort(input.env, 'rebuild.compare')
        const data = compareBundle(input)
        checkAbort(input.env, 'rebuild.compare')
        return packageResult('rebuild.compare', input, data, 'behavior-comparison.json')
      },
    },
  ],
}
