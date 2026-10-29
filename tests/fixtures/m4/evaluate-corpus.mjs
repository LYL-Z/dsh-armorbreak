import { scanSource } from '../../../lib/analyzers/sast/scanner.js'

export function evaluateVulnerabilityContrastCorpus(corpus) {
  const totals = { tp: 0, fp: 0, fn: 0, tn: 0, samples: 0 }
  const byCategory = new Map()
  const cases = []
  for (const group of corpus) {
    const category = byCategory.get(group.cwe) ?? { tp: 0, fp: 0, fn: 0, tn: 0, samples: 0 }
    const extension = group.language === 'python' ? '.py' : '.js'
    for (const [variant, sample] of Object.entries(group.variants)) {
      const result = scanSource({ path: `${group.id}-${variant}${extension}`, buffer: Buffer.from(sample.source) })
      const detections = result.findings.filter((finding) => finding.cwe === group.cwe)
      const detected = detections.length > 0
      const vulnerable = sample.groundTruth === 'vulnerable'
      const key = vulnerable ? detected ? 'tp' : 'fn' : detected ? 'fp' : 'tn'
      totals[key] += 1
      category[key] += 1
      totals.samples += 1
      category.samples += 1
      cases.push({
        id: group.id,
        cwe: group.cwe,
        variant,
        groundTruth: sample.groundTruth,
        detected,
        findings: detections.map((finding) => ({ title: finding.title, ruleId: finding.evidence?.[0]?.meta?.ruleId ?? null, verification: finding.verification })),
      })
    }
    byCategory.set(group.cwe, category)
  }
  const withRates = (values) => ({
    ...values,
    precision: values.tp + values.fp ? values.tp / (values.tp + values.fp) : null,
    recall: values.tp + values.fn ? values.tp / (values.tp + values.fn) : null,
    falsePositiveRate: values.fp + values.tn ? values.fp / (values.fp + values.tn) : null,
  })
  return {
    totals: withRates(totals),
    byCategory: Object.fromEntries([...byCategory.entries()].sort(([left], [right]) => left.localeCompare(right)).map(([cwe, value]) => [cwe, withRates(value)])),
    cases,
  }
}

export default { evaluateVulnerabilityContrastCorpus }
