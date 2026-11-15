import { reviewAssessment } from '../../integrations/assessmentReview.js'
import { correlateAssets } from '../../integrations/assetCorrelation.js'
export default { domain: 'assessment', capabilities: [{
  id: 'assessment.review', title: 'Offline assessment claim review', riskLevel: 'L0', targetKind: 'file',
  description: 'Validate bounded local claim hashes and reference graphs, then reuse security correlation without trusting source authority or executing commands.',
  params: { type: 'object', properties: {}, additionalProperties: false },
  async run(input) {
    if (input.env?.targetTruncated || Object.keys(input.options ?? {}).length) throw new Error('complete assessment input and no options required')
    return reviewAssessment(input.buffer)
  },
}, {
  id: 'assessment.assets', title: 'Offline imported asset correlation', riskLevel: 'L0', targetKind: 'file',
  description: 'Relate imported domain/IP/CIDR/service/certificate claims without external observation or execution.',
  params: { type: 'object', properties: {}, additionalProperties: false },
  async run(input) {
    if (input.env?.targetTruncated || Object.keys(input.options ?? {}).length) throw new Error('complete offline asset input and no options required')
    return correlateAssets(input.buffer)
  },
}] }
