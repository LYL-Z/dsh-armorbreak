import { reviewAssessment } from '../../integrations/assessmentReview.js'
export default { domain: 'assessment', capabilities: [{
  id: 'assessment.review', title: 'Offline assessment claim review', riskLevel: 'L0', targetKind: 'file',
  description: 'Validate bounded local claim hashes and reference graphs, then reuse security correlation without trusting source authority or executing commands.',
  params: { type: 'object', properties: {}, additionalProperties: false },
  async run(input) {
    if (input.env?.targetTruncated || Object.keys(input.options ?? {}).length) throw new Error('complete assessment input and no options required')
    return reviewAssessment(input.buffer)
  },
}] }
