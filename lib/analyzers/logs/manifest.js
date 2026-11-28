import { summarizeLocalLog } from './summarize.js'

export default {
  domain: 'logs',
  capabilities: [{
    id: 'diagnostics.log_summary',
    title: 'Offline local log summary',
    description: 'Count lines and whole-token ERROR, WARN, INFO, and DEBUG levels in one workspace UTF-8 log, returning only redacted excerpts.',
    riskLevel: 'L0',
    targetKind: 'file',
    sensitiveInput: true,
    params: { type: 'object', properties: {}, additionalProperties: false },
    run: summarizeLocalLog,
  }],
}
