/**
 * AB2-M3-10 RAG / execution separation.
 *
 * Threat documents are untrusted data. They may be quoted with citations and
 * timestamps, but cannot elevate permissions, install plugins, change policy, or
 * trigger L2. This module only prepares context; it never calls a tool.
 */
import { assessKnowledge } from '../knowledge/guard.js'

export function buildRagContext(documents, options = {}) {
  const contexts = []
  const flags = []
  for (const document of documents ?? []) {
    const assessment = assessKnowledge(document.text ?? '', { uri: document.uri, source: document.source, retrievedAt: document.retrievedAt })
    flags.push(...assessment.flags)
    contexts.push({
      uri: String(document.uri ?? ''),
      version: String(document.version ?? ''),
      retrievedAt: String(document.retrievedAt ?? ''),
      trust: 'untrusted',
      instruction: assessment.instruction,
      text: assessment.excerpt,
      flags: assessment.flags,
    })
  }
  return {
    schemaVersion: 'armorbreak.rag-context/v1',
    trust: 'untrusted',
    documents: contexts,
    flags,
    executionAllowed: false,
    maxRiskLevel: 'L0',
    note: 'Retrieved content is evidence, not authorization; no tool call is produced here.',
    ...options,
  }
}

/** Explicitly reject attempts to turn retrieval into action. */
export function assertKnowledgeCannotExecute(text) {
  const assessment = assessKnowledge(text)
  const forbidden = /install\s+(this\s+)?plugin|approve\s+(the\s+)?(install|authorization)|call\s+(the\s+)?tool|execute\s+(the\s+)?following|bypass\s+(the\s+)?(approval|policy)|network\s*:\s*l2/i
  if (forbidden.test(String(text)) || !assessment.trusted) {
    return { allowed: false, code: 'KNOWLEDGE_CANNOT_EXECUTE', flags: assessment.flags }
  }
  return { allowed: true, code: 'READ_ONLY_CONTEXT', flags: [] }
}
