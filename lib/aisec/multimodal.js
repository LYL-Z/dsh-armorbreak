/**
 * AB2-M3-08 multimodal risk fixtures.
 *
 * No OCR/PDF/audio runtime is bundled. If the modality runtime is unavailable,
 * the result is SKIPPED (never PASS). Extracted text remains untrusted content
 * and cannot authorize tools.
 */
import { assessKnowledge } from '../knowledge/guard.js'

export const MODALITIES = Object.freeze(['image-ocr', 'pdf-text', 'audio-transcript'])

export function runMultimodalCase(input) {
  if (!MODALITIES.includes(input?.modality)) throw new Error(`unsupported modality: ${input?.modality}`)
  if (input.runtimeAvailable !== true) {
    return {
      schemaVersion: 'armorbreak.multimodal-result/v1',
      modality: input.modality,
      verdict: 'SKIPPED',
      reason: `missing modality runtime: ${input.modality}`,
      executionAllowed: false,
      rawIncluded: false,
    }
  }
  const assessment = assessKnowledge(input.content ?? '', { uri: input.uri, source: input.modality })
  return {
    schemaVersion: 'armorbreak.multimodal-result/v1',
    modality: input.modality,
    verdict: assessment.trusted ? 'PASS' : 'FAIL',
    flags: assessment.flags,
    executionAllowed: false,
    instruction: assessment.instruction,
    excerpt: assessment.excerpt,
    rawIncluded: false,
  }
}
