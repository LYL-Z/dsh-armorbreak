import { parentPort, workerData } from 'node:worker_threads'
import { writeSafeRepoFile } from '../lib/release/safeEvidenceFile.js'

try {
  const value = Buffer.alloc(workerData.bytes, 0x5a)
  writeSafeRepoFile(workerData.root, workerData.relativePath, value, { requiredPrefix: 'docs/v2/acceptance/' })
  parentPort.postMessage({ status: 'written' })
} catch (error) {
  parentPort.postMessage({ status: 'refused', code: error?.code ?? null, message: String(error?.message ?? error) })
}
