import { parentPort, workerData } from 'node:worker_threads'

if (!parentPort) throw new Error('search regex worker requires a worker parent')

let expression
try {
  expression = new RegExp(workerData.pattern, 'i')
  parentPort.postMessage({ type: 'ready' })
} catch (error) {
  parentPort.postMessage({ type: 'invalid', reason: String(error?.message ?? error) })
}

if (expression) {
  parentPort.on('message', (message) => {
    if (message?.type !== 'match') return
    const matches = []
    const lines = message.text.split(/\r?\n/)
    for (let index = 0; index < lines.length; index += 1) {
      if (expression.test(lines[index])) {
        matches.push(index)
        if (matches.length >= message.maxMatches) break
      }
    }
    parentPort.postMessage({ type: 'matches', id: message.id, lineIndexes: matches })
  })
}
