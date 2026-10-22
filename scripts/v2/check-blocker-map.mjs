#!/usr/bin/env node
/** Ensure every GA acceptance blocker has a unique root cause and derived items are marked. */
import { readFileSync } from 'node:fs'

const readiness = JSON.parse(readFileSync('docs/v2/acceptance/v2.2-readiness.json', 'utf8'))
const map = JSON.parse(readFileSync('docs/v2/acceptance/blocker-map.json', 'utf8'))
const current = readiness.gaBlockers.map((blocker) => blocker.code)
const mapped = new Map(map.blockers.map((blocker) => [blocker.code, blocker]))
const missing = current.filter((code) => !mapped.has(code) || !mapped.get(code).rootCause)
const orphan = [...mapped.keys()].filter((code) => !current.includes(code))
const ids = map.rootCauses.map((cause) => cause.id)
if (new Set(ids).size !== ids.length) missing.push('duplicate rootCause id')
if (missing.length) {
  console.error(JSON.stringify({ result: 'FAIL', missing }, null, 2))
  process.exitCode = 1
} else {
  if (orphan.length) console.warn(JSON.stringify({ staleMappedBlockers: orphan }))
  console.log(JSON.stringify({
    result: 'PASS', acceptanceBlockers: current.length,
    uniqueRootCauses: map.rootCauses.filter((cause) => !cause.derived).length,
    derivedBlockers: map.blockers.filter((blocker) => blocker.derived).length,
    staleMappedBlockers: orphan,
  }, null, 2))
}
