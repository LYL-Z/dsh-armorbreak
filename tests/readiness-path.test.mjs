import assert from 'node:assert/strict'
import test from 'node:test'
import { HISTORICAL_FULL_GA_READINESS_PATH, readinessOutputPath, STABLE_PACKAGE_VERSION, STABLE_READINESS_PATH } from '../lib/release/readinessPath.js'

const stablePolicy = { schemaVersion: 'armorbreak.v2.2-stable-scope/v1', channel: 'stable', packageVersion: '2.2.0' }

test('V2.2 Stable writes its current readiness beside the preserved Full GA snapshot', () => {
  assert.equal(STABLE_PACKAGE_VERSION, '2.2.0')
  assert.equal(readinessOutputPath({ packageVersion: '2.2.0', stablePolicy }), STABLE_READINESS_PATH)
  assert.equal(readinessOutputPath({ packageVersion: '2.2.0' }), STABLE_READINESS_PATH)
})

test('RC packages retain the legacy readiness destination even when policy metadata is present', () => {
  assert.equal(readinessOutputPath({ packageVersion: '2.2.0-rc.1', stablePolicy }), HISTORICAL_FULL_GA_READINESS_PATH)
  assert.equal(readinessOutputPath({ packageVersion: '2.1.0' }), HISTORICAL_FULL_GA_READINESS_PATH)
})
