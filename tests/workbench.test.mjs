import assert from 'node:assert/strict'
import test from 'node:test'

import { createWorkbenchServer } from '../workbench/server.mjs'

test('Workbench serves real state, host/provider tables and diagnostics', async () => {
  const server = await createWorkbenchServer()
  try {
    const stateResponse = await fetch(`${server.url}/api/state`)
    assert.equal(stateResponse.status, 200)
    const state = await stateResponse.json()
    assert.equal(state.hosts.length, 9)
    assert.equal(state.providers.length, 6)
    assert.ok(state.skills.length >= 7)
    assert.ok(state.tasks.length >= 40)
    assert.ok(state.hosts.some((host) => host.host === 'Cursor' && host.taskRunState === 'L0_COMPLETED'))
    assert.ok(state.providers.some((provider) => provider.kind === 'openai-responses'))
    const page = await fetch(`${server.url}/`)
    assert.equal(page.status, 200)
    const html = await page.text()
    for (const id of ['hosts-body', 'providers-body', 'skills-list', 'tasks-body', 'evidence-list', 'diag-output']) assert.match(html, new RegExp(`id="${id}"`))
    const provider = await fetch(`${server.url}/api/diagnose`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ providerId: 'openai-responses' }) })
    const providerResult = await provider.json()
    assert.equal(providerResult.status, 'BLOCKED_EXTERNAL')
    assert.equal(providerResult.secretRendered, false)
    const host = await fetch(`${server.url}/api/diagnose`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ host: 'Cursor' }) })
    const hostResult = await host.json()
    assert.equal(hostResult.status, 'L0_COMPLETED')
  } finally {
    await server.close()
  }
})
