import assert from 'node:assert/strict'
import http from 'node:http'
import test from 'node:test'

import { createWorkbenchServer } from '../workbench/server.mjs'

function requestWithHost(url, host) {
  const target = new URL(url)
  return new Promise((resolve, reject) => {
    const request = http.request({
      hostname: target.hostname,
      port: Number(target.port),
      path: target.pathname,
      method: 'GET',
      headers: { Host: host },
    }, (response) => {
      let body = ''
      response.setEncoding('utf8')
      response.on('data', (chunk) => { body += chunk })
      response.on('end', () => resolve({ status: response.statusCode, body: JSON.parse(body) }))
    })
    request.once('error', reject)
    request.end()
  })
}

test('Workbench serves real state, host/provider tables and diagnostics', async () => {
  const server = await createWorkbenchServer()
  try {
    const stateResponse = await fetch(`${server.url}/api/state`)
    assert.equal(stateResponse.status, 200)
    const state = await stateResponse.json()
    assert.equal(state.hosts.length, 12)
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

test('Workbench rejects forged Host and cross-origin requests before serving state', async () => {
  const server = await createWorkbenchServer()
  try {
    const port = new URL(server.url).port
    const foreignHost = await requestWithHost(`${server.url}/api/state`, `evil.example:${port}`)
    assert.equal(foreignHost.status, 403)
    assert.deepEqual(foreignHost.body, { error: 'host not allowed' })

    const wrongPort = await requestWithHost(`${server.url}/api/state`, `127.0.0.1:${Number(port) + 1}`)
    assert.equal(wrongPort.status, 403)
    assert.deepEqual(wrongPort.body, { error: 'host not allowed' })

    const foreignOrigin = await fetch(`${server.url}/api/state`, { headers: { Origin: 'http://attacker.test' } })
    assert.equal(foreignOrigin.status, 403)
    assert.deepEqual(await foreignOrigin.json(), { error: 'origin not allowed' })

    const foreignHealthOrigin = await fetch(`${server.url}/health`, { headers: { Origin: 'http://attacker.test' } })
    assert.equal(foreignHealthOrigin.status, 403)
    assert.deepEqual(await foreignHealthOrigin.json(), { error: 'origin not allowed' })

    const sameOrigin = await fetch(`${server.url}/api/state`, { headers: { Origin: server.url } })
    assert.equal(sameOrigin.status, 200)
    assert.equal((await sameOrigin.json()).schemaVersion, 'armorbreak.workbench-state/v1')
  } finally {
    await server.close()
  }
})
