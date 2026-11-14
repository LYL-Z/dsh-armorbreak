/** Optional real Chromium E2E. Uses an explicitly supplied existing Playwright installation. */
import assert from 'node:assert/strict'
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, isAbsolute } from 'node:path'
import { pathToFileURL } from 'node:url'
import { createWorkbenchServer } from '../workbench/server.mjs'

const modulePath = process.env.ARMORBREAK_PLAYWRIGHT_MODULE
if (!isAbsolute(modulePath ?? '')) throw new Error('Supply an existing Playwright index.mjs absolute path; no dependency is downloaded')
const { chromium } = await import(pathToFileURL(modulePath).href)
const root = await mkdtemp(join(tmpdir(), 'ab-browser-'))
let browser, server
try {
  const workspace = join(root, 'workspace'); await mkdir(workspace)
  const target = join(workspace, 'bundle.json')
  await writeFile(target, JSON.stringify({ schema: 'armorbreak.config-overlay/v1', base: { privatePin: '1234' }, overlays: [{ id: 'privateLabel', values: { privatePin: '5678' } }], conflictPolicy: 'last-wins' }))
  server = await createWorkbenchServer({ native: { workspaceId: workspace, stateRoot: join(root, 'state') } })
  browser = await chromium.launch({ headless: true })
  const page = await browser.newPage()
  const errors = []; page.on('pageerror', error => errors.push(error.message))
  await page.goto(server.url)
  await page.locator('.tab[data-tab="native"]').click()
  await page.locator('#native-status').filter({ hasText: 'NOT identity authentication' }).waitFor()
  await page.locator('#native-capability').selectOption('configuration.preview')
  await page.locator('#native-target').fill(target)
  await page.locator('#native-run').click()
  await page.locator('#native-output').filter({ hasText: 'PREVIEW_READY' }).waitFor()
  const result = JSON.parse(await page.locator('#native-output').textContent())
  assert.equal(result.httpStatus, 200); assert.ok(result.taskId && result.evidenceIds.length)
  assert.doesNotMatch(JSON.stringify(result), /privatePin|privateLabel|beforeSha256|afterSha256|1234|5678/)
  await page.locator('#native-target').fill(join(root, 'outside.json'))
  await page.locator('#native-run').click()
  await page.locator('#native-output').filter({ hasText: 'CORE_REQUEST_REJECTED' }).waitFor()
  assert.equal(await page.locator('#native-run').isEnabled(), true)
  assert.deepEqual(errors, [])
  if (process.env.ARMORBREAK_BROWSER_SCREENSHOT) await page.screenshot({ path: process.env.ARMORBREAK_BROWSER_SCREENSHOT, fullPage: true })
  console.log(JSON.stringify({ result: 'PASS', browser: await browser.version(), mode: 'REAL_HEADLESS_CHROMIUM', checks: ['loaded-ui', 'CSRF-warning', 'select-and-submit', 'Core-evidence-result', 'confidential-preview', 'workspace-denial-rendered', 'button-recovers', 'no-page-errors'], secondOSPrincipal: 'NOT_TESTED', DSHEmbedding: 'NOT_TESTED' }))
} finally {
  await browser?.close(); await server?.close(); await rm(root, { recursive: true, force: true })
}
