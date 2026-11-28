/** Optional real Chromium E2E. Uses an explicitly supplied existing Playwright installation. */
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdtemp, mkdir, readFile, writeFile, rm } from 'node:fs/promises'
import { createRequire } from 'node:module'
import { tmpdir } from 'node:os'
import { join, isAbsolute } from 'node:path'
import { pathToFileURL } from 'node:url'

const modulePath = process.env.ARMORBREAK_PLAYWRIGHT_MODULE
if (!isAbsolute(modulePath ?? '')) throw new Error('Supply an existing Playwright index.mjs absolute path; no dependency is downloaded')
const { chromium } = await import(pathToFileURL(modulePath).href)
const consumer = process.env.ARMORBREAK_BROWSER_CONSUMER
if (consumer && !isAbsolute(consumer)) throw new Error('Supply the absolute npm consumer directory')
const workbench = consumer
  ? pathToFileURL(createRequire(join(consumer, 'package.json')).resolve('dsh-armorbreak/workbench')).href
  : '../workbench/server.mjs'
const { createWorkbenchServer } = await import(workbench)
const root = await mkdtemp(join(tmpdir(), 'ab-browser-'))
let browser, server
try {
  const workspace = join(root, 'workspace'); await mkdir(workspace)
  const target = join(workspace, 'bundle.json')
  await writeFile(target, JSON.stringify({ schema: 'armorbreak.config-overlay/v1', base: { privatePin: '1234' }, overlays: [{ id: 'privateLabel', values: { privatePin: '5678' } }], conflictPolicy: 'last-wins' }))
  server = await createWorkbenchServer({ native: { workspaceId: workspace, stateRoot: join(root, 'state') } })
  browser = await chromium.launch({ headless: true, channel: process.env.ARMORBREAK_BROWSER_CHANNEL })
  const page = await browser.newPage()
  const errors = []; page.on('pageerror', error => errors.push(error.message))
  await page.goto(server.url)
  await page.locator('#workbench-mode').selectOption('advanced')
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

  const editBundle = {
    schema: 'armorbreak.configuration-edit-request/v1',
    configuration: { schema: 'armorbreak.configuration-import/v1', format: 'yaml',
      source: 'privateField: "private-before" # private-annotation\r\nretired: false\r\n' },
    operations: [
      { op: 'replace', path: ['privateField'], expected: 'private-stale', value: 'private-after' },
      { op: 'remove', path: ['retired'], expected: false },
      { op: 'add', path: ['labels'], value: ['inert'] },
    ],
  }
  const editName = 'edit.json', editPath = join(workspace, editName), outside = join(root, 'outside.json')
  await writeFile(editPath, JSON.stringify(editBundle))
  await page.locator('.tab[data-tab="home"]').click()
  await page.getByRole('button', { name: '预览配置变更' }).click()
  await page.getByLabel('配置预览方式').selectOption('edit')
  const input = page.getByLabel('配置请求文件'), submit = page.getByRole('button', { name: '预览编辑' })
  const feedback = page.locator('#product-feedback'), summary = page.locator('#product-result')
  await input.fill(editName)
  await submit.click()
  await feedback.filter({ hasText: '预期旧值，修正文件后重试' }).waitFor()
  assert.equal(await submit.isEnabled(), true)
  assert.equal(await input.inputValue(), editName)
  assert.equal(await summary.isVisible(), false)

  editBundle.operations[0].expected = 'private-before'
  const valid = Buffer.from(JSON.stringify(editBundle))
  await writeFile(editPath, valid)
  const [previewResponse] = await Promise.all([page.waitForResponse(server.url + '/api/product/run'), submit.click()])
  const preview = await previewResponse.json()
  assert.equal(previewResponse.status(), 200)
  assert.equal(preview.state, 'COMPLETED')
  assert.equal(preview.hostModified, false)
  assert.ok(preview.evidenceIds.length)
  await summary.filter({ hasText: '新增 1 项，替换 1 项，删除 1 项' }).waitFor()
  assert.match(await summary.textContent(), /配置编辑预览.*配置值已隐藏，文件未修改/)
  const [download] = await Promise.all([page.waitForEvent('download'), summary.getByRole('button', { name: '下载 Markdown' }).click()])
  const markdown = await readFile(await download.path(), 'utf8')
  assert.equal(download.suggestedFilename(), preview.taskId + '.md')
  const publicResults = await summary.textContent() + JSON.stringify(preview) + markdown
  assert.doesNotMatch(publicResults, /privateField|private-before|private-after|private-annotation/)
  assert.ok(!publicResults.includes(createHash('sha256').update(valid).digest('hex')))
  assert.deepEqual(await readFile(editPath), valid)
  if (process.env.ARMORBREAK_BROWSER_SCREENSHOT) await page.screenshot({ path: process.env.ARMORBREAK_BROWSER_SCREENSHOT, fullPage: true })

  await writeFile(outside, valid)
  await input.fill(outside)
  await submit.click()
  await feedback.filter({ hasText: '检查项目内的目标' }).waitFor()
  assert.equal(await submit.isEnabled(), true)
  assert.deepEqual(await readFile(outside), valid)
  await page.getByLabel('配置预览方式').selectOption('overlay')
  await input.fill('bundle.json')
  await page.getByRole('button', { name: '开始检查' }).click()
  await summary.getByRole('heading', { name: '配置预览', exact: true }).waitFor()

  assert.deepEqual(errors, [])
  console.log(JSON.stringify({ result: 'PASS', browser: await browser.version(), mode: 'REAL_HEADLESS_CHROMIUM', package: consumer ? 'INSTALLED_NPM' : 'SOURCE', checks: ['loaded-ui', 'CSRF-warning', 'native-overlay-Core-evidence', 'structured-edit-expected-value-error', 'corrected-bundle-retry', 'structured-edit-confidential-preview', 'report-download', 'byte-exact-no-write', 'workspace-denial-rendered', 'overlay-mode-still-works', 'no-page-errors'], secondOSPrincipal: 'NOT_TESTED', DSHEmbedding: 'NOT_TESTED' }))
} finally {
  await browser?.close(); await server?.close(); await rm(root, { recursive: true, force: true })
}
