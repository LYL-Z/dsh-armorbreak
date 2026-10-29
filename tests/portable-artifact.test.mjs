import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdir, mkdtemp, readFile, readdir, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

test('portable artifact builds and runs capabilities after clean-room extraction', async () => {
  const out = await mkdtemp(join(tmpdir(), 'abm-portable-'))
  try {
    const stdout = execFileSync(process.execPath, ['scripts/v2/build-portable-artifact.mjs', '--out', out], { cwd: process.cwd(), encoding: 'utf8', timeout: 120_000 })
    const info = JSON.parse(stdout)
    assert.match(info.sha256, /^[a-f0-9]{64}$/)
    assert.ok(info.bytes > 100_000)
    const manifest = JSON.parse(await readFile(info.manifest, 'utf8'))
    assert.equal(manifest.sourcePinned, true)
    assert.equal(manifest.signed, false)
    assert.equal(manifest.commit, execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim())
    const sbom = JSON.parse(await readFile(join(out, `${manifest.artifact}.sbom.cdx.json`), 'utf8'))
    assert.equal(sbom.bomFormat, 'CycloneDX')
    assert.match(manifest.contentManifestSha256, /^[a-f0-9]{64}$/)
    assert.ok(manifest.contentManifest.every((file) => /^[a-f0-9]{64}$/.test(file.sha256)))
    assert.ok(!manifest.contentManifest.some((file) => file.path.startsWith('node_modules/typescript/')))
    const expectedPackages = (await readdir(join(process.cwd(), 'packages'), { withFileTypes: true }))
      .filter((entry) => entry.isDirectory()).map((entry) => `@armorbreak/${entry.name}`).sort()
    assert.deepEqual(sbom.components.map((component) => component.name).sort(), expectedPackages)
    assert.ok(sbom.components.every((component) => component.hashes?.some((hash) => hash.alg === 'SHA-256')))
    const extract = join(out, 'clean-room')
    await mkdir(extract, { recursive: true })
    const archiveBytes = await readFile(info.artifact)
    execFileSync('tar', ['-xzf', '-'], { cwd: extract, input: archiveBytes, timeout: 120_000 })
    const archiveEntries = execFileSync('tar', ['-tzf', '-'], { cwd: extract, input: archiveBytes, encoding: 'utf8', timeout: 120_000 })
      .split(/\r?\n/).filter((entry) => entry && !entry.endsWith('/')).sort()
    assert.deepEqual(archiveEntries, manifest.contentManifest.map((file) => file.path).sort())
    const parserProbeScript = [
      'import sourceManifest from "./lib/analyzers/source/manifest.js";',
      'let listCalled = false;',
      'const result = await sourceManifest.capabilities[0].run({ targetPath: ".", options: {}, env: { listFiles: async () => { listCalled = true; return []; }, readFile: async () => Buffer.alloc(0) } });',
      'console.log(JSON.stringify({ status: result.data.analysis.status, parserVersion: result.data.parser.version, listCalled }));',
    ].join('\n')
    const parserProbe = JSON.parse(execFileSync(process.execPath, ['--input-type=module', '-e', parserProbeScript], { cwd: extract, encoding: 'utf8' }))
    assert.deepEqual(parserProbe, { status: 'UNSUPPORTED', parserVersion: 'UNAVAILABLE', listCalled: false })
    const state = join(out, 'state')
    const workspace = join(out, 'workspace')
    const capsRaw = execFileSync(process.execPath, [join(extract, 'packages/cli/index.js'), 'capabilities', '--json'], {
      cwd: extract, encoding: 'utf8',
      env: { ...process.env, ARMORBREAK_STATE_ROOT: state, ARMORBREAK_WORKSPACE: workspace },
    })
    assert.equal(JSON.parse(capsRaw).length, 51)
  } finally {
    await rm(out, { recursive: true, force: true })
  }
})
