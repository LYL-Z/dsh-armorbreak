import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdir, mkdtemp, readFile, rm } from 'node:fs/promises'
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
    const extract = join(out, 'clean-room')
    await mkdir(extract, { recursive: true })
    execFileSync('tar', ['-xzf', info.artifact, '-C', extract], { timeout: 120_000 })
    const state = join(out, 'state')
    const workspace = join(out, 'workspace')
    const capsRaw = execFileSync(process.execPath, [join(extract, 'packages/cli/index.js'), 'capabilities', '--json'], {
      cwd: extract, encoding: 'utf8',
      env: { ...process.env, ARMORBREAK_STATE_ROOT: state, ARMORBREAK_WORKSPACE: workspace },
    })
    assert.equal(JSON.parse(capsRaw).length, 46)
  } finally {
    await rm(out, { recursive: true, force: true })
  }
})
