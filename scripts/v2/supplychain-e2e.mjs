#!/usr/bin/env node
/** AB2-M2-04/10/11 end-to-end supply-chain evidence (local sandbox, no package code). */
import { generateKeyPairSync } from 'node:crypto'
import { mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { ApprovalAuthority } from '../../lib/control/approvalAuthority.js'
import { TransactionalInstaller } from '../../lib/install/installer.js'
import { VersionedIndex } from '../../lib/connectivity/versionedIndex.js'

const root = await mkdtemp(join(tmpdir(), 'abm-supply-e2e-'))
const artifactPath = join(root, 'bundle.tgz')
await writeFile(artifactPath, 'ARMORBREAK-SIGNED-TEST-ARTIFACT')
const authority = new ApprovalAuthority({ stateRoot: join(root, 'state') })
const installer = new TransactionalInstaller({ root: join(root, 'installer'), approvalAuthority: authority })
const component = {
  name: 'armorbreak-core', version: '2.0.0-rc.1', license: 'MIT', commit: 'local-test-commit', digest: 'sha256:test-artifact', scripts: {},
  osv: { known: false }, scorecard: { score: 9.2 }, sbom: { components: 1 },
}
const plan = await installer.plan({ artifactPath, repo: 'local://armorbreak-bundle', commit: component.commit, license: component.license, components: [component] })
await installer.persist(plan)
const staged = await installer.stage(plan)
const verified = await installer.verify(staged)
const token = authority.issue({ id: `install:${plan.planId}`, riskLevel: 'L2', taskId: plan.planId, target: plan.planHash, operator: 'e2e-operator' }).token
const approved = await installer.approve(verified, { approvalToken: token, operator: 'e2e-operator' })
const active = await installer.activate(approved)
const activePointer = JSON.parse(await readFile(join(installer.root, 'active.json'), 'utf8'))
const rolled = await installer.rollback(active)

const { publicKey, privateKey } = generateKeyPairSync('ed25519')
const indexRoot = join(root, 'index')
const index = new VersionedIndex({ root: indexRoot })
const descriptor = await index.publish([{ id: 'catalog-entry', uri: 'https://github.com/deepseek-ai/DeepSeek-V3', license: 'MIT' }], { signingKey: privateKey, keyId: 'e2e-key' })
const loaded = await index.read({ publicKey, requireSignature: true })
const previous = descriptor.hash
await index.publish([{ id: 'catalog-entry-v2', license: 'MIT' }], { signingKey: privateKey, keyId: 'e2e-key' })
await index.rollback()
const rolledIndex = await index.read({ publicKey, requireSignature: true })

const report = {
  schemaVersion: 'armorbreak.supplychain-e2e/v1',
  generatedAt: new Date().toISOString(),
  packageSources: [
    { id: 'github:deepseek-ai/DeepSeek-V3', kind: 'public-metadata', license: 'MIT', commit: '9b4e9788e4a3a731f7567338ed15d3ec549ce03b' },
    { id: 'local://armorbreak-bundle', kind: 'local-signed-artifact', license: 'MIT', artifactSha256: plan.artifact.sha256 },
  ],
  installer: { plan: plan.status, planHash: plan.planHash, staged: staged.status, verified: verified.status, approved: approved.status, active: active.status, activePointerPlanId: activePointer.planId, rolledBack: rolled.status, executePackageCode: false },
  index: { signature: descriptor.signature, verified: loaded.index.entries.length === 1, rollbackHash: previous, rolledBackEntries: rolledIndex.index.entries.length },
  result: rolled.status === 'ROLLED_BACK' && activePointer.planId === plan.planId && descriptor.signature.alg === 'ed25519' && loaded.index.entries.length === 1 && rolledIndex.index.entries.length === 1 ? 'PASS' : 'FAIL',
}
await writeFile('docs/v2/acceptance/supplychain-e2e.json', `${JSON.stringify(report, null, 2)}\n`)
console.log(JSON.stringify(report, null, 2))
if (report.result !== 'PASS') process.exitCode = 1
