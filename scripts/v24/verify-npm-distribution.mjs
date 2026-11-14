#!/usr/bin/env node
/** Build an actual npm tarball from committed Git blobs, then install and exercise it. */
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

export async function verifyNpmDistribution({ repositoryRoot, commit = 'HEAD', outputRoot, offline = true }) {
  const git = (...args) => execFileSync('git', args, { cwd: repositoryRoot, maxBuffer: 64 * 1024 * 1024 })
  const sha = git('rev-parse', '--verify', `${commit}^{commit}`).toString().trim()
  if (!/^[a-f0-9]{40}$/.test(sha)) throw new Error('DISTRIBUTION_COMMIT_INVALID')
  if (existsSync(outputRoot)) throw new Error('REFUSE_EXISTING_OUTPUT')
  mkdirSync(outputRoot, { recursive: true })
  const source = join(outputRoot, 'frozen-source'), consumer = join(outputRoot, 'consumer')
  mkdirSync(source); mkdirSync(consumer)
  const env = { ...process.env }
  for (const name of Object.keys(env)) if (name.startsWith('ARMORBREAK_') || ['NODE_PATH','NODE_OPTIONS'].includes(name)) delete env[name]
  const npm = process.env.npm_execpath ?? join(dirname(process.execPath), 'node_modules/npm/bin/npm-cli.js')
  if (!existsSync(npm)) throw new Error('NPM_CLI_NOT_FOUND')
  const report = { schema: 'armorbreak.npm-distribution-validation/v1', status: 'RUNNING', commit: sha,
    environment: { node: process.version, platform: process.platform, offlineInstall: offline, developmentNodeModulesUsed: false }, commands: [] }
  const save = () => writeFileSync(join(outputRoot, 'validation.json'), JSON.stringify(report, null, 2) + '\n')
  function run(label, binary, args, cwd = consumer, extra = {}) {
    let bytes
    try {
      bytes = execFileSync(binary, args, { cwd, env, timeout: 120000, maxBuffer: 32 * 1024 * 1024, ...extra })
      report.commands.push({ label, exitCode: 0 }); writeFileSync(join(outputRoot, label + '.log'), bytes); save(); return bytes
    } catch (error) {
      report.commands.push({ label, exitCode: error.status ?? null }); writeFileSync(join(outputRoot, label + '.log'), Buffer.concat([error.stdout ?? Buffer.alloc(0), error.stderr ?? Buffer.alloc(0)])); save(); throw error
    }
  }
  try {
    // Never package uncommitted working-tree bytes, node_modules or Git configuration.
    const tree = git('ls-tree', '-rz', '-r', sha).toString().split('\0').filter(Boolean)
    for (const row of tree) if (!/^(100644|100755) blob [a-f0-9]{40}\t/.test(row)) throw new Error('NON_REGULAR_SOURCE_TREE')
    run('freeze', 'tar', ['-xf', '-', '-C', source], repositoryRoot, { input: git('archive', '--format=tar', sha) })
    const packed = JSON.parse(run('npm-pack', process.execPath, [npm, 'pack', '--ignore-scripts', '--json', '--pack-destination', outputRoot], source).toString())[0]
    const artifact = join(outputRoot, `armorbreak-npm-candidate-${sha.slice(0, 12)}.tgz`)
    renameSync(join(outputRoot, packed.filename), artifact)
    report.artifact = { file: artifact.split(/[\\/]/).at(-1), bytes: readFileSync(artifact).length, sha256: createHash('sha256').update(readFileSync(artifact)).digest('hex') }
    report.packFiles = packed.files.map(file => file.path).sort()
    writeFileSync(join(consumer, 'package.json'), JSON.stringify({ name: 'isolated-armorbreak-consumer', private: true, type: 'module' }))
    run('npm-install', process.execPath, [npm, 'install', '--ignore-scripts', '--omit=dev', '--no-audit', '--no-fund', ...(offline ? ['--offline'] : []), '--registry', 'https://registry.npmjs.org', artifact])
    // First exercise the actual root import: this is the original R3-F-05 reproduction.
    run('root-import', process.execPath, ['--input-type=module', '-e', "await import('dsh-armorbreak'); console.log('ROOT_IMPORTED')"])
    const required = ['packages/core/index.js','packages/cli/index.js','packages/mcp-server/index.js','packages/core/src/syntheticConfiguration.js','workbench/server.mjs','npm-shrinkwrap.json']
    for (const path of required) if (!report.packFiles.includes(path)) throw new Error('DISTRIBUTION_MISSING: ' + path)
    const allowedRoots = new Set(['lib','packages','plugins','skills','locale','workbench'])
    const allowedFiles = new Set(['package.json','npm-shrinkwrap.json','index.js','tools.js','skills.js','client.js','cordis.patch.yml','icon.svg','README.md','README.zh-CN.md','CHANGELOG.md','LICENSE','SECURITY.md','CONTRIBUTING.md','docs/v24/distribution.md'])
    for (const path of report.packFiles) {
      if (!allowedFiles.has(path) && !allowedRoots.has(path.split('/')[0])) throw new Error('UNRELATED_DISTRIBUTION_FILE: ' + path)
      if (/(^|\/)(node_modules|tests?|fixtures?|evidence|acceptance|\.git|\.armorbreak)(\/|$)|(^|\/)\.env(?:\.|$)|\.(?:pem|key|p12|pfx|pyc)$/i.test(path)) throw new Error('SENSITIVE_DISTRIBUTION_PATH: ' + path)
      const bytes = readFileSync(join(consumer, 'node_modules/dsh-armorbreak', path))
      if (/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----\r?\n[A-Za-z0-9+/]/.test(bytes.toString('utf8'))) throw new Error('PRIVATE_KEY_IN_PACKAGE: ' + path)
    }
    const probe = join(consumer, 'installed-probe.mjs')
    writeFileSync(probe, readFileSync(new URL('./installed-probe.mjs', import.meta.url)))
    report.checks = JSON.parse(run('installed-runtime', process.execPath, [probe]).toString())
    report.status = 'PASS_ACTUAL_PACK_INSTALL_IMPORT_RUNTIME'; save(); return report
  } catch (error) {
    report.status = 'FAIL'; report.error = String(error.message); save(); throw error
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const arg = name => process.argv[process.argv.indexOf(name) + 1]
  const outputRoot = process.argv.includes('--out') ? resolve(arg('--out')) : null
  if (!outputRoot) throw new Error('--out <new-directory> is required')
  const report = await verifyNpmDistribution({ repositoryRoot: resolve(fileURLToPath(new URL('../..', import.meta.url))), commit: process.argv.includes('--commit') ? arg('--commit') : 'HEAD', outputRoot, offline: !process.argv.includes('--online') })
  console.log(JSON.stringify({ status: report.status, commit: report.commit, artifact: report.artifact, checks: report.checks }, null, 2))
}
