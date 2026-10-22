#!/usr/bin/env node
/** Rollback drill for JSON/TOML/YAML host config installers. */
import { createHash } from 'node:crypto'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { applyJsonInstall, planJsonInstall, rollbackJsonInstall } from '../../packages/installer/index.js'
import { applyTomlInstall, planTomlInstall, rollbackTomlInstall } from '../../packages/installer/toml.js'
import { applyYamlInstall, planYamlInstall, rollbackYamlInstall } from '../../packages/installer/yaml.js'

const hash = (value) => createHash('sha256').update(value).digest('hex')
const server = { command: 'node', args: ['server.js'], env: { ARMORBREAK_WORKSPACE: 'C:/work' } }
const dir = await mkdtemp(join(tmpdir(), 'abm-rollback-drill-'))
const result = { json: false, toml: false, yaml: false, byteExact: false }
try {
  const jsonPath = join(dir, 'config.json')
  const jsonBefore = JSON.stringify({ mcpServers: { other: { command: 'other' } } }, null, 2) + '\n'
  await writeFile(jsonPath, jsonBefore)
  const jsonPlan = await planJsonInstall({ configPath: jsonPath, server })
  const jsonApplied = await applyJsonInstall(jsonPlan)
  await rollbackJsonInstall(jsonApplied.backupPath, jsonPath)
  result.json = hash(await readFile(jsonPath, 'utf8')) === hash(jsonBefore)

  const tomlPath = join(dir, 'config.toml')
  const tomlBefore = '[mcp_servers.other]\ncommand = "other"\n'
  await writeFile(tomlPath, tomlBefore)
  const tomlPlan = await planTomlInstall({ configPath: tomlPath, server })
  const tomlApplied = await applyTomlInstall(tomlPlan)
  await rollbackTomlInstall(tomlApplied.backupPath, tomlPath)
  result.toml = hash(await readFile(tomlPath, 'utf8')) === hash(tomlBefore)

  const yamlPath = join(dir, 'config.yaml')
  const yamlBefore = 'mcp_servers:\n  other:\n    enabled: true\n'
  await writeFile(yamlPath, yamlBefore)
  const yamlPlan = await planYamlInstall({ configPath: yamlPath, server })
  const yamlApplied = await applyYamlInstall(yamlPlan)
  await rollbackYamlInstall(yamlApplied.backupPath, yamlPath)
  result.yaml = hash(await readFile(yamlPath, 'utf8')) === hash(yamlBefore)
  result.byteExact = result.json && result.toml && result.yaml
} finally {
  await rm(dir, { recursive: true, force: true })
}
console.log(JSON.stringify({ schemaVersion: 'armorbreak.rollback-drill/v1', ...result, cleanup: true, passed: result.byteExact }, null, 2))
if (!result.byteExact) process.exitCode = 1
