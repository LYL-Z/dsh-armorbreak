#!/usr/bin/env node
/**
 * V2 migration CLI. Usage:
 *   node scripts/v2/migrate.mjs --workspace <dir> [--plan | --apply | --rollback <manifest>]
 */
import { applyMigration, planMigration, rollbackMigration } from '../../lib/migrations/v1-to-v2.js'

function arg(name, fallback = null) {
  const index = process.argv.indexOf(name)
  return index >= 0 ? process.argv[index + 1] : fallback
}

const workspace = arg('--workspace', process.cwd())
const rollback = arg('--rollback')
try {
  let result
  if (rollback) result = await rollbackMigration({ manifestPath: rollback })
  else if (process.argv.includes('--apply')) result = await applyMigration({ workspaceRoot: workspace })
  else result = await planMigration({ workspaceRoot: workspace })
  console.log(JSON.stringify(result, null, 2))
} catch (error) {
  console.error(`migration failed: ${String(error?.message ?? error)}`)
  process.exitCode = 1
}
