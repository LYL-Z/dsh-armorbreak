#!/usr/bin/env node
/**
 * Fault-injection child for AB2-M1-08 tests: prepare the migration then SIGKILL
 * itself before replacing the first task. The parent must recover from the
 * prepared manifest and restore the exact original bytes.
 */
import { applyMigration } from '../../lib/migrations/v1-to-v2.js'

const workspace = process.argv[2]
await applyMigration({
  workspaceRoot: workspace,
  onBeforeReplace() {
    process.kill(process.pid, 'SIGKILL')
  },
})
