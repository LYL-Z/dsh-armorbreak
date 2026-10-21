import assert from 'node:assert/strict'
import { readFile, readdir } from 'node:fs/promises'
import { join } from 'node:path'
import test from 'node:test'

test('seven standard Agent Skills have valid frontmatter', async () => {
  const dirs = (await readdir('skills', { withFileTypes: true })).filter((entry) => entry.isDirectory())
  const skills = []
  for (const dir of dirs) {
    const file = join('skills', dir.name, 'SKILL.md')
    try {
      const text = await readFile(file, 'utf8')
      const match = /^---\n([\s\S]*?)\n---\n/.exec(text)
      assert.ok(match, `${file} has no frontmatter`)
      const front = match[1]
      const name = /^name:\s*(\S+)$/m.exec(front)?.[1]
      const description = /^description:\s*(.+)$/m.exec(front)?.[1]
      assert.equal(name, dir.name)
      assert.ok(description && description.length >= 20)
      assert.match(front, /^license:\s*MIT$/m)
      skills.push(name)
    } catch (error) {
      if (error.code === 'ENOENT') continue
      throw error
    }
  }
  assert.equal(skills.length, 7)
})
