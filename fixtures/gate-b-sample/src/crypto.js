// Deliberately weak crypto sample for ArmorBreak Gate B (local Semgrep rules only).
'use strict'

const crypto = require('node:crypto')

// Semgrep: weak hash -> CWE-327
function legacyDigest(value) {
  return crypto.createHash('md5').update(value).digest('hex')
}

module.exports = { legacyDigest }
