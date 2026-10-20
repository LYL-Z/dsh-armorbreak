// Deliberately vulnerable sample for ArmorBreak Gate B.
// This file exists only to exercise the local Semgrep rule set. Never deploy it.
'use strict'

const { exec } = require('node:child_process')

// Semgrep: dynamic eval -> CWE-95
function runUserCode(code) {
  return eval(code)
}

// Semgrep: command concatenation -> CWE-78
function pingHost(host) {
  exec('ping -n 1 ' + host, (error, stdout) => {
    if (!error) console.log(stdout)
  })
}

// Semgrep: SQL string concatenation -> CWE-89
function findUser(db, userId) {
  return db.query('SELECT * FROM users WHERE id = ' + userId)
}

// Semgrep: hardcoded AWS access key (documented AWS example value, never a live credential)
const AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'

module.exports = { runUserCode, pingHost, findUser, AWS_ACCESS_KEY_ID }
