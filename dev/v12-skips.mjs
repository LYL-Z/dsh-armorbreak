import { readFileSync, writeFileSync } from 'node:fs'

let n = readFileSync('tests/network.test.mjs', 'utf8')
n = n.replaceAll('  for (const capability of networkManifest.capabilities) {', "  for (const capability of networkManifest.capabilities) {\n    if (capability.id === 'network.tshark') continue; // external tool + capture; covered by external-adapters-v2.test.mjs / Gate B")
writeFileSync('tests/network.test.mjs', n)

let a = readFileSync('tests/android.test.mjs', 'utf8')
a = a.replaceAll('  for (const capability of androidManifest.capabilities) {', "  for (const capability of androidManifest.capabilities) {\n    if (capability.id === 'android.jadx') continue; // external JADX + APK; covered by external-adapters-v2.test.mjs / Gate B")
writeFileSync('tests/android.test.mjs', a)
console.log('skips inserted')
