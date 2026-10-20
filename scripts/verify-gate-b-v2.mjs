/** Real-tool Gate B for v1.2.0 adapters (TShark/Syft/JADX). */
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { execFileSync } from 'node:child_process'
import { tsharkCapability } from '../lib/analyzers/network/tshark.js'
import { syftCapability } from '../lib/analyzers/sast/syft.js'
import { jadxCapability } from '../lib/analyzers/android/jadx.js'
import { resolveJava } from '../lib/core/externalTools.js'

function makePcap(path) {
  const packets = []
  const http = Buffer.from('GET /login?x=1 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: armorbreak-test\r\n\r\n', 'latin1')
  const eth = Buffer.alloc(14)
  Buffer.from('001122334455', 'hex').copy(eth, 0)
  Buffer.from('66778899aabb', 'hex').copy(eth, 6)
  eth.writeUInt16BE(0x0800, 12)
  const ip = Buffer.alloc(20)
  ip[0] = 0x45
  ip.writeUInt16BE(20 + 20 + http.length, 2)
  ip[8] = 64; ip[9] = 6
  ip.writeUInt32BE(0x0a000005, 12) // 10.0.0.5
  ip.writeUInt32BE(0x5db8d822, 16) // 93.184.216.34
  const tcp = Buffer.alloc(20)
  tcp.writeUInt16BE(12345, 0); tcp.writeUInt16BE(80, 2)
  tcp.writeUInt32BE(1, 4); tcp.writeUInt32BE(0, 8)
  tcp[12] = 0x50; tcp[13] = 0x18
  const frame = Buffer.concat([eth, ip, tcp, http])
  packets.push(frame)
  const dnsPayload = Buffer.concat([
    Buffer.from([0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
    Buffer.from([7]), Buffer.from('example', 'latin1'), Buffer.from([3]), Buffer.from('com', 'latin1'), Buffer.from([0, 0, 1, 0, 1]),
  ])
  const udp = Buffer.alloc(8)
  udp.writeUInt16BE(5353, 0); udp.writeUInt16BE(53, 2); udp.writeUInt16BE(8 + dnsPayload.length, 4)
  const ip2 = Buffer.alloc(20)
  ip2[0] = 0x45; ip2.writeUInt16BE(20 + 8 + dnsPayload.length, 2); ip2[8] = 64; ip2[9] = 17
  ip2.writeUInt32BE(0x0a000005, 12); ip2.writeUInt32BE(0x08080808, 16)
  packets.push(Buffer.concat([eth, ip2, udp, dnsPayload]))
  const global = Buffer.alloc(24)
  global.writeUInt32LE(0xa1b2c3d4, 0); global.writeUInt16LE(2, 4); global.writeUInt16LE(4, 6)
  global.writeUInt32LE(0, 8); global.writeUInt32LE(0, 12); global.writeUInt32LE(65535, 16); global.writeUInt32LE(1, 20)
  const parts = [global]
  let ts = 1700000000
  for (const packet of packets) {
    const header = Buffer.alloc(16)
    header.writeUInt32LE(ts, 0); header.writeUInt32LE(0, 4); header.writeUInt32LE(packet.length, 8); header.writeUInt32LE(packet.length, 12)
    parts.push(header, packet); ts += 1
  }
  writeFileSync(path, Buffer.concat(parts))
}

const tmp = mkdtempSync(join(tmpdir(), 'abm-gateb-v2-'))
const pcap = join(tmp, 'http-dns.pcap')
makePcap(pcap)
const results = {}
results.tshark = await tsharkCapability.run({ targetPath: pcap, options: { maxPackets: 50 }, limits: { timeoutMs: 60000, maxFindings: 20 }, env: {} })
results.syft = await syftCapability.run({ targetPath: join(process.cwd(), 'fixtures', 'gate-b-sample'), options: { maxComponents: 50 }, limits: { timeoutMs: 180000 }, env: {} })

// JADX: compile a tiny jar with risky APIs and decompile it.
const java = resolveJava()
const javac = join(dirname(java), process.platform === 'win32' ? 'javac.exe' : 'javac')
const jarTool = join(dirname(java), process.platform === 'win32' ? 'jar.exe' : 'jar')
const srcDir = join(tmp, 'src', 'com', 'example')
mkdirSync(srcDir, { recursive: true })
writeFileSync(join(srcDir, 'A.java'), `package com.example;
public class A {
  public void run() throws Exception { Runtime.getRuntime().exec("id"); }
  public void net() throws Exception { new ProcessBuilder("whoami").start(); }
}
`)
mkdirSync(join(tmp, 'classes'), { recursive: true })
execFileSync(javac, ['-d', join(tmp, 'classes'), join(srcDir, 'A.java')], { stdio: 'pipe' })
const jarPath = join(tmp, 'app.jar')
execFileSync(jarTool, ['cf', jarPath, '-C', join(tmp, 'classes'), '.'], { stdio: 'pipe' })
results.jadx = await jadxCapability.run({ targetPath: jarPath, options: { maxFiles: 50 }, limits: { timeoutMs: 180000 }, env: {} })

const summary = {
  generatedAt: new Date().toISOString(),
  tools: { tshark: '4.6.9', syft: '1.54.1', jadx: '1.5.6', java: java },
  tshark: { summary: results.tshark.summary, packets: results.tshark.data.packetCount, http: results.tshark.data.httpRequests.length, dns: results.tshark.data.dnsQueries.length, findings: results.tshark.findings.length },
  syft: { summary: results.syft.summary, components: results.syft.data.componentCount, types: results.syft.data.types, findings: results.syft.findings.length },
  jadx: { summary: results.jadx.summary, files: results.jadx.data.filesScanned, classes: results.jadx.data.classCount, methods: results.jadx.data.methodCount, apis: Object.keys(results.jadx.data.apiCategories) },
}
writeFileSync('docs/acceptance/adapter-v2-real.json', JSON.stringify(summary, null, 2))
console.log(JSON.stringify(summary, null, 2))
