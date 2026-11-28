import childProcess from 'node:child_process'
import fs from 'node:fs'
import { syncBuiltinESMExports } from 'node:module'
import { basename, join } from 'node:path'
import { parentPort, workerData } from 'node:worker_threads'
import { writeSafeRepoFile } from '../lib/release/safeEvidenceFile.js'

// Run a disposable copy of the native helper with one checkpoint in its write
// sequence. Production helpers do not receive the port or run this code.
function instrumentNativeHelper(command, args, options) {
  const isWindows = process.platform === 'win32'
  const helperIndex = isWindows ? args.indexOf('-File') + 1 : 1
  const helper = args[helperIndex]
  const expectedHelper = isWindows ? 'safe-evidence-write-windows.ps1' : 'safe-evidence-write-posix.py'
  if (basename(helper) !== expectedHelper) throw new Error('unexpected native evidence writer helper')
  const source = fs.readFileSync(helper, 'utf8').replaceAll('\r\n', '\n')
  const output = join(workerData.root, basename(helper))
  const { port, token } = workerData.nativeCheckpoint
  const marker = isWindows
    ? '            temporary = OpenRelative(parent, temporaryName, false, FILE_WRITE_DATA | DELETE, FILE_CREATE);'
    : '            temporary_identity = identity(opened)'
  const checkpoint = isWindows ? `
            try
            {
                using (var client = new System.Net.Sockets.TcpClient("127.0.0.1", ${port}))
                {
                    client.ReceiveTimeout = 15000;
                    var stream = client.GetStream();
                    var notice = System.Text.Encoding.ASCII.GetBytes("${token} " + temporaryName + "\\n");
                    stream.Write(notice, 0, notice.Length);
                    if (stream.ReadByte() != 49) throw new IOException("test checkpoint acknowledgement missing");
                }
            }
            catch (Exception error) { throw new IOException("SAFE_EVIDENCE_TEST_CHECKPOINT_FAILED", error); }`
    : `
            import socket
            try:
                with socket.create_connection(('127.0.0.1', ${port}), timeout=15) as client:
                    client.sendall(('${token} ' + temporary + '\\n').encode('ascii'))
                    if client.recv(1) != b'1':
                        raise OSError('test checkpoint acknowledgement missing')
            except OSError:
                print('SAFE_EVIDENCE_TEST_CHECKPOINT_FAILED', file=sys.stderr)
                raise`
  if (source.split(marker).length !== 2) throw new Error('native evidence test checkpoint insertion point changed')
  fs.writeFileSync(output, source.replace(marker, marker + checkpoint))
  const instrumentedArgs = [...args]
  instrumentedArgs[helperIndex] = output
  const result = originalSpawnSync(command, instrumentedArgs, options)
  helperCheckpointFailed = result.stderr?.includes('SAFE_EVIDENCE_TEST_CHECKPOINT_FAILED') ?? false
  return result
}

const originalSpawnSync = childProcess.spawnSync
const originalOpenSync = fs.openSync
let helperCheckpointFailed = false
if (workerData.nativeCheckpoint) {
  childProcess.spawnSync = instrumentNativeHelper
} else {
  const acknowledgement = new Int32Array(workerData.acknowledgement)
  fs.openSync = (path, ...args) => {
    const descriptor = originalOpenSync(path, ...args)
    if (String(path).endsWith('.tmp')) {
      parentPort.postMessage({ status: 'opened', temporaryName: basename(path) })
      if (Atomics.wait(acknowledgement, 0, 0, 15000) === 'timed-out') {
        helperCheckpointFailed = true
        fs.closeSync(descriptor)
        throw new Error('test checkpoint acknowledgement timed out')
      }
    }
    return descriptor
  }
}
syncBuiltinESMExports()

try {
  const value = Buffer.alloc(workerData.bytes, 0x5a)
  writeSafeRepoFile(workerData.root, workerData.relativePath, value, { requiredPrefix: 'docs/v2/acceptance/' })
  parentPort.postMessage({ status: 'written' })
} catch (error) {
  parentPort.postMessage({
    status: 'refused', code: error?.code ?? null, message: String(error?.message ?? error), helperCheckpointFailed,
  })
} finally {
  childProcess.spawnSync = originalSpawnSync
  fs.openSync = originalOpenSync
  syncBuiltinESMExports()
}
