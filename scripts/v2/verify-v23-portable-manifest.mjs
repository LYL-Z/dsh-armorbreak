import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'

const digest = (bytes) => createHash('sha256').update(bytes).digest('hex')

export function verifyV23PortableManifest(artifactPath, expectedCommit) {
  const artifactBytes = readFileSync(artifactPath)
  const artifactSha256 = digest(artifactBytes)
  const manifestPath = `${artifactPath}.manifest.json`
  const manifestBytes = readFileSync(manifestPath)
  const manifest = JSON.parse(manifestBytes.toString('utf8'))
  const expectedArtifact = 'armorbreak-portable-2.3.1.tar.gz'

  if (manifest.schemaVersion !== 'armorbreak.release-build/v1'
    || manifest.commit !== expectedCommit
    || manifest.version !== '2.3.1'
    || manifest.reproducible !== true
    || manifest.artifact !== expectedArtifact
    || manifest.bytes !== artifactBytes.length
    || manifest.sha256 !== artifactSha256) {
    throw new Error(`portable archive does not match the exact source commit and build manifest: ${manifestPath}`)
  }

  return {
    artifactBytes,
    artifactSha256,
    manifest,
    manifestPath,
    manifestSha256: digest(manifestBytes),
  }
}
