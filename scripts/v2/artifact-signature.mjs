/** Ed25519 artifact signatures. Production key management is intentionally separate. */
import { createPrivateKey, createPublicKey, sign, verify } from 'node:crypto'
import { readFile } from 'node:fs/promises'

export async function signArtifact(artifactPath, privateKeyPem) {
  const bytes = await readFile(artifactPath)
  const key = createPrivateKey(privateKeyPem)
  return { algorithm: 'ed25519', signature: sign(null, bytes, key).toString('base64') }
}

export async function verifyArtifactSignature(artifactPath, signatureBase64, publicKeyPem) {
  const bytes = await readFile(artifactPath)
  const key = createPublicKey(publicKeyPem)
  return verify(null, bytes, key, Buffer.from(String(signatureBase64), 'base64'))
}
