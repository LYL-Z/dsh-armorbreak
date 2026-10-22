import { ArmorBreakClient, type AnalyzeResult, type Capability } from '../../packages/sdk-ts/index.js'
import type { ClientContract, SdkMethod } from '../../packages/sdk-ts/generated/contract.js'

const client = new ArmorBreakClient({ baseUrl: 'http://127.0.0.1:1' })
const capabilities: Promise<Capability[]> = client.capabilities()
const analysis: Promise<AnalyzeResult> = client.analyze({ capability: 'forensics.hash', target: 'sample.txt' })
const method: SdkMethod = 'analyze'
const contractShape: Pick<ClientContract, 'schemaVersion' | 'security'> = {
  schemaVersion: 'armorbreak.sdk-contract/v1',
  security: { modelIsAuthority: false, tokenSource: 'host configuration' },
}
void capabilities
void analysis
void method
void contractShape
