// Generated from packages/sdk-ts/schemas/client-contract.json. Do not edit by hand.
export type SdkMethod = 'analyze' | 'capabilities' | 'evidence' | 'health' | 'report' | 'task' | 'tasks'

export interface ClientContract {
  schemaVersion: string
  package: string
  transports: string[]
  methods: Record<SdkMethod, { params: string[]; result: string }>
  security: { modelIsAuthority: boolean; tokenSource: string }
}

export declare const CONTRACT: ClientContract
