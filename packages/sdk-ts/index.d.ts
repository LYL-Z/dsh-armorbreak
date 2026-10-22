export interface InvocationPrincipal {
  id: string
  kind: 'local-user' | 'service' | 'verified-host'
  sessionId?: string
}

export interface AnalyzeInput {
  capability: string
  target?: string
  options?: Record<string, unknown>
}

export interface Capability {
  id: string
  title: string
  riskLevel: 'L0' | 'L1' | 'L2' | 'L3'
  domain: string
}

export interface AnalyzeResult {
  taskId: string
  state: string
  capability: string
  riskLevel: string
  target: string
  targetSha256: string | null
  evidenceIds: string[]
  reportPath: string | null
}

export interface TaskResult {
  id: string
  workspace: string
  state: string
  operator: string
  createdAt: string
  [key: string]: unknown
}

export interface EvidenceResult {
  taskId: string
  evidence: Array<{ id: string; title: string; kind: string; excerpt: string; hash: string; targetSha256: string | null }>
}

export interface ReportResult {
  taskId: string
  path: string
  sha256: string
  markdown: string
}

export class ArmorBreakClient {
  constructor(options: {
    engine?: object
    baseUrl?: string
    token?: string
    fetchImpl?: Function
    principal?: InvocationPrincipal
    workspaceId?: string
  })
  health(): Promise<Record<string, unknown>>
  capabilities(): Promise<Capability[]>
  analyze(input: AnalyzeInput): Promise<AnalyzeResult>
  task(taskId: string): Promise<TaskResult>
  tasks(): Promise<TaskResult[]>
  evidence(taskId: string): Promise<EvidenceResult>
  report(taskId: string): Promise<ReportResult>
}
