export interface ScopeItem {
  name: string
  type: string
  description?: string
}

export interface AnalysisData {
  languages?: string[]
  frameworks?: string[]
  components?: number
  data_flows?: number
  security_findings?: number
}

export interface ScopeData {
  in_scope?: ScopeItem[]
  out_of_scope?: ScopeItem[]
}

export interface ParsedDescription {
  threatStatement?: string
  trustBoundary?: string
  impactedAssets?: string
  assumptions?: string
  mitigations?: string[]
  rawText?: string
}

export interface SystemContext {
  components: string[]
  trustBoundary?: string
  boundaryFrom?: string
  boundaryTo?: string
}
