// Mirrored from UnitoneController web/lib/types.ts.
// Self-contained so this package has no host-app dependency.

export type Severity = "critical" | "high" | "medium" | "low" | "info"

export interface CodeLocation {
  file_path: string
  line_start?: number
  line_end?: number
  column_start?: number
  column_end?: number
  snippet?: string
}

export interface Issue {
  issue_id: string
  title: string
  description?: string
  severity: Severity
  category: string
  location?: CodeLocation
  tool_id: string
  rule_id?: string
  cwe_id?: string
  fix_suggestion?: string
  metadata?: Record<string, any>
}

export interface RunToolResponse {
  execution_id?: string
  tool_id: string
  tool_version?: string
  issues: Issue[]
  summary: Record<string, any>
  data: Record<string, any>
  started_at?: string
  issues_found?: number
}
