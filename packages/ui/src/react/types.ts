/**
 * Types for the Synthesis threat model renderer.
 *
 * These types are compatible with UnitoneController's ToolOutput format.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info"

export interface IssueLocation {
  file_path?: string
  line_start?: number
  line_end?: number
  column_start?: number
  column_end?: number
  snippet?: string
}

export interface Issue {
  issue_id?: string
  id?: string
  tool_id?: string
  title: string
  severity: Severity
  category?: string
  description?: string
  location?: IssueLocation
  remediation?: string
  rule_id?: string
  fix_suggestion?: string
  metadata?: Record<string, any>
}

export interface RunToolResponse {
  execution_id?: string
  tool_id: string
  tool_version?: string
  issues: Issue[]
  summary?: Record<string, any>
  data?: Record<string, any>
  status?: string
}

export interface ThreatModelRendererProps {
  output: RunToolResponse
}
