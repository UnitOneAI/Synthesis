/**
 * React components for Synthesis threat model rendering.
 *
 * Usage in UnitoneController or other React apps:
 *
 * ```tsx
 * import { ThreatModelRenderer } from "@synthesis/ui/react"
 *
 * <ThreatModelRenderer output={toolOutput} />
 * ```
 */

export { ThreatModelRenderer } from "./ThreatModelRenderer"
export type {
  ThreatModelRendererProps,
  RunToolResponse,
  Issue,
  IssueLocation,
  Severity,
} from "./types"
