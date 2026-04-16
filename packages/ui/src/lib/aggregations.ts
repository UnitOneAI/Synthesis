import { Issue, Severity } from "../types"
import { getStrideCategory, getSystemContext } from "./parse"

export type StrideCounts = Record<string, number>
export type SeverityCounts = Record<string, number>

export function computeByStride(issues: Issue[]): StrideCounts {
  return issues.reduce<StrideCounts>((acc, issue) => {
    const s = getStrideCategory(issue)
    acc[s] = (acc[s] || 0) + 1
    return acc
  }, {})
}

export function computeBySeverity(issues: Issue[]): SeverityCounts {
  return issues.reduce<SeverityCounts>((acc, issue) => {
    const sev = issue.severity || "info"
    acc[sev] = (acc[sev] || 0) + 1
    return acc
  }, {})
}

const UNASSIGNED = "Unassigned"

export function groupByComponent(issues: Issue[]): Record<string, Issue[]> {
  const groups: Record<string, Issue[]> = {}
  for (const issue of issues) {
    const ctx = getSystemContext(issue)
    const comps = ctx.components.length > 0 ? ctx.components : [UNASSIGNED]
    // Each issue goes under its first listed component to avoid double-counting.
    const primary = comps[0]
    if (!groups[primary]) groups[primary] = []
    groups[primary].push(issue)
  }
  return groups
}

export interface Node {
  id: string
  label: string
  zone: "external" | "internal"
  issueCount: number
  criticalCount: number
}

export interface Edge {
  from: string
  to: string
  count: number
}

// Build a simple architecture graph from issues.
// Zones: "external" = anything on the LEFT side of a trust boundary, "internal" = right side.
// Nodes: unique impacted_assets + unique boundary sources.
// Edges: for each issue with a boundary "A → B", add edge (A, firstComponent).
export function buildGraph(issues: Issue[]): { nodes: Node[]; edges: Edge[] } {
  const nodeMap = new Map<string, Node>()
  const edgeMap = new Map<string, Edge>()

  function addNode(label: string, zone: "external" | "internal", issue?: Issue) {
    const id = label
    const existing = nodeMap.get(id)
    if (existing) {
      if (issue) {
        existing.issueCount += 1
        if (issue.severity === "critical") existing.criticalCount += 1
      }
      return existing
    }
    const node: Node = {
      id,
      label,
      zone,
      issueCount: issue ? 1 : 0,
      criticalCount: issue && issue.severity === "critical" ? 1 : 0,
    }
    nodeMap.set(id, node)
    return node
  }

  for (const issue of issues) {
    const ctx = getSystemContext(issue)
    const primary = ctx.components[0]

    if (primary) addNode(primary, "internal", issue)

    if (ctx.boundaryFrom) addNode(ctx.boundaryFrom, "external")
    if (ctx.boundaryTo && ctx.boundaryTo !== primary) {
      addNode(ctx.boundaryTo, "internal")
    }

    if (ctx.boundaryFrom && primary) {
      const key = `${ctx.boundaryFrom}→${primary}`
      const existing = edgeMap.get(key)
      if (existing) existing.count += 1
      else edgeMap.set(key, { from: ctx.boundaryFrom, to: primary, count: 1 })
    }
  }

  return { nodes: Array.from(nodeMap.values()), edges: Array.from(edgeMap.values()) }
}

export interface DerivedInsight {
  label: string
  value: string
  detail?: string
}

export function deriveInsights(issues: Issue[]): DerivedInsight[] {
  const insights: DerivedInsight[] = []
  if (issues.length === 0) return insights

  // Most impacted component
  const byComponent = groupByComponent(issues)
  const componentRank = Object.entries(byComponent).sort(
    (a, b) => b[1].length - a[1].length
  )
  if (componentRank.length > 0 && componentRank[0][0] !== UNASSIGNED) {
    const [name, list] = componentRank[0]
    insights.push({
      label: "Most impacted component",
      value: name,
      detail: `${list.length} of ${issues.length} threats`,
    })
  }

  // Dominant trust boundary source
  const boundaryFroms: Record<string, number> = {}
  for (const issue of issues) {
    const ctx = getSystemContext(issue)
    if (ctx.boundaryFrom) {
      boundaryFroms[ctx.boundaryFrom] = (boundaryFroms[ctx.boundaryFrom] || 0) + 1
    }
  }
  const boundaryRank = Object.entries(boundaryFroms).sort((a, b) => b[1] - a[1])
  if (boundaryRank.length > 0) {
    const [source, count] = boundaryRank[0]
    const pct = Math.round((count / issues.length) * 100)
    insights.push({
      label: "Dominant boundary source",
      value: source,
      detail: `${pct}% of threats originate here`,
    })
  }

  // Critical threats involving any data-storage-like component
  const dataKeywords = /database|db|storage|s3|bucket|cache|redis|vault/i
  const criticals = issues.filter((i) => i.severity === "critical")
  if (criticals.length > 0) {
    const dataCriticals = criticals.filter((i) => {
      const comps = getSystemContext(i).components
      return comps.some((c) => dataKeywords.test(c))
    })
    if (dataCriticals.length > 0) {
      const pct = Math.round((dataCriticals.length / criticals.length) * 100)
      insights.push({
        label: "Critical threats on data layer",
        value: `${pct}%`,
        detail: `${dataCriticals.length} of ${criticals.length} critical threats`,
      })
    }
  }

  // Top STRIDE category
  const byStride = computeByStride(issues)
  const strideRank = Object.entries(byStride).sort((a, b) => b[1] - a[1])
  if (strideRank.length > 0) {
    const [cat, count] = strideRank[0]
    insights.push({
      label: "Dominant STRIDE category",
      value: cat.replace(/_/g, " "),
      detail: `${count} threats`,
    })
  }

  return insights
}
