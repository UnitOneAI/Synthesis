import { Issue } from "../types"
import { ParsedDescription, SystemContext } from "./types"
import { normalizeStride } from "./constants"

export function parseDescription(description: string): ParsedDescription {
  const result: ParsedDescription = {}

  function extractSection(text: string, sectionName: string): string | null {
    const pattern = new RegExp(
      `\\*\\*${sectionName}\\*\\*:\\s*([\\s\\S]*?)(?=\\n\\*\\*|$)`
    )
    const match = text.match(pattern)
    if (match) {
      let content = match[1].trim()
      const mitigationsIdx = content.indexOf("\n-")
      if (mitigationsIdx > 0 && !sectionName.toLowerCase().includes("mitigation")) {
        content = content.substring(0, mitigationsIdx).trim()
      }
      return content
    }
    return null
  }

  result.threatStatement = extractSection(description, "Threat Statement") || undefined
  result.trustBoundary = extractSection(description, "Trust Boundary") || undefined
  result.impactedAssets = extractSection(description, "Impacted Assets") || undefined
  result.assumptions = extractSection(description, "Assumptions") || undefined

  const mitigationsMatch = description.match(/\*\*Mitigations\*\*:\s*([\s\S]*)$/)
  if (mitigationsMatch) {
    const mitigationText = mitigationsMatch[1].trim()
    const items = mitigationText
      .split("\n")
      .filter((line) => line.trim().startsWith("-"))
    result.mitigations = items.map((item) => item.replace(/^-\s*/, "").trim())
  }

  if (
    !result.threatStatement &&
    !result.trustBoundary &&
    !result.impactedAssets
  ) {
    result.rawText = description
  }

  return result
}

// Normalize impacted_assets into a string array.
// Source priority: metadata.impacted_assets (string|array) → parsed from description → []
export function extractImpactedAssets(issue: Issue, parsed?: ParsedDescription): string[] {
  const meta = issue.metadata?.impacted_assets
  if (Array.isArray(meta)) {
    return meta.map((x) => String(x).trim()).filter(Boolean)
  }
  if (typeof meta === "string" && meta.trim()) {
    return splitAssets(meta)
  }
  if (parsed?.impactedAssets) {
    return splitAssets(parsed.impactedAssets)
  }
  return []
}

function splitAssets(raw: string): string[] {
  return raw
    .split(/[,;\n]|\band\b/gi)
    .map((s) => s.replace(/^[-*\s]+|\s+$/g, ""))
    .filter(Boolean)
}

// Extract trust boundary and split by arrow into from/to
export function extractTrustBoundary(issue: Issue, parsed?: ParsedDescription): {
  raw?: string
  from?: string
  to?: string
} {
  const raw =
    (typeof issue.metadata?.trust_boundary === "string"
      ? issue.metadata.trust_boundary
      : undefined) || parsed?.trustBoundary
  if (!raw) return {}
  const parts = raw.split(/→|->|=>/).map((s) => s.trim()).filter(Boolean)
  if (parts.length >= 2) return { raw, from: parts[0], to: parts[1] }
  return { raw }
}

export function getStrideCategory(issue: Issue): string {
  const raw =
    issue.metadata?.stride_category || issue.rule_id?.split("/")[1] || "unknown"
  return normalizeStride(raw)
}

export function getSystemContext(issue: Issue): SystemContext {
  const parsed = issue.description ? parseDescription(issue.description) : undefined
  const components = extractImpactedAssets(issue, parsed)
  const boundary = extractTrustBoundary(issue, parsed)
  return {
    components,
    trustBoundary: boundary.raw,
    boundaryFrom: boundary.from,
    boundaryTo: boundary.to,
  }
}
