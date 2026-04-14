"use client"

import { useState } from "react"
import type { ThreatModelRendererProps, Issue, Severity } from "./types"

// STRIDE category colors matching Synthesis
const STRIDE_COLORS: Record<string, { bg: string; text: string; border: string }> = {
  spoofing: { bg: "#8b5cf6/10", text: "#6d28d9", border: "#c4b5fd" },
  tampering: { bg: "#ef4444/10", text: "#dc2626", border: "#fecaca" },
  repudiation: { bg: "#f59e0b/10", text: "#b45309", border: "#fde68a" },
  information_disclosure: { bg: "#3b82f6/10", text: "#2563eb", border: "#bfdbfe" },
  "information-disclosure": { bg: "#3b82f6/10", text: "#2563eb", border: "#bfdbfe" },
  denial_of_service: { bg: "#f97316/10", text: "#ea580c", border: "#fed7aa" },
  "denial-of-service": { bg: "#f97316/10", text: "#ea580c", border: "#fed7aa" },
  elevation_of_privilege: { bg: "#e11d48/10", text: "#be123c", border: "#fecdd3" },
  "elevation-of-privilege": { bg: "#e11d48/10", text: "#be123c", border: "#fecdd3" },
}

const SEVERITY_COLORS: Record<Severity, { bg: string; text: string; border: string }> = {
  critical: { bg: "rgba(239, 68, 68, 0.1)", text: "#dc2626", border: "#fecaca" },
  high: { bg: "rgba(249, 115, 22, 0.1)", text: "#ea580c", border: "#fed7aa" },
  medium: { bg: "rgba(234, 179, 8, 0.1)", text: "#a16207", border: "#fef08a" },
  low: { bg: "rgba(34, 197, 94, 0.1)", text: "#16a34a", border: "#bbf7d0" },
  info: { bg: "rgba(59, 130, 246, 0.1)", text: "#2563eb", border: "#bfdbfe" },
}

function getStrideColor(stride: string) {
  const normalized = stride.toLowerCase().replace(/\s+/g, "_")
  return STRIDE_COLORS[normalized] || { bg: "#f3f4f6", text: "#6b7280", border: "#d1d5db" }
}

function getStrideLabel(stride: string): string {
  const labels: Record<string, string> = {
    spoofing: "Spoofing",
    tampering: "Tampering",
    repudiation: "Repudiation",
    information_disclosure: "Information Disclosure",
    "information-disclosure": "Information Disclosure",
    denial_of_service: "Denial of Service",
    "denial-of-service": "Denial of Service",
    elevation_of_privilege: "Elevation of Privilege",
    "elevation-of-privilege": "Elevation of Privilege",
  }
  const normalized = stride.toLowerCase().replace(/\s+/g, "_")
  return labels[normalized] || stride
}

// Clean title by removing STRIDE prefix like "[Spoofing]" since we show it as a badge
function cleanTitle(title: string): string {
  return title.replace(/^\[[\w\s]+\]\s*/, "")
}

// Parse description to extract structured sections
function parseDescription(description: string): {
  summary: string
  impact?: string
  affectedComponents?: string
  attackVector?: string
} {
  const lines = description.split("\n")
  const result: ReturnType<typeof parseDescription> = { summary: "" }

  let currentSection: string | null = null
  const summaryLines: string[] = []

  for (const line of lines) {
    const trimmed = line.trim()
    if (trimmed.startsWith("**Impact:**") || trimmed.startsWith("Impact:")) {
      currentSection = "impact"
      result.impact = trimmed.replace(/^\*?\*?Impact:\*?\*?\s*/, "")
    } else if (trimmed.startsWith("**Affected Components:**") || trimmed.startsWith("Affected Components:")) {
      currentSection = "affected"
      result.affectedComponents = trimmed.replace(/^\*?\*?Affected Components:\*?\*?\s*/, "")
    } else if (trimmed.startsWith("**Attack Vector:**") || trimmed.startsWith("Attack Vector:")) {
      currentSection = "attack"
      result.attackVector = trimmed.replace(/^\*?\*?Attack Vector:\*?\*?\s*/, "")
    } else if (currentSection === "impact" && trimmed) {
      result.impact = (result.impact || "") + " " + trimmed
    } else if (currentSection === "affected" && trimmed) {
      result.affectedComponents = (result.affectedComponents || "") + " " + trimmed
    } else if (currentSection === "attack" && trimmed) {
      result.attackVector = (result.attackVector || "") + " " + trimmed
    } else if (!currentSection && trimmed) {
      summaryLines.push(trimmed)
    }
  }

  result.summary = summaryLines.join(" ")
  return result
}

// Scope section component
function ScopeSection({ scope }: { scope: any }) {
  if (!scope) return null

  return (
    <div
      style={{
        marginBottom: "24px",
        padding: "16px",
        backgroundColor: "#f8fafc",
        borderRadius: "8px",
        border: "1px solid #e2e8f0",
      }}
    >
      <h3
        style={{
          fontSize: "14px",
          fontWeight: 600,
          color: "#475569",
          marginBottom: "12px",
          display: "flex",
          alignItems: "center",
          gap: "8px",
        }}
      >
        <span style={{ fontSize: "16px" }}>🎯</span> Analysis Scope
      </h3>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: "12px" }}>
        {scope.files_analyzed !== undefined && (
          <div>
            <p style={{ fontSize: "12px", color: "#64748b", margin: 0 }}>Files Analyzed</p>
            <p style={{ fontSize: "18px", fontWeight: 600, color: "#1e293b", margin: 0 }}>{scope.files_analyzed}</p>
          </div>
        )}
        {scope.components !== undefined && (
          <div>
            <p style={{ fontSize: "12px", color: "#64748b", margin: 0 }}>Components</p>
            <p style={{ fontSize: "18px", fontWeight: 600, color: "#1e293b", margin: 0 }}>{scope.components}</p>
          </div>
        )}
        {scope.data_flows !== undefined && (
          <div>
            <p style={{ fontSize: "12px", color: "#64748b", margin: 0 }}>Data Flows</p>
            <p style={{ fontSize: "18px", fontWeight: 600, color: "#1e293b", margin: 0 }}>{scope.data_flows}</p>
          </div>
        )}
        {scope.entry_points !== undefined && (
          <div>
            <p style={{ fontSize: "12px", color: "#64748b", margin: 0 }}>Entry Points</p>
            <p style={{ fontSize: "18px", fontWeight: 600, color: "#1e293b", margin: 0 }}>{scope.entry_points}</p>
          </div>
        )}
      </div>
      {scope.focus_areas && scope.focus_areas.length > 0 && (
        <div style={{ marginTop: "12px" }}>
          <p style={{ fontSize: "12px", color: "#64748b", margin: 0, marginBottom: "6px" }}>Focus Areas</p>
          <div style={{ display: "flex", gap: "6px", flexWrap: "wrap" }}>
            {scope.focus_areas.map((area: string, idx: number) => (
              <span
                key={idx}
                style={{
                  padding: "2px 8px",
                  backgroundColor: "#e0e7ff",
                  color: "#3730a3",
                  borderRadius: "4px",
                  fontSize: "12px",
                }}
              >
                {area}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

function Badge({
  children,
  style,
}: {
  children: React.ReactNode
  style: React.CSSProperties
}) {
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        padding: "2px 8px",
        borderRadius: "4px",
        fontSize: "12px",
        fontWeight: 500,
        border: "1px solid",
        ...style,
      }}
    >
      {children}
    </span>
  )
}

function SeverityBadge({ severity }: { severity: Severity }) {
  const colors = SEVERITY_COLORS[severity]
  return (
    <Badge
      style={{
        backgroundColor: colors.bg,
        color: colors.text,
        borderColor: colors.border,
        textTransform: "uppercase",
      }}
    >
      {severity}
    </Badge>
  )
}

function StrideBadge({ stride }: { stride: string }) {
  const colors = getStrideColor(stride)
  return (
    <Badge
      style={{
        backgroundColor: colors.bg,
        color: colors.text,
        borderColor: colors.border,
      }}
    >
      {getStrideLabel(stride)}
    </Badge>
  )
}

function ThreatCard({ issue }: { issue: Issue }) {
  const [expanded, setExpanded] = useState(false)

  const strideCategory =
    issue.metadata?.stride_category || issue.rule_id?.split("/")[1] || "unknown"

  const title = cleanTitle(issue.title)
  const parsedDesc = issue.description ? parseDescription(issue.description) : null

  return (
    <div
      onClick={() => setExpanded(!expanded)}
      style={{
        padding: "16px",
        border: "1px solid #e5e7eb",
        borderRadius: "8px",
        marginBottom: "12px",
        cursor: "pointer",
        transition: "border-color 0.2s",
      }}
      onMouseEnter={(e) => (e.currentTarget.style.borderColor = "#6366f1")}
      onMouseLeave={(e) => (e.currentTarget.style.borderColor = "#e5e7eb")}
    >
      <div style={{ display: "flex", justifyContent: "space-between", gap: "16px" }}>
        <div style={{ flex: 1 }}>
          <div style={{ display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap" }}>
            <SeverityBadge severity={issue.severity} />
            <StrideBadge stride={strideCategory} />
            <span style={{ fontWeight: 500 }}>{title}</span>
          </div>
          {parsedDesc?.summary && (
            <p
              style={{
                fontSize: "14px",
                color: "#6b7280",
                marginTop: "8px",
                overflow: "hidden",
                display: "-webkit-box",
                WebkitLineClamp: 2,
                WebkitBoxOrient: "vertical",
              }}
            >
              {parsedDesc.summary}
            </p>
          )}
        </div>
      </div>

      {issue.location?.file_path && (
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "8px",
            fontSize: "14px",
            color: "#6b7280",
            marginTop: "12px",
          }}
        >
          <span style={{ fontFamily: "monospace" }}>
            {issue.location.file_path}
            {issue.location.line_start && `:${issue.location.line_start}`}
          </span>
        </div>
      )}

      {expanded && (
        <div style={{ paddingTop: "12px", borderTop: "1px solid #e5e7eb", marginTop: "12px" }}>
          {parsedDesc?.summary && (
            <div style={{ marginBottom: "16px" }}>
              <h4 style={{ fontSize: "12px", fontWeight: 600, color: "#6b7280", marginBottom: "4px" }}>
                Description
              </h4>
              <p style={{ fontSize: "14px" }}>{parsedDesc.summary}</p>
            </div>
          )}

          {parsedDesc?.impact && (
            <div style={{ marginBottom: "16px" }}>
              <h4 style={{ fontSize: "12px", fontWeight: 600, color: "#dc2626", marginBottom: "4px" }}>
                Impact
              </h4>
              <p style={{ fontSize: "14px" }}>{parsedDesc.impact}</p>
            </div>
          )}

          {parsedDesc?.affectedComponents && (
            <div style={{ marginBottom: "16px" }}>
              <h4 style={{ fontSize: "12px", fontWeight: 600, color: "#6b7280", marginBottom: "4px" }}>
                Affected Components
              </h4>
              <p style={{ fontSize: "14px", fontFamily: "monospace" }}>{parsedDesc.affectedComponents}</p>
            </div>
          )}

          {parsedDesc?.attackVector && (
            <div style={{ marginBottom: "16px" }}>
              <h4 style={{ fontSize: "12px", fontWeight: 600, color: "#ea580c", marginBottom: "4px" }}>
                Attack Vector
              </h4>
              <p style={{ fontSize: "14px" }}>{parsedDesc.attackVector}</p>
            </div>
          )}

          {issue.metadata?.threat_statement && (
            <div
              style={{
                backgroundColor: "#f9fafb",
                borderRadius: "8px",
                padding: "12px",
                border: "1px solid #e5e7eb",
                marginBottom: "16px",
              }}
            >
              <h4 style={{ fontSize: "12px", fontWeight: 600, color: "#6b7280", marginBottom: "8px" }}>
                Threat Statement
              </h4>
              <p style={{ fontSize: "14px" }}>{issue.metadata.threat_statement}</p>
            </div>
          )}

          {issue.metadata?.mitigations && Array.isArray(issue.metadata.mitigations) && (
            <div style={{ marginBottom: "16px" }}>
              <h4 style={{ fontSize: "12px", fontWeight: 600, color: "#6b7280", marginBottom: "8px" }}>
                Mitigations ({issue.metadata.mitigations.length})
              </h4>
              <ul style={{ margin: 0, padding: 0, listStyle: "none" }}>
                {issue.metadata.mitigations.map((mit: any, idx: number) => (
                  <li
                    key={idx}
                    style={{
                      fontSize: "14px",
                      padding: "8px",
                      backgroundColor: "rgba(0,0,0,0.03)",
                      borderRadius: "4px",
                      border: "1px solid #e5e7eb",
                      marginBottom: "8px",
                    }}
                  >
                    {typeof mit === "string" ? mit : mit.description || JSON.stringify(mit)}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {issue.fix_suggestion && (
            <div
              style={{
                padding: "12px",
                backgroundColor: "rgba(34, 197, 94, 0.05)",
                borderRadius: "6px",
                border: "1px solid #bbf7d0",
              }}
            >
              <p style={{ fontSize: "12px", color: "#6b7280", marginBottom: "4px" }}>Suggested Fix:</p>
              <p style={{ fontSize: "14px" }}>{issue.fix_suggestion}</p>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export function ThreatModelRenderer({ output }: ThreatModelRendererProps) {
  const issues = output.issues || []
  const scope = output.data?.scope

  // Group by STRIDE category
  const byStride = issues.reduce(
    (acc, issue) => {
      const stride =
        issue.metadata?.stride_category || issue.rule_id?.split("/")[1] || "unknown"
      const normalized = stride.toLowerCase().replace(/\s+/g, "_")
      acc[normalized] = (acc[normalized] || 0) + 1
      return acc
    },
    {} as Record<string, number>
  )

  // Group by severity
  const bySeverity = issues.reduce(
    (acc, issue) => {
      const sev = issue.severity || "info"
      acc[sev] = (acc[sev] || 0) + 1
      return acc
    },
    {} as Record<string, number>
  )

  const strideCategories = [
    "spoofing",
    "tampering",
    "repudiation",
    "information_disclosure",
    "denial_of_service",
    "elevation_of_privilege",
  ]

  return (
    <div>
      {/* Scope Section */}
      <ScopeSection scope={scope} />

      {/* STRIDE Summary */}
      <div style={{ marginBottom: "24px" }}>
        <h3 style={{ fontSize: "14px", fontWeight: 500, color: "#6b7280", marginBottom: "12px" }}>
          STRIDE Categories
        </h3>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(6, 1fr)", gap: "8px" }}>
          {strideCategories.map((stride) => {
            const colors = getStrideColor(stride)
            return (
              <div
                key={stride}
                style={{
                  padding: "12px",
                  borderRadius: "8px",
                  textAlign: "center",
                  border: `1px solid ${colors.border}`,
                  backgroundColor: colors.bg,
                  color: colors.text,
                }}
              >
                <p style={{ fontSize: "24px", fontWeight: 700, margin: 0 }}>
                  {byStride[stride] || 0}
                </p>
                <p style={{ fontSize: "12px", margin: 0, overflow: "hidden", textOverflow: "ellipsis" }}>
                  {getStrideLabel(stride).split(" ")[0]}
                </p>
              </div>
            )
          })}
        </div>
      </div>

      {/* Severity Summary */}
      <div style={{ marginBottom: "24px" }}>
        <h3 style={{ fontSize: "14px", fontWeight: 500, color: "#6b7280", marginBottom: "12px" }}>
          By Severity
        </h3>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: "8px" }}>
          {(["critical", "high", "medium", "low", "info"] as const).map((severity) => {
            const colors = SEVERITY_COLORS[severity]
            return (
              <div
                key={severity}
                style={{
                  padding: "12px",
                  borderRadius: "8px",
                  textAlign: "center",
                  border: `1px solid ${colors.border}`,
                  backgroundColor: colors.bg,
                  color: colors.text,
                }}
              >
                <p style={{ fontSize: "24px", fontWeight: 700, margin: 0 }}>
                  {bySeverity[severity] || 0}
                </p>
                <p style={{ fontSize: "12px", textTransform: "uppercase", margin: 0 }}>{severity}</p>
              </div>
            )
          })}
        </div>
      </div>

      {/* Threats List */}
      {issues.length > 0 ? (
        <div>
          <h3 style={{ fontWeight: 500, display: "flex", alignItems: "center", gap: "8px", marginBottom: "8px" }}>
            Threats ({issues.length})
          </h3>
          <p style={{ fontSize: "14px", color: "#6b7280", marginBottom: "16px" }}>
            Click on a threat to see details
          </p>
          {issues.map((issue, index) => (
            <ThreatCard key={issue.issue_id || issue.id || index} issue={issue} />
          ))}
        </div>
      ) : (
        <div style={{ textAlign: "center", padding: "32px", color: "#6b7280" }}>
          <p>No threats identified</p>
        </div>
      )}
    </div>
  )
}
