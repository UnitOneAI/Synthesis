"use client"

import { useEffect, useState } from "react"
import { Issue, Severity } from "../types"
import {
  AlertTriangle,
  CheckCircle2,
  ExternalLink,
  FileCode,
  Lock,
  Maximize2,
  Minimize2,
  Shield,
  X,
} from "lucide-react"
import { Badge } from "../primitives"
import { Button } from "../primitives"
import { SeverityBadge, StrideBadge } from "./badges"
import { CodeDiff, looksLikeUnifiedDiff } from "./CodeDiff"
import { ApplyFixButton } from "./ApplyFixButton"
import { ThreatStatement } from "./ThreatStatement"
import { OwaspRiskRating } from "./OwaspRiskRating"
import { JiraTicketButton } from "./JiraTicketButton"
import { ActionsMenu } from "./ActionsMenu"
import { cleanTitle } from "../lib/constants"
import { getStrideCategory, parseDescription } from "../lib/parse"
import { maybeCalculateRiskRating } from "../lib/owasp-risk"

type ThreatStatus = "Identified" | "In Progress" | "Mitigated" | "Accepted"

interface Props {
  issue: Issue | null
  onClose: () => void
}

// Right-aligned slide-over detail panel with full Synthesis-style feature
// parity: expand/collapse toggle, OWASP risk rating, structured threat
// statement, assumptions, mitigations (diff + Jira + apply fix), CVE link,
// and local status tracking.
export function ThreatDetailPanel({ issue, onClose }: Props) {
  const [expanded, setExpanded] = useState(false)
  const [localStatus, setLocalStatus] = useState<ThreatStatus | null>(null)

  useEffect(() => {
    setLocalStatus(null)
    setExpanded(false)
  }, [issue?.issue_id])

  useEffect(() => {
    function handleKey(e: KeyboardEvent) {
      if (e.key === "Escape") onClose()
    }
    if (issue) window.addEventListener("keydown", handleKey)
    return () => window.removeEventListener("keydown", handleKey)
  }, [issue, onClose])

  const open = issue !== null

  return (
    <>
      <div
        className={`fixed inset-0 bg-black/20 z-40 transition-opacity ${
          open ? "opacity-100" : "opacity-0 pointer-events-none"
        }`}
        onClick={onClose}
      />
      <aside
        className={`fixed right-0 top-0 bottom-0 bg-background border-l shadow-2xl z-50 flex flex-col transition-all duration-300 ${
          open ? "translate-x-0" : "translate-x-full"
        } ${expanded ? "w-full md:w-[85vw]" : "w-full sm:w-[640px]"}`}
      >
        {issue && (
          <PanelBody
            issue={issue}
            localStatus={localStatus}
            onSetStatus={setLocalStatus}
            expanded={expanded}
            onToggleExpand={() => setExpanded(!expanded)}
            onClose={onClose}
          />
        )}
      </aside>
    </>
  )
}

function PanelBody({
  issue,
  localStatus,
  onSetStatus,
  expanded,
  onToggleExpand,
  onClose,
}: {
  issue: Issue
  localStatus: ThreatStatus | null
  onSetStatus: (s: ThreatStatus | null) => void
  expanded: boolean
  onToggleExpand: () => void
  onClose: () => void
}) {
  const stride = getStrideCategory(issue)
  const parsed = issue.description ? parseDescription(issue.description) : null
  const title = cleanTitle(issue.title)
  const mitigations = extractMitigations(issue, parsed)
  const rating = maybeCalculateRiskRating(
    issue.metadata?.owasp_likelihood,
    issue.metadata?.owasp_impact
  )
  const assumptions = extractAssumptions(issue, parsed)
  const cve = extractCve(issue)
  const status = localStatus || "Identified"

  return (
    <>
      <div className="flex items-start justify-between p-6 border-b gap-4">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap mb-2">
            <StrideBadge stride={stride} />
            <SeverityBadge severity={issue.severity} />
            <StatusBadge status={status} />
          </div>
          <h2 className="text-lg font-semibold leading-tight">{title}</h2>
          {issue.location?.file_path && (
            <div className="flex items-center gap-1.5 text-xs text-muted-foreground font-mono mt-2">
              <FileCode className="h-3 w-3" />
              <span>
                {issue.location.file_path}
                {issue.location.line_start ? `:${issue.location.line_start}` : ""}
              </span>
            </div>
          )}
        </div>
        <div className="flex items-center gap-1">
          <button
            onClick={onToggleExpand}
            className="p-1 rounded-md hover:bg-muted text-muted-foreground"
            aria-label={expanded ? "Collapse" : "Expand"}
          >
            {expanded ? <Minimize2 className="h-4 w-4" /> : <Maximize2 className="h-4 w-4" />}
          </button>
          <button
            onClick={onClose}
            className="p-1 rounded-md hover:bg-muted text-muted-foreground"
            aria-label="Close"
          >
            <X className="h-5 w-5" />
          </button>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto">
        <div className="p-6 space-y-6">
          <ThreatStatement issue={issue} fallback={parsed?.threatStatement} />

          <div className="grid md:grid-cols-2 gap-6">
            <TrustBoundarySection boundary={extractTrustBoundary(issue, parsed)} />
            {cve && <CveSection cve={cve} />}
          </div>

          {rating && <OwaspRiskRating rating={rating} />}

          {assumptions.length > 0 && (
            <section>
              <h3 className="text-sm font-semibold mb-2">Assumptions</h3>
              <ul className="space-y-2">
                {assumptions.map((a, idx) => (
                  <li key={idx} className="flex items-start gap-2 text-sm text-muted-foreground">
                    <AlertTriangle className="h-3.5 w-3.5 text-amber-500 shrink-0 mt-0.5" />
                    <span>{a}</span>
                  </li>
                ))}
              </ul>
            </section>
          )}

          <section>
            <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
              <Shield className="h-4 w-4 text-primary" />
              Mitigations{mitigations.length > 0 ? ` (${mitigations.length})` : ""}
            </h3>
            {mitigations.length === 0 ? (
              <p className="text-sm text-muted-foreground">No mitigations provided.</p>
            ) : (
              <div className="space-y-4">
                {mitigations.map((m, idx) => (
                  <MitigationCard key={idx} mitigation={m} />
                ))}
              </div>
            )}
          </section>
        </div>
      </div>

      <div className="border-t p-4 flex items-center justify-between gap-2 bg-muted/20">
        <ActionsMenu
          items={[
            {
              label: "Mark as Identified",
              onClick: () => onSetStatus("Identified"),
              disabled: status === "Identified",
            },
            {
              label: "Mark as In Progress",
              onClick: () => onSetStatus("In Progress"),
              disabled: status === "In Progress",
            },
            {
              label: "Mark as Mitigated",
              onClick: () => onSetStatus("Mitigated"),
              disabled: status === "Mitigated",
            },
          ]}
        />
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" disabled>
            Create All Tickets
          </Button>
          <Button size="sm" onClick={() => onSetStatus("Accepted")} disabled={status === "Accepted"}>
            <CheckCircle2 className="h-3.5 w-3.5 mr-1" />
            Accept Risk
          </Button>
        </div>
      </div>
    </>
  )
}

function StatusBadge({ status }: { status: ThreatStatus }) {
  const cls =
    status === "Mitigated"
      ? "bg-green-500/10 text-green-600 border-green-200"
      : status === "In Progress"
      ? "bg-blue-500/10 text-blue-600 border-blue-200"
      : status === "Accepted"
      ? "bg-muted text-muted-foreground"
      : "bg-red-500/10 text-red-600 border-red-200"
  return (
    <Badge variant="outline" className={`${cls} text-xs`}>
      {status}
    </Badge>
  )
}

function TrustBoundarySection({ boundary }: { boundary: string | undefined }) {
  if (!boundary) return null
  return (
    <section>
      <h3 className="text-sm font-semibold mb-2 flex items-center gap-2">
        <Lock className="h-4 w-4 text-primary" />
        Trust Boundary
      </h3>
      <div className="flex items-center gap-2 text-sm">
        <span className="size-2 rounded-full bg-orange-400" />
        <span className="text-muted-foreground">{boundary}</span>
      </div>
    </section>
  )
}

function CveSection({ cve }: { cve: string }) {
  const url = cveUrl(cve)
  return (
    <section>
      <h3 className="text-sm font-semibold mb-2">Related Vulnerability</h3>
      <div className="flex items-center gap-2 p-3 rounded-lg bg-red-500/5 border border-red-200/50">
        <AlertTriangle className="h-4 w-4 text-red-500 shrink-0" />
        <span className="font-mono text-sm text-red-700">{cve}</span>
        {url && (
          <a
            href={url}
            target="_blank"
            rel="noopener noreferrer"
            className="ml-auto text-xs text-red-600 hover:text-red-700 hover:underline flex items-center gap-1"
          >
            View <ExternalLink className="h-3 w-3" />
          </a>
        )}
      </div>
    </section>
  )
}

interface Mitigation {
  description: string
  codeOriginal?: string
  codeFixed?: string
  unifiedDiff?: string
  filePath?: string
  lineStart?: number
  status?: "Proposed" | "Implemented" | "Verified"
  jiraKey?: string
  jiraUrl?: string
}

function MitigationCard({ mitigation }: { mitigation: Mitigation }) {
  const hasDiff = !!mitigation.codeFixed || !!mitigation.codeOriginal || !!mitigation.unifiedDiff
  const status = mitigation.status || "Proposed"
  const statusCls =
    status === "Verified"
      ? "bg-green-500/10 text-green-600 border-green-200"
      : status === "Implemented"
      ? "bg-blue-500/10 text-blue-600 border-blue-200"
      : "bg-amber-500/10 text-amber-600 border-amber-200"

  return (
    <div className="border rounded-lg p-4 space-y-3">
      <div className="flex items-start justify-between gap-3">
        <p className="text-sm flex-1">{mitigation.description}</p>
        <Badge variant="outline" className={`${statusCls} text-xs shrink-0`}>
          {status}
        </Badge>
      </div>

      {hasDiff && (
        <CodeDiff
          filePath={mitigation.filePath}
          lineStart={mitigation.lineStart}
          original={mitigation.codeOriginal}
          fixed={mitigation.codeFixed}
          unified={mitigation.unifiedDiff}
        />
      )}

      <div className="flex items-center gap-2 pt-1 flex-wrap">
        {hasDiff && <ApplyFixButton />}
        <JiraTicketButton
          existingKey={mitigation.jiraKey}
          existingUrl={mitigation.jiraUrl}
          configured={false}
        />
      </div>
    </div>
  )
}

function extractMitigations(
  issue: Issue,
  parsed: ReturnType<typeof parseDescription> | null
): Mitigation[] {
  const out: Mitigation[] = []

  const metaMitigations = issue.metadata?.mitigations
  if (Array.isArray(metaMitigations)) {
    for (const m of metaMitigations) {
      if (typeof m === "string") {
        out.push({ description: m })
      } else if (m && typeof m === "object") {
        const desc = m.description || m.name || m.summary || m.text || "Apply the suggested fix"
        out.push({
          description: desc,
          codeOriginal: m.codeOriginal || m.code_original || m.original,
          codeFixed: m.codeFixed || m.code_fixed || m.fixed || m.code,
          filePath: m.filePath || m.file_path || m.codeFile || m.code_file || issue.location?.file_path,
          lineStart: m.lineStart || m.line_start || m.codeLine || m.code_line || issue.location?.line_start,
          status: m.status || "Proposed",
          jiraKey: m.jira?.key || m.jiraKey,
          jiraUrl: m.jira?.url || m.jiraUrl,
        })
      }
    }
  }

  if (out.length === 0 && parsed?.mitigations) {
    for (const text of parsed.mitigations) out.push({ description: text })
  }

  if (issue.fix_suggestion) {
    const isDiff = looksLikeUnifiedDiff(issue.fix_suggestion)
    if (isDiff) {
      out.push({
        description: "Suggested fix",
        unifiedDiff: issue.fix_suggestion,
        filePath: issue.location?.file_path,
      })
    } else if (out.length === 0) {
      out.push({ description: issue.fix_suggestion })
    }
  }

  return out
}

function extractAssumptions(
  issue: Issue,
  parsed: ReturnType<typeof parseDescription> | null
): string[] {
  const meta = issue.metadata?.assumptions
  if (Array.isArray(meta)) return meta.map((a) => String(a).trim()).filter(Boolean)
  if (typeof meta === "string" && meta.trim()) {
    return meta.split(/;|\n/).map((s) => s.trim()).filter(Boolean)
  }
  if (parsed?.assumptions) {
    return parsed.assumptions.split(/;|\n/).map((s) => s.trim()).filter(Boolean)
  }
  return []
}

function extractTrustBoundary(
  issue: Issue,
  parsed: ReturnType<typeof parseDescription> | null
): string | undefined {
  const meta = issue.metadata?.trust_boundary
  if (typeof meta === "string" && meta.trim()) return meta
  return parsed?.trustBoundary
}

function extractCve(issue: Issue): string | undefined {
  const v =
    issue.metadata?.related_cve ||
    issue.metadata?.relatedCve ||
    issue.metadata?.relatedCVE ||
    issue.cwe_id
  if (typeof v === "string" && v.trim()) return v
  if (Array.isArray(v) && v.length > 0) return String(v[0])
  return undefined
}

function cveUrl(cve: string): string | null {
  if (/^CVE-\d+-\d+$/i.test(cve)) return `https://nvd.nist.gov/vuln/detail/${cve}`
  if (/^CWE-\d+$/i.test(cve)) return `https://cwe.mitre.org/data/definitions/${cve.slice(4)}.html`
  return null
}
