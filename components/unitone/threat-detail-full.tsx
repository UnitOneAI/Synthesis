"use client"

import {
  AlertTriangle,
  BookOpen,
  CheckCircle2,
  ExternalLink,
  Shield,
  X,
  Zap,
} from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
} from "@/components/ui/dialog"
import { ScrollArea } from "@/components/ui/scroll-area"
import { CodeDiff } from "@/components/unitone/code-diff"

interface ThreatStatement {
  actor: string
  prerequisites?: string
  action: string
  asset: string
  impact: string
}

interface Mitigation {
  id: string
  description: string
  status: "Proposed" | "Implemented" | "Verified"
  codeSnippet?: {
    file: string
    line: number
    original: string
    fixed: string
  }
  jiraTicket?: {
    key: string
    summary: string
    status: "To Do" | "In Progress" | "Done"
  }
}

interface Threat {
  id: string
  title: string
  stride: string
  severity: "Critical" | "High" | "Medium" | "Low"
  status: "Identified" | "In Progress" | "Mitigated" | "Accepted"
  threatStatement: ThreatStatement
  trustBoundary: string
  assumptions: string[]
  mitigations: Mitigation[]
  relatedCVE?: string
}

function getSeverityColor(severity: string) {
  switch (severity) {
    case "Critical": return "bg-red-500/10 text-red-600 border-red-200"
    case "High": return "bg-orange-500/10 text-orange-600 border-orange-200"
    case "Medium": return "bg-yellow-500/10 text-yellow-700 border-yellow-200"
    case "Low": return "bg-green-500/10 text-green-600 border-green-200"
    default: return ""
  }
}

function getStrideColor(stride: string) {
  switch (stride) {
    case "Spoofing": return "bg-violet-500/10 text-violet-700 border-violet-200"
    case "Tampering": return "bg-red-500/10 text-red-600 border-red-200"
    case "Repudiation": return "bg-amber-500/10 text-amber-700 border-amber-200"
    case "Information Disclosure": return "bg-blue-500/10 text-blue-600 border-blue-200"
    case "Denial of Service": return "bg-orange-500/10 text-orange-600 border-orange-200"
    case "Elevation of Privilege": return "bg-rose-500/10 text-rose-700 border-rose-200"
    default: return ""
  }
}

function getStatusColor(status: string) {
  switch (status) {
    case "Identified": return "bg-red-500/10 text-red-600 border-red-200"
    case "In Progress": return "bg-blue-500/10 text-blue-600 border-blue-200"
    case "Mitigated": return "bg-green-500/10 text-green-600 border-green-200"
    case "Accepted": return "bg-muted text-muted-foreground border-border"
    default: return ""
  }
}

interface ThreatDetailFullProps {
  threat: Threat
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function ThreatDetailFull({
  threat,
  open,
  onOpenChange,
}: ThreatDetailFullProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-6xl max-h-[90vh] p-0 gap-0">
        {/* Header */}
        <div className="p-6 border-b border-border">
          <div className="flex items-center justify-between mb-3">
            <span className="text-sm font-mono text-muted-foreground">
              {threat.id}
            </span>
            <button
              type="button"
              onClick={() => onOpenChange(false)}
              className="size-8 rounded-md hover:bg-muted flex items-center justify-center"
            >
              <X className="size-4" />
            </button>
          </div>
          <h2 className="text-xl font-semibold">{threat.title}</h2>
          <div className="flex items-center gap-2 mt-3">
            <Badge variant="outline" className={`${getSeverityColor(threat.severity)} text-xs`}>
              {threat.severity}
            </Badge>
            <Badge variant="outline" className={`${getStrideColor(threat.stride)} text-xs`}>
              {threat.stride}
            </Badge>
            <Badge variant="outline" className={`${getStatusColor(threat.status)} text-xs`}>
              {threat.status}
            </Badge>
          </div>
        </div>

        {/* Body */}
        <ScrollArea className="max-h-[calc(90vh-140px)]">
          <div className="p-6 space-y-8">
            {/* Threat Statement */}
            <div>
              <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
                <BookOpen className="size-4 text-primary" />
                Threat Statement
              </h3>
              <div className="bg-muted/50 rounded-lg p-4 border border-border">
                <p className="text-sm leading-relaxed">
                  <span className="font-medium text-red-600">{threat.threatStatement.actor}</span>{" "}
                  {threat.threatStatement.prerequisites && (
                    <span className="text-muted-foreground">
                      with {threat.threatStatement.prerequisites}{" "}
                    </span>
                  )}
                  <span>{threat.threatStatement.action}</span>{" "}
                  <span className="font-medium text-orange-600">{threat.threatStatement.asset}</span>{" "}
                  <span className="font-medium">{threat.threatStatement.impact}</span>
                </p>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-6">
              {/* Trust Boundary */}
              <div>
                <h3 className="text-sm font-semibold mb-2">Trust Boundary Crossed</h3>
                <div className="flex items-center gap-2 text-sm text-muted-foreground">
                  <div className="size-2 rounded-full bg-orange-400" />
                  {threat.trustBoundary}
                </div>
              </div>

              {/* Related CVE */}
              {threat.relatedCVE && (
                <div>
                  <h3 className="text-sm font-semibold mb-2">Related CVE</h3>
                  <div className="flex items-center gap-3 p-3 rounded-lg bg-red-50 border border-red-200">
                    <AlertTriangle className="size-4 text-red-500" />
                    <span className="text-sm text-red-700 font-mono font-medium">
                      {threat.relatedCVE}
                    </span>
                    <Button variant="ghost" size="sm" className="ml-auto gap-1 text-red-600 text-xs">
                      View <ExternalLink className="size-3" />
                    </Button>
                  </div>
                </div>
              )}
            </div>

            {/* Assumptions */}
            {threat.assumptions.length > 0 && (
              <div>
                <h3 className="text-sm font-semibold mb-3">Assumptions</h3>
                <ul className="space-y-2">
                  {threat.assumptions.map((a, i) => (
                    <li
                      key={`full-assumption-${threat.id}-${i}`}
                      className="flex items-start gap-2 text-sm text-muted-foreground"
                    >
                      <AlertTriangle className="size-3.5 text-amber-500 mt-0.5 shrink-0" />
                      {a}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* Mitigations - Full Detail */}
            <div>
              <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
                <Shield className="size-4 text-primary" />
                Mitigations ({threat.mitigations.length})
              </h3>
              <div className="space-y-4">
                {threat.mitigations.map((mit) => (
                  <div key={mit.id} className="rounded-lg border border-border p-4 space-y-3">
                    <div className="flex items-start justify-between gap-3">
                      <p className="text-sm flex-1">{mit.description}</p>
                      <Badge
                        variant="outline"
                        className={`text-xs shrink-0 ${
                          mit.status === "Verified"
                            ? "bg-green-500/10 text-green-600 border-green-200"
                            : mit.status === "Implemented"
                              ? "bg-blue-500/10 text-blue-600 border-blue-200"
                              : "bg-amber-500/10 text-amber-600 border-amber-200"
                        }`}
                      >
                        {mit.status}
                      </Badge>
                    </div>

                    {mit.codeSnippet && (
                      <CodeDiff
                        original={mit.codeSnippet.original}
                        fixed={mit.codeSnippet.fixed}
                        filePath={mit.codeSnippet.file}
                        lineStart={mit.codeSnippet.line}
                      />
                    )}

                    {mit.jiraTicket && (
                      <div className="flex items-center gap-3 p-3 rounded-md bg-muted/50 border border-border">
                        <div className="size-6 rounded bg-blue-600 flex items-center justify-center">
                          <span className="text-xs font-bold text-white">J</span>
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-mono text-primary">{mit.jiraTicket.key}</span>
                            <span className="text-sm truncate">{mit.jiraTicket.summary}</span>
                          </div>
                        </div>
                        <Badge
                          variant="outline"
                          className={`text-xs ${
                            mit.jiraTicket.status === "Done"
                              ? "bg-green-500/10 text-green-600 border-green-200"
                              : mit.jiraTicket.status === "In Progress"
                                ? "bg-blue-500/10 text-blue-600 border-blue-200"
                                : "bg-muted text-muted-foreground"
                          }`}
                        >
                          {mit.jiraTicket.status}
                        </Badge>
                      </div>
                    )}
                  </div>
                ))}

                {threat.mitigations.length === 0 && (
                  <div className="text-sm text-muted-foreground p-4 bg-muted/30 rounded-lg text-center">
                    No mitigations defined yet.
                  </div>
                )}
              </div>
            </div>
          </div>
        </ScrollArea>
      </DialogContent>
    </Dialog>
  )
}
