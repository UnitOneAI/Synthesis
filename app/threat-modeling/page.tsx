"use client"

import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import {
  AlertTriangle,
  ArrowRight,
  BookOpen,
  Calendar,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  ClipboardCopy,
  Clock,
  Download,
  ExternalLink,
  FileCode,
  FileDown,
  FileSearch,
  FileText,
  GitBranch,
  Layers,
  Lightbulb,
  Link2,
  Loader2,
  Maximize2,
  Minimize2,
  Plus,
  Shield,
  Target,
  Trash2,
  Upload,
  X,
  Zap,
} from "lucide-react"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible"
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Textarea } from "@/components/ui/textarea"
import { AppHeader, AppSidebar, ProjectProvider, useProject } from "@/components/unitone/app-sidebar"
import { ApplyFixButton } from "@/components/unitone/apply-fix-button"
import { CodeDiff } from "@/components/unitone/code-diff"
import { JiraTicketButton } from "@/components/unitone/jira-ticket-button"
import { MermaidDiagram } from "@/components/unitone/mermaid-diagram"
import { ThreatDetailFull } from "@/components/unitone/threat-detail-full"
import { ThreatFilters } from "@/components/unitone/threat-filters"

// ── Types (matching API response) ──

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

interface SessionStats {
  total: number
  critical: number
  high: number
  medium: number
  low: number
  mitigated: number
}

interface InsightMetrics {
  strideCoverage: {
    covered: string[]
    missing: string[]
    total: number
    percentage: number
  }
  severityDistribution: {
    critical: number
    high: number
    medium: number
    low: number
  }
  mitigationRate: {
    threatsWithMitigation: number
    totalThreats: number
    percentage: number
  }
  strideBreakdown: {
    category: string
    count: number
    abbreviation: string
  }[]
  riskScore: number
  recommendations: string[]
}

interface SessionSummary {
  id: string
  name: string
  source: "design-doc" | "github-repo"
  sourceRef: string
  createdAt: string
  status: "Processing" | "Review" | "Complete" | "Failed"
  framework: string
  stats: SessionStats
}

interface SessionDetail extends SessionSummary {
  description: string
  dataFlowDiagram: string
  threats: Threat[]
  insights: InsightMetrics
  designReview?: DesignReviewData
}

interface DesignEnhancement {
  section: string
  gap: string
  suggestion: string
  rationale: string
  severity: string
  strideCategory: string
}

interface PreCodeRisk {
  title: string
  category: string
  severity: string
  component: string
  designDecision: string
  recommendation: string
  implementationPhase: "pre-code" | "during-code"
}

interface DesignReviewData {
  enhancements: DesignEnhancement[]
  risks: PreCodeRisk[]
  contextLayer: string | null
}

// ── Helpers ──

function getSeverityColor(severity: string) {
  switch (severity) {
    case "Critical":
      return "bg-red-500/10 text-red-600 border-red-200"
    case "High":
      return "bg-orange-500/10 text-orange-600 border-orange-200"
    case "Medium":
      return "bg-yellow-500/10 text-yellow-700 border-yellow-200"
    case "Low":
      return "bg-green-500/10 text-green-600 border-green-200"
    default:
      return ""
  }
}

function getStrideColor(stride: string) {
  switch (stride) {
    case "Spoofing":
      return "bg-violet-500/10 text-violet-700 border-violet-200"
    case "Tampering":
      return "bg-red-500/10 text-red-600 border-red-200"
    case "Repudiation":
      return "bg-amber-500/10 text-amber-700 border-amber-200"
    case "Information Disclosure":
      return "bg-blue-500/10 text-blue-600 border-blue-200"
    case "Denial of Service":
      return "bg-orange-500/10 text-orange-600 border-orange-200"
    case "Elevation of Privilege":
      return "bg-rose-500/10 text-rose-700 border-rose-200"
    default:
      return ""
  }
}

function getStatusColor(status: string) {
  switch (status) {
    case "Identified":
      return "bg-red-500/10 text-red-600 border-red-200"
    case "In Progress":
      return "bg-blue-500/10 text-blue-600 border-blue-200"
    case "Mitigated":
      return "bg-green-500/10 text-green-600 border-green-200"
    case "Accepted":
      return "bg-muted text-muted-foreground border-border"
    default:
      return ""
  }
}

function StrideIcon({ category }: { category: string }) {
  const iconMap: Record<string, string> = {
    Spoofing: "S",
    Tampering: "T",
    Repudiation: "R",
    "Information Disclosure": "I",
    "Denial of Service": "D",
    "Elevation of Privilege": "E",
  }
  return (
    <span className="size-6 rounded bg-foreground/10 flex items-center justify-center text-xs font-bold text-foreground/70">
      {iconMap[category] || "?"}
    </span>
  )
}

function formatDate(iso: string) {
  return new Date(iso).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
  })
}

// ── New Session Dialog ──

function NewSessionDialog({
  open,
  onOpenChange,
  onStart,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  onStart: (data: {
    name: string
    source: "design-doc" | "github-repo"
    sourceRef: string
    framework: string
    file?: File
    documentContent?: string
  }) => Promise<boolean>
}) {
  const [sourceType, setSourceType] = useState<"design-doc" | "github-repo">(
    "github-repo",
  )
  const [name, setName] = useState("")
  const [sourceRef, setSourceRef] = useState("")
  const [framework, setFramework] = useState("STRIDE")
  const [uploadedFile, setUploadedFile] = useState<File | null>(null)
  const [pastedText, setPastedText] = useState("")
  const [inputMode, setInputMode] = useState<"upload" | "paste">("upload")
  const [creating, setCreating] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>New Threat Model Session</DialogTitle>
        </DialogHeader>

        <div className="space-y-5">
          {/* Source Type Toggle */}
          <div>
            <label className="text-sm font-medium text-foreground mb-2 block">
              Source Type
            </label>
            <div className="grid grid-cols-2 gap-3">
              <button
                type="button"
                onClick={() => setSourceType("github-repo")}
                className={`flex items-center gap-3 p-4 rounded-lg border-2 transition-colors text-left ${
                  sourceType === "github-repo"
                    ? "border-primary bg-primary/5"
                    : "border-border hover:border-primary/40"
                }`}
              >
                <GitBranch className="size-5 text-primary" />
                <div>
                  <div className="font-medium text-sm">GitHub Repo</div>
                  <div className="text-xs text-muted-foreground">
                    Analyze source code
                  </div>
                </div>
              </button>
              <button
                type="button"
                onClick={() => setSourceType("design-doc")}
                className={`flex items-center gap-3 p-4 rounded-lg border-2 transition-colors text-left ${
                  sourceType === "design-doc"
                    ? "border-primary bg-primary/5"
                    : "border-border hover:border-primary/40"
                }`}
              >
                <FileText className="size-5 text-primary" />
                <div>
                  <div className="font-medium text-sm">Design Doc</div>
                  <div className="text-xs text-muted-foreground">
                    Upload PDF or MD
                  </div>
                </div>
              </button>
            </div>
          </div>

          {/* Session Name */}
          <div>
            <label className="text-sm font-medium text-foreground mb-1.5 block">
              Session Name
            </label>
            <input
              type="text"
              placeholder="e.g., HVAC Cloud API - Threat Model"
              className="w-full px-3 py-2 rounded-md border border-input bg-background text-sm focus:outline-none focus:ring-2 focus:ring-ring"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </div>

          {/* Source Input */}
          {sourceType === "github-repo" ? (
            <div>
              <label className="text-sm font-medium text-foreground mb-1.5 block">
                Repository URL
              </label>
              <div className="flex items-center gap-2">
                <div className="flex-1 flex items-center gap-2 px-3 py-2 rounded-md border border-input bg-background">
                  <Link2 className="size-4 text-muted-foreground" />
                  <input
                    type="text"
                    placeholder="https://github.com/org/repo"
                    className="flex-1 bg-transparent text-sm focus:outline-none"
                    value={sourceRef}
                    onChange={(e) => setSourceRef(e.target.value)}
                  />
                </div>
              </div>
            </div>
          ) : (
            <div>
              <label className="text-sm font-medium text-foreground mb-1.5 block">
                Design Document
              </label>
              {/* Toggle between Upload and Paste modes */}
              <div className="flex items-center gap-2 mb-3">
                <button
                  type="button"
                  onClick={() => setInputMode("upload")}
                  className={`px-3 py-1.5 rounded-md text-sm font-medium transition-colors ${
                    inputMode === "upload"
                      ? "bg-primary text-primary-foreground"
                      : "bg-muted text-muted-foreground hover:bg-muted/80"
                  }`}
                >
                  Upload File
                </button>
                <button
                  type="button"
                  onClick={() => setInputMode("paste")}
                  className={`px-3 py-1.5 rounded-md text-sm font-medium transition-colors ${
                    inputMode === "paste"
                      ? "bg-primary text-primary-foreground"
                      : "bg-muted text-muted-foreground hover:bg-muted/80"
                  }`}
                >
                  Paste Text
                </button>
              </div>

              {inputMode === "upload" ? (
                <>
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept=".md,.txt,.pdf"
                    className="hidden"
                    onChange={(e) => {
                      const file = e.target.files?.[0]
                      if (file) {
                        setUploadedFile(file)
                        if (!sourceRef) setSourceRef(file.name)
                      }
                    }}
                  />
                  <div
                    className="border-2 border-dashed border-border rounded-lg p-8 text-center hover:border-primary/40 transition-colors cursor-pointer"
                    onClick={() => fileInputRef.current?.click()}
                    onDragOver={(e) => {
                      e.preventDefault()
                      e.stopPropagation()
                    }}
                    onDrop={(e) => {
                      e.preventDefault()
                      e.stopPropagation()
                      const file = e.dataTransfer.files?.[0]
                      if (file && (file.name.endsWith(".md") || file.name.endsWith(".txt") || file.name.endsWith(".pdf"))) {
                        setUploadedFile(file)
                        if (!sourceRef) setSourceRef(file.name)
                      }
                    }}
                    onKeyDown={() => {}}
                    role="button"
                    tabIndex={0}
                  >
                    {uploadedFile ? (
                      <div className="flex items-center justify-center gap-2">
                        <FileText className="size-6 text-primary" />
                        <div>
                          <p className="text-sm font-medium text-foreground">{uploadedFile.name}</p>
                          <p className="text-xs text-muted-foreground">
                            {(uploadedFile.size / 1024).toFixed(1)} KB — Click or drop to replace
                          </p>
                        </div>
                      </div>
                    ) : (
                      <>
                        <Upload className="size-8 text-muted-foreground mx-auto mb-2" />
                        <p className="text-sm text-muted-foreground">
                          Drop a PDF, Markdown, or text file here, or click to browse
                        </p>
                      </>
                    )}
                  </div>
                </>
              ) : (
                <Textarea
                  placeholder="Paste your design document content here (Markdown or plain text)..."
                  className="min-h-[160px] text-sm"
                  value={pastedText}
                  onChange={(e) => setPastedText(e.target.value)}
                />
              )}

              <input
                type="text"
                placeholder="Document reference name"
                className="w-full px-3 py-2 mt-2 rounded-md border border-input bg-background text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                value={sourceRef}
                onChange={(e) => setSourceRef(e.target.value)}
              />
            </div>
          )}

          {/* Framework Selection */}
          <div>
            <label className="text-sm font-medium text-foreground mb-1.5 block">
              Threat Framework
            </label>
            <div className="flex items-center gap-2">
              {["STRIDE", "AWS Threat Grammar", "OWASP Top 10"].map((fw) => (
                <Badge
                  key={fw}
                  variant="outline"
                  className={`cursor-pointer ${
                    framework === fw
                      ? "bg-primary/5 border-primary text-primary"
                      : "hover:bg-muted"
                  }`}
                  onClick={() => setFramework(fw)}
                >
                  {fw}
                </Badge>
              ))}
            </div>
          </div>

          {/* Error message */}
          {error && (
            <p className="text-sm text-red-600">{error}</p>
          )}

          {/* Actions */}
          <div className="flex items-center justify-end gap-3 pt-2">
            <Button
              variant="outline"
              onClick={() => onOpenChange(false)}
              className="bg-transparent"
            >
              Cancel
            </Button>
            <Button
              className="gap-2 bg-primary hover:bg-primary/90"
              disabled={creating || !name || (!sourceRef && !uploadedFile && !pastedText)}
              onClick={async () => {
                setCreating(true)
                setError(null)
                const ok = await onStart({
                  name,
                  source: sourceType,
                  sourceRef: sourceRef || uploadedFile?.name || "pasted-document",
                  framework,
                  file: uploadedFile || undefined,
                  documentContent: pastedText || undefined,
                })
                setCreating(false)
                if (ok) {
                  onOpenChange(false)
                } else {
                  setError("Failed to create session. Please check your input and try again.")
                }
              }}
            >
              {creating ? (
                <div className="size-4 rounded-full border-2 border-primary-foreground border-t-transparent animate-spin" />
              ) : (
                <Zap className="size-4" />
              )}
              {creating ? "Creating..." : "Generate Threat Model"}
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  )
}

// ── Processing State ──

function ProcessingState({
  sessionId,
  source,
  onComplete,
}: {
  sessionId: string
  source?: "design-doc" | "github-repo"
  onComplete: (sessionId: string) => void
}) {
  const [step, setStep] = useState(0)
  const [pollingStatus, setPollingStatus] = useState<string>("Processing")

  const designDocSteps = [
    "Parsing Design Document",
    "Analyzing Architecture Decisions",
    "Identifying Security Gaps & Risks",
    "Generating Threat Statements",
    "Building Context Layer File",
    "Finalizing Review",
  ]
  const repoSteps = [
    "Cloning Repository",
    "Analyzing Architecture",
    "Building Data Flow Diagram",
    "Identifying Trust Boundaries",
    "Generating Threat Statements",
    "Mapping to STRIDE Categories",
  ]
  const steps = source === "design-doc" ? designDocSteps : repoSteps

  // Animate steps visually
  useEffect(() => {
    const timer = setInterval(() => {
      setStep((prev) => {
        if (prev >= steps.length - 1) return prev
        return prev + 1
      })
    }, 2500)
    return () => clearInterval(timer)
  }, [steps.length])

  // Poll API for actual completion
  useEffect(() => {
    const pollInterval = setInterval(async () => {
      try {
        const res = await fetch(`/api/threat-model/sessions/${sessionId}`)
        if (res.ok) {
          const data = await res.json()
          setPollingStatus(data.status)
          if (data.status === "Review" || data.status === "Complete") {
            clearInterval(pollInterval)
            setStep(steps.length - 1)
            setTimeout(() => onComplete(sessionId), 800)
          } else if (data.status === "Failed") {
            clearInterval(pollInterval)
          }
        }
      } catch {
        // Continue polling
      }
    }, 3000)

    return () => clearInterval(pollInterval)
  }, [sessionId, onComplete, steps.length])

  return (
    <div className="flex-1 flex items-center justify-center">
      <Card className="w-full max-w-lg py-8">
        <CardContent className="space-y-6">
          <div className="text-center space-y-2">
            <div className="size-12 rounded-full bg-primary/10 flex items-center justify-center mx-auto">
              <Shield className="size-6 text-primary animate-pulse" />
            </div>
            <h2 className="text-xl font-semibold">Analyzing Architecture</h2>
            <p className="text-sm text-muted-foreground">
              Unitone AI is scanning the repository to build a threat model
            </p>
          </div>

          <div className="space-y-3">
            {steps.map((label, i) => {
              const isComplete = i < step
              const isActive = i === step
              return (
                <div key={label} className="flex items-center gap-3">
                  {isComplete ? (
                    <CheckCircle2 className="size-5 text-green-500 shrink-0" />
                  ) : isActive ? (
                    <div className="size-5 rounded-full border-2 border-primary border-t-transparent animate-spin shrink-0" />
                  ) : (
                    <div className="size-5 rounded-full border-2 border-border shrink-0" />
                  )}
                  <span
                    className={`text-sm ${
                      isComplete
                        ? "text-muted-foreground line-through"
                        : isActive
                          ? "text-foreground font-medium"
                          : "text-muted-foreground"
                    }`}
                  >
                    {label}
                  </span>
                </div>
              )
            })}
          </div>

          <div className="w-full bg-muted rounded-full h-2">
            <div
              className="bg-primary h-2 rounded-full transition-all duration-700"
              style={{ width: `${((step + 1) / steps.length) * 100}%` }}
            />
          </div>

          {pollingStatus === "Failed" && (
            <p className="text-sm text-red-600 text-center">
              {source === "design-doc"
                ? "Analysis failed. Please check your document and try again."
                : "Analysis failed. Please check your repository URL and try again."}
            </p>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

// ── Sessions List View ──

function SessionsList({
  sessions,
  loading,
  onSelect,
  onNewSession,
  onDelete,
}: {
  sessions: SessionSummary[]
  loading: boolean
  onSelect: (id: string) => void
  onNewSession: () => void
  onDelete: (id: string) => void
}) {
  const statusColor = (s: string) => {
    switch (s) {
      case "Processing":
        return "bg-amber-500/10 text-amber-600 border-amber-200"
      case "Review":
        return "bg-blue-500/10 text-blue-600 border-blue-200"
      case "Complete":
        return "bg-green-500/10 text-green-600 border-green-200"
      case "Failed":
        return "bg-red-500/10 text-red-600 border-red-200"
      default:
        return ""
    }
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-semibold">Threat Model Sessions</h2>
          <p className="text-sm text-muted-foreground mt-1">
            {sessions.length} sessions across all projects
          </p>
        </div>
        <Button
          className="gap-2 bg-primary hover:bg-primary/90"
          onClick={onNewSession}
        >
          <Plus className="size-4" />
          New Session
        </Button>
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-16">
          <Loader2 className="size-6 animate-spin text-muted-foreground" />
        </div>
      ) : sessions.length === 0 ? (
        <Card className="py-16">
          <CardContent className="text-center">
            <Shield className="size-12 text-muted-foreground mx-auto mb-4" />
            <h3 className="text-lg font-semibold mb-2">No Threat Models Yet</h3>
            <p className="text-sm text-muted-foreground mb-4">
              Create your first threat model by submitting a GitHub repo or design document.
            </p>
            <Button
              className="gap-2 bg-primary hover:bg-primary/90"
              onClick={onNewSession}
            >
              <Plus className="size-4" />
              New Session
            </Button>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {sessions.map((session) => (
            <Card
              key={session.id}
              className="hover:border-primary/30 transition-colors cursor-pointer"
              onClick={() => onSelect(session.id)}
            >
              <CardContent className="py-5 px-6">
                <div className="flex items-start gap-4">
                  <div className="size-10 rounded-lg bg-muted flex items-center justify-center shrink-0 mt-0.5">
                    {session.source === "github-repo" ? (
                      <GitBranch className="size-5 text-muted-foreground" />
                    ) : (
                      <FileText className="size-5 text-muted-foreground" />
                    )}
                  </div>

                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-3">
                      <h3 className="font-semibold truncate">{session.name}</h3>
                      <Badge
                        variant="outline"
                        className={`${statusColor(session.status)} text-xs shrink-0`}
                      >
                        {session.status}
                      </Badge>
                    </div>
                    <div className="flex items-center gap-4 mt-1.5 text-sm text-muted-foreground">
                      <span className="flex items-center gap-1.5">
                        {session.source === "github-repo" ? (
                          <Link2 className="size-3" />
                        ) : (
                          <FileText className="size-3" />
                        )}
                        {session.sourceRef}
                      </span>
                      <span className="flex items-center gap-1.5">
                        <Calendar className="size-3" />
                        {formatDate(session.createdAt)}
                      </span>
                      <span className="flex items-center gap-1.5">
                        <Shield className="size-3" />
                        {session.framework}
                      </span>
                    </div>
                  </div>

                  <div className="flex items-center gap-3 shrink-0">
                    <div className="text-center">
                      <div className="text-lg font-bold">
                        {session.stats.total}
                      </div>
                      <div className="text-xs text-muted-foreground">
                        Threats
                      </div>
                    </div>
                    <div className="h-8 w-px bg-border" />
                    {session.stats.critical > 0 && (
                      <div className="text-center">
                        <div className="text-lg font-bold text-red-600">
                          {session.stats.critical}
                        </div>
                        <div className="text-xs text-red-500">Critical</div>
                      </div>
                    )}
                    <div className="text-center">
                      <div className="text-lg font-bold text-green-600">
                        {session.stats.mitigated}
                      </div>
                      <div className="text-xs text-green-500">Mitigated</div>
                    </div>
                    <button
                      type="button"
                      className="size-8 rounded-md hover:bg-red-100 dark:hover:bg-red-900/30 flex items-center justify-center transition-colors text-muted-foreground hover:text-red-600"
                      onClick={(e) => {
                        e.stopPropagation()
                        if (confirm("Delete this threat model session? This cannot be undone.")) {
                          fetch(`/api/threat-model/sessions/${session.id}`, { method: "DELETE" })
                            .then(() => onDelete(session.id))
                            .catch(() => {})
                        }
                      }}
                    >
                      <Trash2 className="size-4" />
                    </button>
                    <ChevronRight className="size-5 text-muted-foreground" />
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  )
}

// ── Data Flow Diagram Panel (dynamic) ──

function DataFlowDiagramPanel({
  mermaidChart,
}: {
  mermaidChart: string
}) {
  return (
    <Card>
      <div className="px-6 py-4 border-b border-border flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Target className="size-4 text-primary" />
          <h3 className="font-semibold">Data Flow Diagram</h3>
        </div>
        <Button variant="outline" size="sm" className="gap-1 bg-transparent">
          <FileCode className="size-3" />
          Edit DFD
        </Button>
      </div>
      <CardContent className="py-4">
        {mermaidChart ? (
          <MermaidDiagram chart={mermaidChart} />
        ) : (
          <div className="bg-muted/30 rounded-lg border border-border p-12 flex items-center justify-center">
            <p className="text-sm text-muted-foreground">
              No data flow diagram available
            </p>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

// ── Threat Detail Slide-Over ──

function ThreatDetailPanel({
  threat,
  isRepoSource,
  jiraConfigured,
  onClose,
  onThreatUpdated,
  onPopOut,
}: {
  threat: Threat
  isRepoSource: boolean
  jiraConfigured: boolean
  onClose: () => void
  onThreatUpdated: (threatId: string, newStatus: string) => void
  onPopOut: () => void
}) {
  const [expanded, setExpanded] = useState(false)
  const [creatingTickets, setCreatingTickets] = useState(false)

  async function handleUpdateStatus(newStatus: string) {
    try {
      await fetch(`/api/threat-model/threats/${threat.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: newStatus }),
      })
      onThreatUpdated(threat.id, newStatus)
    } catch {
      // Handle error
    }
  }

  async function handleCreateAllTickets() {
    if (!jiraConfigured) return
    setCreatingTickets(true)
    try {
      const unticketedMitigations = threat.mitigations.filter((m) => !m.jiraTicket)
      for (const mit of unticketedMitigations) {
        await fetch(`/api/threat-model/threats/${threat.id}/jira`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ mitigationId: mit.id }),
        })
      }
      onThreatUpdated(threat.id, threat.status)
    } catch {
      // Handle error
    } finally {
      setCreatingTickets(false)
    }
  }

  return (
    <div className={`fixed inset-y-0 right-0 ${expanded ? "w-[85vw]" : "w-[540px]"} bg-card border-l border-border shadow-xl z-50 flex flex-col transition-all duration-300`}>
      {/* Header */}
      <div className="p-6 border-b border-border">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <StrideIcon category={threat.stride} />
            <span className="text-sm font-medium text-muted-foreground">
              {threat.id}
            </span>
          </div>
          <div className="flex items-center gap-1">
            <button
              type="button"
              onClick={() => setExpanded(!expanded)}
              className="size-8 rounded-md hover:bg-muted flex items-center justify-center transition-colors"
              aria-label={expanded ? "Collapse panel" : "Expand panel"}
            >
              {expanded ? <Minimize2 className="size-4" /> : <Maximize2 className="size-4" />}
            </button>
            <button
              type="button"
              onClick={onClose}
              className="size-8 rounded-md hover:bg-muted flex items-center justify-center transition-colors"
            >
              <X className="size-4" />
            </button>
          </div>
        </div>
        <h2 className="text-lg font-semibold leading-tight">{threat.title}</h2>
        <div className="flex items-center gap-2 mt-3">
          <Badge
            variant="outline"
            className={`${getSeverityColor(threat.severity)} text-xs`}
          >
            {threat.severity}
          </Badge>
          <Badge
            variant="outline"
            className={`${getStrideColor(threat.stride)} text-xs`}
          >
            {threat.stride}
          </Badge>
          <Badge
            variant="outline"
            className={`${getStatusColor(threat.status)} text-xs`}
          >
            {threat.status}
          </Badge>
        </div>
      </div>

      {/* Content */}
      <ScrollArea className="flex-1 overflow-hidden">
        <div className="p-6 space-y-6">
          {/* Threat Statement */}
          <div>
            <h3 className="text-sm font-semibold text-foreground mb-3 flex items-center gap-2">
              <BookOpen className="size-4 text-primary" />
              Threat Statement
            </h3>
            <div className="bg-muted/50 rounded-lg p-4 border border-border">
              <p className="text-sm leading-relaxed">
                <span className="font-medium text-red-600">
                  {threat.threatStatement.actor}
                </span>{" "}
                {threat.threatStatement.prerequisites && (
                  <span className="text-muted-foreground">
                    with {threat.threatStatement.prerequisites}{" "}
                  </span>
                )}
                <span className="text-foreground">
                  {threat.threatStatement.action}
                </span>{" "}
                <span className="font-medium text-orange-600">
                  {threat.threatStatement.asset}
                </span>{" "}
                <span className="text-foreground font-medium">
                  {threat.threatStatement.impact}
                </span>
              </p>
            </div>
          </div>

          {/* Trust Boundary */}
          <div>
            <h3 className="text-sm font-semibold text-foreground mb-2">
              Trust Boundary Crossed
            </h3>
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <div className="size-2 rounded-full bg-orange-400" />
              {threat.trustBoundary}
            </div>
          </div>

          {/* Assumptions */}
          {threat.assumptions.length > 0 && (
            <div>
              <h3 className="text-sm font-semibold text-foreground mb-2">
                Assumptions
              </h3>
              <ul className="space-y-2">
                {threat.assumptions.map((a, i) => (
                  <li
                    key={`assumption-${threat.id}-${i}`}
                    className="flex items-start gap-2 text-sm text-muted-foreground"
                  >
                    <AlertTriangle className="size-3.5 text-amber-500 mt-0.5 shrink-0" />
                    {a}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Mitigations */}
          <div>
            <h3 className="text-sm font-semibold text-foreground mb-3">
              Mitigations
            </h3>
            <div className="space-y-4">
              {threat.mitigations.map((mit) => (
                <div
                  key={mit.id}
                  className="rounded-lg border border-border p-4 space-y-3"
                >
                  <div className="flex items-start justify-between gap-3">
                    <p className="text-sm text-foreground flex-1">
                      {mit.description}
                    </p>
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
                          <span className="text-xs font-mono text-primary">
                            {mit.jiraTicket.key}
                          </span>
                          <span className="text-sm truncate">
                            {mit.jiraTicket.summary}
                          </span>
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

                  <div className="flex items-center gap-2">
                    {mit.codeSnippet && isRepoSource && threat.status !== "Mitigated" && (
                      <ApplyFixButton
                        threatId={threat.id}
                        mitigationId={mit.id}
                        hasCodeFix={!!mit.codeSnippet}
                        isRepoSource={isRepoSource}
                        onApplied={(result) => {
                          onThreatUpdated(threat.id, result.threatStatus)
                        }}
                      />
                    )}
                    {!mit.codeSnippet && (
                      <Button
                        variant="outline"
                        size="sm"
                        className="gap-1 text-xs bg-transparent opacity-50 cursor-not-allowed"
                        disabled
                        title="No code fix available"
                      >
                        <Zap className="size-3" />
                        Generate Fix
                      </Button>
                    )}
                    <JiraTicketButton
                      threatId={threat.id}
                      mitigationId={mit.id}
                      jiraConfigured={jiraConfigured}
                      existingJiraKey={mit.jiraTicket?.key}
                      existingJiraUrl={mit.jiraTicket ? undefined : undefined}
                    />
                  </div>
                </div>
              ))}

              {threat.mitigations.length === 0 && (
                <div className="text-sm text-muted-foreground p-4 bg-muted/30 rounded-lg text-center">
                  No mitigations defined yet.
                </div>
              )}
            </div>
          </div>

          {/* Related CVE */}
          {threat.relatedCVE && (
            <div className="flex items-center gap-2 p-3 rounded-lg bg-red-50 border border-red-200">
              <AlertTriangle className="size-4 text-red-500" />
              <span className="text-sm text-red-700">
                Related vulnerability:{" "}
                <span className="font-mono font-medium">
                  {threat.relatedCVE}
                </span>
              </span>
              <Button
                variant="ghost"
                size="sm"
                className="ml-auto gap-1 text-red-600 hover:text-red-700 hover:bg-red-100 text-xs"
              >
                View Fix
                <ExternalLink className="size-3" />
              </Button>
            </div>
          )}
        </div>
      </ScrollArea>

      {/* Footer */}
      <div className="p-4 border-t border-border flex items-center justify-between">
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="outline" size="sm" className="gap-1 bg-transparent">
              <ChevronDown className="size-3" />
              Actions
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start">
            <DropdownMenuItem onClick={() => handleUpdateStatus("Mitigated")}>
              <Shield className="size-3 mr-2" />
              Mark as Mitigated
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => handleUpdateStatus("Identified")}>
              <AlertTriangle className="size-3 mr-2" />
              Mark as Identified
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            className="gap-1 bg-transparent"
            disabled={!jiraConfigured || creatingTickets || threat.mitigations.length === 0}
            onClick={handleCreateAllTickets}
            title={!jiraConfigured ? "Configure Jira in Settings first" : ""}
          >
            {creatingTickets ? (
              <Loader2 className="size-3 animate-spin" />
            ) : (
              <Plus className="size-3" />
            )}
            {creatingTickets ? "Creating..." : "Create All Tickets"}
          </Button>
          <Button
            size="sm"
            className="gap-1 bg-primary hover:bg-primary/90"
            onClick={() => handleUpdateStatus("Accepted")}
          >
            <CheckCircle2 className="size-3" />
            Accept Risk
          </Button>
        </div>
      </div>
    </div>
  )
}

// ── Progress Tracker breadcrumb ──

function ProgressTracker({ session }: { session: SessionDetail }) {
  const stages = [
    { label: "Design", complete: true },
    { label: "Threat Model", complete: true },
    { label: "Jira Tickets", complete: session.stats.mitigated > 0 },
    { label: "Remediation", complete: false },
  ]

  return (
    <div className="flex items-center gap-2">
      {stages.map((stage, i) => (
        <div key={stage.label} className="flex items-center gap-2">
          <div className="flex items-center gap-1.5">
            <div
              className={`size-5 rounded-full flex items-center justify-center text-xs ${
                stage.complete
                  ? "bg-green-500 text-white"
                  : "bg-muted text-muted-foreground border border-border"
              }`}
            >
              {stage.complete ? <CheckCircle2 className="size-3" /> : i + 1}
            </div>
            <span
              className={`text-xs ${
                stage.complete
                  ? "text-foreground font-medium"
                  : "text-muted-foreground"
              }`}
            >
              {stage.label}
            </span>
          </div>
          {i < stages.length - 1 && (
            <ChevronRight className="size-3 text-muted-foreground" />
          )}
        </div>
      ))}
    </div>
  )
}

// ── Insights Panel ──

function InsightsPanel({ insights, stats }: { insights: InsightMetrics; stats: SessionStats }) {
  return (
    <Card>
      <CardContent className="py-6 space-y-4">
        <h3 className="font-semibold">Quality Insights</h3>

        {/* Risk Score */}
        <div className="p-4 rounded-lg border border-border flex items-center gap-4">
          <div className={`text-3xl font-bold ${
            insights.riskScore > 70 ? "text-red-600" :
            insights.riskScore > 40 ? "text-amber-600" : "text-green-600"
          }`}>
            {insights.riskScore}
          </div>
          <div>
            <div className="text-sm font-medium">Risk Score</div>
            <div className="text-xs text-muted-foreground">
              {insights.riskScore > 70 ? "High risk — address critical threats immediately" :
               insights.riskScore > 40 ? "Moderate risk — continue mitigation efforts" :
               "Low risk — good coverage"}
            </div>
          </div>
        </div>

        <div className="grid grid-cols-3 gap-4">
          <div className="p-4 rounded-lg border border-border space-y-2">
            <div className="text-sm text-muted-foreground">
              Threat Coverage
            </div>
            <div className="text-2xl font-bold">
              {insights.strideCoverage.covered.length}/{insights.strideCoverage.total}
            </div>
            <div className="text-xs text-muted-foreground">
              STRIDE categories covered
            </div>
            <div className="w-full bg-muted rounded-full h-2">
              <div
                className="bg-primary h-2 rounded-full"
                style={{ width: `${insights.strideCoverage.percentage}%` }}
              />
            </div>
          </div>
          <div className="p-4 rounded-lg border border-border space-y-2">
            <div className="text-sm text-muted-foreground">
              Mitigation Rate
            </div>
            <div className="text-2xl font-bold">
              {insights.mitigationRate.percentage}%
            </div>
            <div className="text-xs text-muted-foreground">
              Threats with at least one mitigation
            </div>
            <div className="w-full bg-muted rounded-full h-2">
              <div
                className="bg-green-500 h-2 rounded-full"
                style={{ width: `${insights.mitigationRate.percentage}%` }}
              />
            </div>
          </div>
          <div className="p-4 rounded-lg border border-border space-y-2">
            <div className="text-sm text-muted-foreground">
              Mitigated
            </div>
            <div className="text-2xl font-bold">{stats.mitigated}/{stats.total}</div>
            <div className="text-xs text-muted-foreground">
              Threats fully mitigated
            </div>
            <div className="w-full bg-muted rounded-full h-2">
              <div
                className="bg-blue-500 h-2 rounded-full"
                style={{
                  width: `${stats.total > 0 ? (stats.mitigated / stats.total) * 100 : 0}%`,
                }}
              />
            </div>
          </div>
        </div>

        {/* STRIDE Breakdown */}
        <div className="mt-4">
          <h4 className="text-sm font-medium mb-3">
            STRIDE Category Breakdown
          </h4>
          <div className="grid grid-cols-6 gap-2">
            {insights.strideBreakdown.map((item) => (
              <div
                key={item.category}
                className="text-center p-3 rounded-lg border border-border"
              >
                <div className="text-lg font-bold">{item.count}</div>
                <div className="text-xs text-muted-foreground">
                  {item.category.length > 12
                    ? item.category.split(" ").map((w) => w[0]).join(". ") + "."
                    : item.category}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Recommendations */}
        {insights.recommendations.length > 0 && (
          <div className="mt-4">
            <h4 className="text-sm font-medium mb-3">Recommendations</h4>
            <div className="space-y-2">
              {insights.recommendations.map((rec, i) => (
                <div
                  key={`rec-${i}`}
                  className="flex items-start gap-2 text-sm text-muted-foreground p-3 rounded-lg bg-muted/30 border border-border"
                >
                  <AlertTriangle className="size-4 text-amber-500 mt-0.5 shrink-0" />
                  {rec}
                </div>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

// ── Threat Row (extracted for reuse in flat/grouped views) ──

function ThreatRow({ threat, onClick }: { threat: Threat; onClick: () => void }) {
  return (
    <button
      type="button"
      className="w-full px-6 py-4 flex items-center gap-4 hover:bg-muted/50 transition-colors text-left"
      onClick={onClick}
    >
      <StrideIcon category={threat.stride} />
      <Badge
        variant="outline"
        className={`${getSeverityColor(threat.severity)} min-w-[70px] justify-center text-xs`}
      >
        {threat.severity}
      </Badge>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="font-medium truncate text-sm">
            {threat.title}
          </span>
          <span className="text-xs text-muted-foreground shrink-0">
            {threat.id}
          </span>
        </div>
        <p className="text-xs text-muted-foreground truncate mt-0.5">
          {threat.threatStatement.actor}{" "}
          {threat.threatStatement.action}
        </p>
      </div>
      <Badge
        variant="outline"
        className={`${getStatusColor(threat.status)} text-xs`}
      >
        {threat.status}
      </Badge>
      <div className="hidden sm:flex items-center gap-1 text-xs text-muted-foreground w-24 justify-end">
        <Shield className="size-3" />
        {threat.mitigations.length} mitigation
        {threat.mitigations.length !== 1 ? "s" : ""}
      </div>
      <ChevronRight className="size-4 text-muted-foreground" />
    </button>
  )
}

// ── Session Detail View ──

function SessionDetailView({
  session,
  onBack,
}: {
  session: SessionDetail
  onBack: () => void
}) {
  const [threats, setThreats] = useState<Threat[]>(session.threats)
  const [selectedThreat, setSelectedThreat] = useState<Threat | null>(null)
  const [popOutThreat, setPopOutThreat] = useState<Threat | null>(null)
  const [jiraConfigured, setJiraConfigured] = useState(false)

  // Filter state
  const [filterSeverity, setFilterSeverity] = useState<string[]>([])
  const [filterStatus, setFilterStatus] = useState<string[]>([])
  const [filterStride, setFilterStride] = useState<string[]>([])
  const [groupByStride, setGroupByStride] = useState(false)

  // Pagination
  const [currentPage, setCurrentPage] = useState(1)
  const THREATS_PER_PAGE = 10

  // Check if Jira is configured
  useEffect(() => {
    async function checkJira() {
      try {
        const res = await fetch("/api/settings")
        if (res.ok) {
          const settings = await res.json()
          const hasJira = settings.some((s: { key: string; value: string }) =>
            s.key === "jira_url" && s.value
          )
          setJiraConfigured(hasJira)
        }
      } catch {
        // Not configured
      }
    }
    checkJira()
  }, [])

  const handleThreatUpdated = useCallback(
    (threatId: string, newStatus: string) => {
      setThreats((prev) =>
        prev.map((t) =>
          t.id === threatId ? { ...t, status: newStatus as Threat["status"] } : t
        )
      )
      if (selectedThreat?.id === threatId) {
        setSelectedThreat((prev) =>
          prev ? { ...prev, status: newStatus as Threat["status"] } : prev
        )
      }
    },
    [selectedThreat]
  )

  // Filtered threats
  const filteredThreats = useMemo(() => {
    return threats.filter((t) => {
      if (filterSeverity.length > 0 && !filterSeverity.includes(t.severity)) return false
      if (filterStatus.length > 0 && !filterStatus.includes(t.status)) return false
      if (filterStride.length > 0 && !filterStride.includes(t.stride)) return false
      return true
    })
  }, [threats, filterSeverity, filterStatus, filterStride])

  // Paginated threats
  const totalPages = Math.ceil(filteredThreats.length / THREATS_PER_PAGE)
  const paginatedThreats = useMemo(() => {
    if (groupByStride) return filteredThreats // No pagination when grouped
    const start = (currentPage - 1) * THREATS_PER_PAGE
    return filteredThreats.slice(start, start + THREATS_PER_PAGE)
  }, [filteredThreats, currentPage, groupByStride])

  // STRIDE groups
  const strideGroups = useMemo(() => {
    if (!groupByStride) return null
    const groups: Record<string, Threat[]> = {}
    for (const t of filteredThreats) {
      if (!groups[t.stride]) groups[t.stride] = []
      groups[t.stride].push(t)
    }
    return groups
  }, [filteredThreats, groupByStride])

  // Reset page when filters change
  useEffect(() => {
    setCurrentPage(1)
  }, [filterSeverity, filterStatus, filterStride])

  // Recompute stats from local threats state
  const liveStats = {
    total: threats.length,
    critical: threats.filter((t) => t.severity === "Critical").length,
    high: threats.filter((t) => t.severity === "High").length,
    medium: threats.filter((t) => t.severity === "Medium").length,
    low: threats.filter((t) => t.severity === "Low").length,
    mitigated: threats.filter((t) => t.status === "Mitigated").length,
  }

  async function handleExportPDF() {
    const { generateThreatModelPDF } = await import("@/lib/pdf-export")
    generateThreatModelPDF(session as Parameters<typeof generateThreatModelPDF>[0])
  }

  return (
    <>
      <AppHeader title="Threat Modeling">
        <ProgressTracker session={{ ...session, stats: liveStats }} />
      </AppHeader>

      <ScrollArea className="flex-1 overflow-hidden">
        <div className="p-6 space-y-6">
          {/* Session Header */}
          <div className="flex items-center justify-between gap-4">
            <div className="flex items-center gap-3 min-w-0">
              <Button
                variant="ghost"
                size="sm"
                className="gap-1 shrink-0"
                onClick={onBack}
              >
                <ChevronRight className="size-4 rotate-180" />
                All Sessions
              </Button>
              <div className="h-6 w-px bg-border shrink-0" />
              <div className="min-w-0">
                <h2 className="text-xl font-semibold truncate">{session.name}</h2>
                <p className="text-sm text-muted-foreground mt-0.5 truncate">
                  {session.description}
                </p>
              </div>
            </div>
            <Button
              size="sm"
              className="gap-1 bg-primary hover:bg-primary/90 shrink-0"
              onClick={handleExportPDF}
            >
              <Download className="size-3" />
              Export PDF
            </Button>
          </div>

          {/* KPI Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4">
            {[
              { label: "Total Threats", value: liveStats.total, color: "", labelColor: "" },
              { label: "Critical", value: liveStats.critical, color: "text-red-600", labelColor: "text-red-500" },
              { label: "High", value: liveStats.high, color: "text-orange-600", labelColor: "text-orange-500" },
              { label: "Medium", value: liveStats.medium, color: "text-yellow-700", labelColor: "text-yellow-600" },
              { label: "Mitigated", value: liveStats.mitigated, color: "text-green-600", labelColor: "text-green-500" },
            ].map((stat) => (
              <Card key={stat.label} className="py-4">
                <CardContent className="flex flex-col gap-1">
                  <span className={`text-sm ${stat.labelColor || "text-muted-foreground"}`}>
                    {stat.label}
                  </span>
                  <span className={`text-2xl font-bold ${stat.color}`}>
                    {stat.value}
                  </span>
                </CardContent>
              </Card>
            ))}
          </div>

          {/* Tabs */}
          <Tabs defaultValue="threats">
            <TabsList>
              <TabsTrigger value="threats">Threat List</TabsTrigger>
              <TabsTrigger value="dfd">Data Flow Diagram</TabsTrigger>
              <TabsTrigger value="insights">Insights</TabsTrigger>
              {session.source === "design-doc" && (
                <TabsTrigger value="design-review" className="gap-1.5">
                  <FileSearch className="size-4" />
                  Design Review
                </TabsTrigger>
              )}
            </TabsList>

            <TabsContent value="threats">
              <Card className="overflow-hidden">
                <div className="px-6 py-4 border-b border-border flex items-center justify-between flex-wrap gap-2">
                  <h3 className="font-semibold">
                    Identified Threats ({filteredThreats.length}
                    {filteredThreats.length !== threats.length && ` of ${threats.length}`})
                  </h3>
                  <div className="flex items-center gap-2 flex-wrap">
                    <ThreatFilters
                      filterSeverity={filterSeverity}
                      filterStatus={filterStatus}
                      filterStride={filterStride}
                      onFilterSeverityChange={setFilterSeverity}
                      onFilterStatusChange={setFilterStatus}
                      onFilterStrideChange={setFilterStride}
                    />
                    <Button
                      variant="outline"
                      size="sm"
                      className={`gap-1.5 bg-transparent ${groupByStride ? "border-primary text-primary" : ""}`}
                      onClick={() => setGroupByStride(!groupByStride)}
                    >
                      <Layers className="size-3.5" />
                      Group by STRIDE
                    </Button>
                  </div>
                </div>

                {groupByStride && strideGroups ? (
                  <div className="divide-y divide-border">
                    {Object.entries(strideGroups).map(([category, groupThreats]) => (
                      <Collapsible key={category} defaultOpen>
                        <CollapsibleTrigger className="w-full px-6 py-3 flex items-center gap-3 hover:bg-muted/30 transition-colors text-left">
                          <ChevronDown className="size-4 text-muted-foreground" />
                          <StrideIcon category={category} />
                          <span className="font-medium text-sm">{category}</span>
                          <Badge variant="secondary" className="text-xs">
                            {groupThreats.length}
                          </Badge>
                        </CollapsibleTrigger>
                        <CollapsibleContent>
                          <div className="divide-y divide-border">
                            {groupThreats.map((threat) => (
                              <ThreatRow key={threat.id} threat={threat} onClick={() => setSelectedThreat(threat)} />
                            ))}
                          </div>
                        </CollapsibleContent>
                      </Collapsible>
                    ))}
                  </div>
                ) : (
                  <>
                    <div className="divide-y divide-border">
                      {paginatedThreats.map((threat) => (
                        <ThreatRow key={threat.id} threat={threat} onClick={() => setSelectedThreat(threat)} />
                      ))}
                    </div>

                    {/* Pagination */}
                    {totalPages > 1 && (
                      <div className="px-6 py-4 border-t border-border flex items-center justify-between flex-wrap gap-2">
                        <span className="text-sm text-muted-foreground">
                          Page {currentPage} of {totalPages}
                        </span>
                        <div className="flex items-center gap-2">
                          <Button
                            variant="outline"
                            size="sm"
                            className="bg-transparent"
                            disabled={currentPage === 1}
                            onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                          >
                            Previous
                          </Button>
                          {Array.from({ length: totalPages }, (_, i) => i + 1).map((page) => (
                            <Button
                              key={page}
                              variant={page === currentPage ? "default" : "outline"}
                              size="sm"
                              className={page !== currentPage ? "bg-transparent" : ""}
                              onClick={() => setCurrentPage(page)}
                            >
                              {page}
                            </Button>
                          ))}
                          <Button
                            variant="outline"
                            size="sm"
                            className="bg-transparent"
                            disabled={currentPage === totalPages}
                            onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                          >
                            Next
                          </Button>
                        </div>
                      </div>
                    )}
                  </>
                )}
              </Card>
            </TabsContent>

            <TabsContent value="dfd">
              <DataFlowDiagramPanel mermaidChart={session.dataFlowDiagram} />
            </TabsContent>

            <TabsContent value="insights">
              <InsightsPanel insights={session.insights} stats={liveStats} />
            </TabsContent>

            {session.source === "design-doc" && (
              <TabsContent value="design-review">
                <DesignReviewPanel designReview={session.designReview} sessionName={session.name} />
              </TabsContent>
            )}
          </Tabs>
        </div>
      </ScrollArea>

      {/* Threat Detail Slide-Over */}
      {selectedThreat && (
        <>
          <div
            className="fixed inset-0 bg-black/30 z-40"
            onClick={() => setSelectedThreat(null)}
            onKeyDown={() => {}}
            role="button"
            tabIndex={-1}
            aria-label="Close threat detail"
          />
          <ThreatDetailPanel
            threat={selectedThreat}
            isRepoSource={session.source === "github-repo"}
            jiraConfigured={jiraConfigured}
            onClose={() => setSelectedThreat(null)}
            onThreatUpdated={handleThreatUpdated}
            onPopOut={() => {
              setPopOutThreat(selectedThreat)
              setSelectedThreat(null)
            }}
          />
        </>
      )}

      {/* Pop-out Full Dialog */}
      {popOutThreat && (
        <ThreatDetailFull
          threat={popOutThreat}
          open={!!popOutThreat}
          onOpenChange={(open) => {
            if (!open) setPopOutThreat(null)
          }}
        />
      )}
    </>
  )
}

// ── Design Review Panel ──

function DesignReviewPanel({ designReview, sessionName }: { designReview?: DesignReviewData; sessionName: string }) {
  const [enhancementsOpen, setEnhancementsOpen] = useState(true)
  const [risksOpen, setRisksOpen] = useState(true)
  const [expandedRisks, setExpandedRisks] = useState<Set<number>>(new Set())
  const [copied, setCopied] = useState(false)

  if (!designReview) {
    return (
      <Card className="py-16">
        <CardContent className="text-center">
          <FileSearch className="size-12 text-muted-foreground mx-auto mb-4" />
          <h3 className="text-lg font-semibold mb-2">No Design Review Available</h3>
          <p className="text-sm text-muted-foreground">
            Design review data will appear here once the analysis is complete.
          </p>
        </CardContent>
      </Card>
    )
  }

  const severityOrder: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3 }

  const sortedEnhancements = [...(designReview.enhancements || [])].sort(
    (a, b) => (severityOrder[a.severity] ?? 4) - (severityOrder[b.severity] ?? 4)
  )

  const riskSeveritySummary = (() => {
    const counts: Record<string, number> = {}
    for (const r of designReview.risks || []) {
      counts[r.severity] = (counts[r.severity] || 0) + 1
    }
    return ["Critical", "High", "Medium", "Low"]
      .filter((s) => counts[s])
      .map((s) => `${counts[s]} ${s}`)
      .join(", ")
  })()

  function toggleRiskExpanded(index: number) {
    setExpandedRisks((prev) => {
      const next = new Set(prev)
      if (next.has(index)) {
        next.delete(index)
      } else {
        next.add(index)
      }
      return next
    })
  }

  function handleDownload(filename: string) {
    if (!designReview.contextLayer) return
    const blob = new Blob([designReview.contextLayer], { type: "text/markdown" })
    const url = URL.createObjectURL(blob)
    const a = document.createElement("a")
    a.href = url
    a.download = filename
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  async function handleCopy() {
    if (!designReview.contextLayer) return
    await navigator.clipboard.writeText(designReview.contextLayer)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="space-y-6">
      {/* Section A — Design Enhancements */}
      <Card>
        <Collapsible open={enhancementsOpen} onOpenChange={setEnhancementsOpen}>
          <CollapsibleTrigger className="w-full px-6 py-4 border-b border-border flex items-center gap-3 hover:bg-muted/30 transition-colors text-left">
            <ChevronDown className={`size-4 text-muted-foreground transition-transform ${enhancementsOpen ? "" : "-rotate-90"}`} />
            <Lightbulb className="size-4 text-amber-500" />
            <h3 className="font-semibold flex-1">
              {sortedEnhancements.length} Design Enhancement{sortedEnhancements.length !== 1 ? "s" : ""} Identified
            </h3>
          </CollapsibleTrigger>
          <CollapsibleContent>
            <CardContent className="py-4">
              {sortedEnhancements.length === 0 ? (
                <div className="text-sm text-muted-foreground p-4 bg-muted/30 rounded-lg text-center">
                  No design enhancements identified.
                </div>
              ) : (
                <div className="space-y-4">
                  {sortedEnhancements.map((enh, i) => (
                    <div key={`enh-${i}`} className="rounded-lg border border-border p-4 space-y-3">
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-sm">{enh.section}</span>
                        <div className="flex items-center gap-2">
                          <Badge variant="outline" className={`text-xs ${getSeverityColor(enh.severity)}`}>
                            {enh.severity}
                          </Badge>
                          <Badge variant="outline" className={`text-xs ${getStrideColor(enh.strideCategory)}`}>
                            {enh.strideCategory}
                          </Badge>
                        </div>
                      </div>
                      <div className="flex items-start gap-2 p-3 rounded-md bg-amber-500/10 border border-amber-200">
                        <AlertTriangle className="size-4 text-amber-600 mt-0.5 shrink-0" />
                        <span className="text-sm text-amber-800">{enh.gap}</span>
                      </div>
                      <div className="flex items-start gap-2 p-3 rounded-md bg-emerald-500/10 border border-emerald-200">
                        <Lightbulb className="size-4 text-emerald-600 mt-0.5 shrink-0" />
                        <span className="text-sm text-emerald-800">{enh.suggestion}</span>
                      </div>
                      {enh.rationale && (
                        <p className="text-xs text-muted-foreground pl-1">{enh.rationale}</p>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </CollapsibleContent>
        </Collapsible>
      </Card>

      {/* Section B — Pre-Code Risk Register */}
      <Card>
        <Collapsible open={risksOpen} onOpenChange={setRisksOpen}>
          <CollapsibleTrigger className="w-full px-6 py-4 border-b border-border flex items-center gap-3 hover:bg-muted/30 transition-colors text-left">
            <ChevronDown className={`size-4 text-muted-foreground transition-transform ${risksOpen ? "" : "-rotate-90"}`} />
            <Shield className="size-4 text-primary" />
            <h3 className="font-semibold flex-1">
              Pre-Code Risk Register
            </h3>
            {riskSeveritySummary && (
              <span className="text-xs text-muted-foreground">{riskSeveritySummary}</span>
            )}
          </CollapsibleTrigger>
          <CollapsibleContent>
            <CardContent className="py-4">
              {(!designReview.risks || designReview.risks.length === 0) ? (
                <div className="text-sm text-muted-foreground p-4 bg-muted/30 rounded-lg text-center">
                  No pre-code risks identified.
                </div>
              ) : (
                <div className="space-y-3">
                  {designReview.risks.map((risk, i) => (
                    <div key={`risk-${i}`} className="rounded-lg border border-border">
                      <button
                        type="button"
                        className="w-full px-4 py-3 flex items-center gap-3 hover:bg-muted/30 transition-colors text-left"
                        onClick={() => toggleRiskExpanded(i)}
                      >
                        <ChevronRight className={`size-4 text-muted-foreground transition-transform ${expandedRisks.has(i) ? "rotate-90" : ""}`} />
                        <span className="font-medium text-sm flex-1">{risk.title}</span>
                        <Badge variant="outline" className={`text-xs ${getSeverityColor(risk.severity)}`}>
                          {risk.severity}
                        </Badge>
                        <Badge variant="outline" className={`text-xs ${getStrideColor(risk.category)}`}>
                          {risk.category}
                        </Badge>
                        <span className="text-xs text-muted-foreground">{risk.component}</span>
                        <Badge
                          variant="outline"
                          className={`text-xs ${
                            risk.implementationPhase === "pre-code"
                              ? "bg-violet-500/10 text-violet-700 border-violet-200"
                              : "bg-blue-500/10 text-blue-600 border-blue-200"
                          }`}
                        >
                          {risk.implementationPhase === "pre-code" ? "Pre-Code" : "During-Code"}
                        </Badge>
                      </button>
                      {expandedRisks.has(i) && (
                        <div className="px-4 pb-4 pt-1 space-y-3 border-t border-border">
                          <div>
                            <h4 className="text-xs font-semibold text-muted-foreground uppercase mb-1">Design Decision</h4>
                            <p className="text-sm text-foreground">{risk.designDecision}</p>
                          </div>
                          <div>
                            <h4 className="text-xs font-semibold text-muted-foreground uppercase mb-1">Recommendation</h4>
                            <p className="text-sm text-foreground">{risk.recommendation}</p>
                          </div>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </CollapsibleContent>
        </Collapsible>
      </Card>

      {/* Section C — Context Layer File */}
      <Card>
        <div className="px-6 py-4 border-b border-border flex items-center gap-2">
          <FileCode className="size-4 text-primary" />
          <h3 className="font-semibold">AI Agent Context Layer</h3>
        </div>
        <CardContent className="py-4 space-y-4">
          {!designReview.contextLayer ? (
            <div className="text-sm text-muted-foreground p-4 bg-muted/30 rounded-lg text-center">
              No context layer file generated.
            </div>
          ) : (
            <>
              <pre className="whitespace-pre-wrap text-sm bg-muted/50 p-4 rounded-lg max-h-[500px] overflow-auto border border-border">
                {designReview.contextLayer}
              </pre>
              <div className="flex items-center gap-2 flex-wrap">
                <Button
                  size="sm"
                  className="gap-1.5 bg-primary hover:bg-primary/90"
                  onClick={() => handleDownload("CLAUDE.md")}
                >
                  <FileDown className="size-3.5" />
                  Download as CLAUDE.md
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  className="gap-1.5 bg-transparent"
                  onClick={() => handleDownload("AGENTS.md")}
                >
                  Download as AGENTS.md
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  className="gap-1.5 bg-transparent"
                  onClick={() => handleDownload(".cursorrules")}
                >
                  Download as .cursorrules
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  className="gap-1.5 bg-transparent"
                  onClick={handleCopy}
                >
                  <ClipboardCopy className="size-3.5" />
                  {copied ? "Copied!" : "Copy to Clipboard"}
                </Button>
              </div>
            </>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

// ── Main Page ──

export default function ThreatModelingPage() {
  return (
    <ProjectProvider>
      <ThreatModelingContent />
    </ProjectProvider>
  )
}

function ThreatModelingContent() {
  const { projectId } = useProject()
  const [showNewSession, setShowNewSession] = useState(false)
  const [view, setView] = useState<"list" | "processing" | "detail">("list")
  const [sessions, setSessions] = useState<SessionSummary[]>([])
  const [sessionsLoading, setSessionsLoading] = useState(true)
  const [activeSession, setActiveSession] = useState<SessionDetail | null>(null)
  const [processingSessionId, setProcessingSessionId] = useState<string | null>(null)
  const [processingSource, setProcessingSource] = useState<"design-doc" | "github-repo" | null>(null)

  // Fetch sessions on mount and when project changes
  useEffect(() => {
    fetchSessions()
  }, [projectId])

  async function fetchSessions() {
    setSessionsLoading(true)
    try {
      const url = projectId
        ? `/api/threat-model/sessions?projectId=${projectId}`
        : "/api/threat-model/sessions"
      const res = await fetch(url)
      if (res.ok) {
        const data = await res.json()
        setSessions(data)
      }
    } catch {
      // Handle error
    } finally {
      setSessionsLoading(false)
    }
  }

  async function fetchSessionDetail(id: string) {
    try {
      const res = await fetch(`/api/threat-model/sessions/${id}`)
      if (res.ok) {
        const data = await res.json()
        setActiveSession(data)
        setView("detail")
      }
    } catch {
      // Handle error
    }
  }

  async function handleNewSession(data: {
    name: string
    source: "design-doc" | "github-repo"
    sourceRef: string
    framework: string
    file?: File
    documentContent?: string
  }): Promise<boolean> {
    try {
      // 1. Create the session
      let createRes: Response

      if (data.file) {
        // Use FormData for file upload
        const formData = new FormData()
        formData.append("name", data.name)
        formData.append("source", data.source)
        formData.append("sourceRef", data.sourceRef)
        formData.append("framework", data.framework)
        formData.append("file", data.file)
        if (projectId) formData.append("projectId", projectId)

        createRes = await fetch("/api/threat-model/sessions", {
          method: "POST",
          body: formData,
        })
      } else if (data.documentContent) {
        // Include document content in JSON body
        createRes = await fetch("/api/threat-model/sessions", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            name: data.name,
            source: data.source,
            sourceRef: data.sourceRef,
            framework: data.framework,
            documentContent: data.documentContent,
            projectId: projectId || undefined,
          }),
        })
      } else {
        // Default JSON behavior (github-repo)
        createRes = await fetch("/api/threat-model/sessions", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            name: data.name,
            source: data.source,
            sourceRef: data.sourceRef,
            framework: data.framework,
            projectId: projectId || undefined,
          }),
        })
      }

      if (!createRes.ok) {
        const errBody = await createRes.json().catch(() => ({}))
        console.error("Session creation failed:", errBody)
        return false
      }

      const session = await createRes.json()

      // 2. Trigger analysis
      const analyzeRes = await fetch(`/api/threat-model/sessions/${session.id}/analyze`, {
        method: "POST",
      })
      if (!analyzeRes.ok) {
        const errBody = await analyzeRes.json().catch(() => ({}))
        console.error("Analysis trigger failed:", errBody)
        return false
      }

      // 3. Show processing view — store the source for ProcessingState
      setProcessingSessionId(session.id)
      setProcessingSource(data.source)
      setView("processing")
      return true
    } catch (error) {
      console.error("Failed to start session:", error)
      return false
    }
  }

  function handleProcessingComplete(sessionId: string) {
    fetchSessionDetail(sessionId)
    fetchSessions() // Refresh the list
  }

  function handleSelectSession(id: string) {
    fetchSessionDetail(id)
  }

  return (
    <div className="flex h-screen bg-background">
      <AppSidebar />

      <main className="flex-1 flex flex-col overflow-hidden min-w-0">
        {/* List view */}
        {view === "list" && (
          <>
            <AppHeader title="Threat Modeling">
              <Badge variant="secondary" className="gap-1 text-xs">
                <Shield className="size-3" />
                {sessions.length} sessions
              </Badge>
            </AppHeader>
            <ScrollArea className="flex-1 overflow-hidden">
              <SessionsList
                sessions={sessions}
                loading={sessionsLoading}
                onSelect={handleSelectSession}
                onNewSession={() => setShowNewSession(true)}
                onDelete={() => fetchSessions()}
              />
            </ScrollArea>
          </>
        )}

        {/* Processing view */}
        {view === "processing" && processingSessionId && (
          <>
            <AppHeader title="Threat Modeling">
              <Badge variant="secondary" className="gap-1 text-xs">
                <Clock className="size-3" />
                Generating...
              </Badge>
            </AppHeader>
            <ProcessingState
              sessionId={processingSessionId}
              source={processingSource || undefined}
              onComplete={handleProcessingComplete}
            />
          </>
        )}

        {/* Detail view */}
        {view === "detail" && activeSession && (
          <SessionDetailView
            session={activeSession}
            onBack={() => {
              setView("list")
              setActiveSession(null)
              fetchSessions()
            }}
          />
        )}
      </main>

      <NewSessionDialog
        open={showNewSession}
        onOpenChange={setShowNewSession}
        onStart={handleNewSession}
      />
    </div>
  )
}
