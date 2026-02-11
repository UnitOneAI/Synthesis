"use client"

import { useCallback, useEffect, useState } from "react"
import { FileCode, Loader2, Shield, Zap } from "lucide-react"

import { Badge } from "@/components/ui/badge"
import { Card, CardContent } from "@/components/ui/card"
import { ScrollArea } from "@/components/ui/scroll-area"
import { AppHeader, AppSidebar, ProjectProvider } from "@/components/unitone/app-sidebar"
import { ApplyFixButton } from "@/components/unitone/apply-fix-button"

interface AutoFixItem {
  id: string
  threat_id: string
  description: string
  status: string
  code_file: string | null
  code_line: number | null
  code_original: string | null
  code_fixed: string | null
  threat_title: string
  severity: string
  session_id: string
  session_name: string
  source: string
  source_ref: string
}

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

function getStatusColor(status: string) {
  switch (status) {
    case "Proposed":
      return "bg-blue-500/10 text-blue-600 border-blue-200"
    case "Implemented":
      return "bg-green-500/10 text-green-600 border-green-200"
    default:
      return "bg-muted text-muted-foreground border-border"
  }
}

export default function AutoFixPage() {
  const [fixes, setFixes] = useState<AutoFixItem[]>([])
  const [loading, setLoading] = useState(true)

  const loadFixes = useCallback(async () => {
    setLoading(true)
    try {
      const res = await fetch("/api/autofix")
      if (res.ok) {
        setFixes(await res.json())
      }
    } catch {
      // Handle error silently
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    loadFixes()
  }, [loadFixes])

  const pendingFixes = fixes.filter((f) => f.status === "Proposed")
  const appliedFixes = fixes.filter((f) => f.status === "Implemented")

  function handleApplied(fixId: string) {
    setFixes((prev) =>
      prev.map((f) =>
        f.id === fixId ? { ...f, status: "Implemented" } : f
      )
    )
  }

  return (
    <ProjectProvider>
      <div className="flex h-screen bg-background">
        <AppSidebar />
        <main className="flex-1 flex flex-col overflow-hidden min-w-0">
          <AppHeader title="AutoFix Queue">
            <Badge variant="secondary" className="gap-1 text-xs">
              <Zap className="size-3" />
              {pendingFixes.length} Pending
            </Badge>
          </AppHeader>

          <ScrollArea className="flex-1 overflow-hidden">
            <div className="p-6 max-w-4xl space-y-8">
              {loading ? (
                <div className="flex items-center justify-center py-16">
                  <Loader2 className="size-6 animate-spin text-muted-foreground" />
                </div>
              ) : fixes.length === 0 ? (
                <Card className="py-12">
                  <CardContent className="text-center">
                    <Zap className="size-10 text-muted-foreground mx-auto mb-3" />
                    <h4 className="font-semibold mb-1">No Code Fixes Available</h4>
                    <p className="text-sm text-muted-foreground">
                      When threat analysis identifies code-level mitigations, they will appear here for review and one-click application.
                    </p>
                  </CardContent>
                </Card>
              ) : (
                <>
                  {/* Pending Fixes */}
                  {pendingFixes.length > 0 && (
                    <section>
                      <div className="flex items-center gap-2 mb-4">
                        <Zap className="size-5 text-primary" />
                        <h2 className="text-lg font-semibold">Pending Fixes</h2>
                        <Badge variant="secondary" className="text-xs">
                          {pendingFixes.length}
                        </Badge>
                      </div>
                      <div className="space-y-3">
                        {pendingFixes.map((fix) => (
                          <FixCard
                            key={fix.id}
                            fix={fix}
                            onApplied={() => handleApplied(fix.id)}
                          />
                        ))}
                      </div>
                    </section>
                  )}

                  {/* Applied Fixes */}
                  {appliedFixes.length > 0 && (
                    <section>
                      <div className="flex items-center gap-2 mb-4">
                        <Shield className="size-5 text-green-600" />
                        <h2 className="text-lg font-semibold">Applied Fixes</h2>
                        <Badge variant="secondary" className="text-xs">
                          {appliedFixes.length}
                        </Badge>
                      </div>
                      <div className="space-y-3">
                        {appliedFixes.map((fix) => (
                          <FixCard key={fix.id} fix={fix} />
                        ))}
                      </div>
                    </section>
                  )}
                </>
              )}
            </div>
          </ScrollArea>
        </main>
      </div>
    </ProjectProvider>
  )
}

function FixCard({
  fix,
  onApplied,
}: {
  fix: AutoFixItem
  onApplied?: () => void
}) {
  const isRepoSource = fix.source === "github-repo"
  const isPending = fix.status === "Proposed"

  return (
    <Card>
      <CardContent className="py-4 px-6">
        <div className="flex items-start justify-between gap-4">
          <div className="flex-1 min-w-0 space-y-2">
            {/* Top row: severity + threat title */}
            <div className="flex items-center gap-2 flex-wrap">
              <Badge
                variant="outline"
                className={`text-xs ${getSeverityColor(fix.severity)}`}
              >
                {fix.severity}
              </Badge>
              <span className="font-medium text-sm truncate">
                {fix.threat_title}
              </span>
            </div>

            {/* Mitigation description */}
            <p className="text-sm text-muted-foreground line-clamp-2">
              {fix.description}
            </p>

            {/* File path + session info */}
            <div className="flex items-center gap-4 text-xs text-muted-foreground">
              {fix.code_file && (
                <div className="flex items-center gap-1">
                  <FileCode className="size-3" />
                  <span className="font-mono">
                    {fix.code_file}
                    {fix.code_line ? `:${fix.code_line}` : ""}
                  </span>
                </div>
              )}
              <div className="flex items-center gap-1">
                <Shield className="size-3" />
                <span>{fix.session_name}</span>
              </div>
            </div>
          </div>

          {/* Right side: status badge + action */}
          <div className="flex flex-col items-end gap-2 shrink-0">
            <Badge
              variant="outline"
              className={`text-xs ${getStatusColor(fix.status)}`}
            >
              {fix.status}
            </Badge>
            {isPending && (
              <ApplyFixButton
                threatId={fix.threat_id}
                mitigationId={fix.id}
                hasCodeFix={!!fix.code_fixed}
                isRepoSource={isRepoSource}
                onApplied={() => onApplied?.()}
              />
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
