"use client"

import { useState } from "react"
import { RunToolResponse } from "./types"
import { AnalysisData, ScopeData } from "./lib/types"
import { SystemView } from "./views/SystemView"
import { IssuesView } from "./views/IssuesView"
import { InsightsView } from "./views/InsightsView"
import { Network, AlertTriangle, BarChart3 } from "lucide-react"

type Tab = "system" | "issues" | "insights"

interface ThreatModelRendererProps {
  output: RunToolResponse
}

const TABS: { id: Tab; label: string; icon: React.ComponentType<{ className?: string }> }[] = [
  { id: "system", label: "System View", icon: Network },
  { id: "issues", label: "Issues View", icon: AlertTriangle },
  { id: "insights", label: "Insights", icon: BarChart3 },
]

export function ThreatModelRenderer({ output }: ThreatModelRendererProps) {
  const issues = output.issues || []
  const analysis = output.data?.analysis as AnalysisData | undefined
  const scope = output.data?.scope as ScopeData | undefined
  const dfdMermaid = typeof output.data?.dfd_mermaid === "string"
    ? (output.data.dfd_mermaid as string)
    : undefined

  // Default to Issues View (preserves current landing behavior)
  const [tab, setTab] = useState<Tab>("issues")
  const [selectedComponent, setSelectedComponent] = useState<string | null>(null)

  function handleSelectComponent(component: string | null) {
    setSelectedComponent(component)
    if (component) setTab("issues")
  }

  return (
    <div className="space-y-6">
      <div className="border-b flex gap-1">
        {TABS.map((t) => {
          const Icon = t.icon
          const active = tab === t.id
          return (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={`px-4 py-2 text-sm font-medium flex items-center gap-2 border-b-2 transition-colors -mb-px ${
                active
                  ? "border-primary text-foreground"
                  : "border-transparent text-muted-foreground hover:text-foreground"
              }`}
            >
              <Icon className="h-4 w-4" />
              {t.label}
              {t.id === "issues" && (
                <span className="text-xs text-muted-foreground">({issues.length})</span>
              )}
            </button>
          )
        })}
      </div>

      {tab === "system" && (
        <SystemView
          issues={issues}
          analysis={analysis}
          scope={scope}
          dfdMermaid={dfdMermaid}
          selectedComponent={selectedComponent}
          onSelectComponent={handleSelectComponent}
        />
      )}

      {tab === "issues" && (
        <IssuesView
          issues={issues}
          filterComponent={selectedComponent}
          onClearFilter={() => setSelectedComponent(null)}
        />
      )}

      {tab === "insights" && <InsightsView issues={issues} />}
    </div>
  )
}
