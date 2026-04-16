"use client"

import { Issue } from "../types"
import { AnalysisData, ScopeData } from "../lib/types"
import { buildGraph } from "../lib/aggregations"
import { DataFlowDiagram } from "../components/DataFlowDiagram"
import { ArrowRightLeft, Box, Globe } from "lucide-react"

export function SystemView({
  issues,
  analysis,
  scope,
  dfdMermaid,
  selectedComponent,
  onSelectComponent,
}: {
  issues: Issue[]
  analysis?: AnalysisData
  scope?: ScopeData
  dfdMermaid?: string
  selectedComponent: string | null
  onSelectComponent: (component: string | null) => void
}) {
  const { nodes, edges } = buildGraph(issues)

  const external = nodes.filter((n) => n.zone === "external")
  const internal = nodes.filter((n) => n.zone === "internal")

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatCard
          icon={<Box className="h-4 w-4" />}
          label="Components"
          value={analysis?.components ?? internal.length}
        />
        <StatCard
          icon={<ArrowRightLeft className="h-4 w-4" />}
          label="Data Flows"
          value={analysis?.data_flows ?? edges.length}
        />
        <StatCard
          icon={<Globe className="h-4 w-4" />}
          label="External Actors"
          value={external.length}
        />
        <StatCard label="Threats" value={issues.length} />
      </div>

      {selectedComponent && (
        <div className="flex items-center justify-between p-3 rounded-lg border bg-primary/5">
          <p className="text-sm">
            Filtered by <strong>{selectedComponent}</strong>
          </p>
          <button
            className="text-sm text-primary hover:underline"
            onClick={() => onSelectComponent(null)}
          >
            Clear filter
          </button>
        </div>
      )}

      {dfdMermaid && <DataFlowDiagram mermaid={dfdMermaid} />}

      <div className="border rounded-lg p-6 bg-muted/20">
        <h3 className="text-sm font-medium text-muted-foreground mb-4">
          {dfdMermaid ? "Threat distribution" : "Architecture"}
        </h3>
        {nodes.length === 0 ? (
          <p className="text-sm text-muted-foreground text-center py-8">
            No component information available in issue metadata.
          </p>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-[1fr_auto_2fr] gap-4 items-stretch">
            <Zone label="External">
              {external.length === 0 ? (
                <EmptyZone />
              ) : (
                external.map((n) => (
                  <NodeBox
                    key={n.id}
                    label={n.label}
                    issueCount={n.issueCount}
                    criticalCount={n.criticalCount}
                    selected={selectedComponent === n.id}
                    onClick={() =>
                      onSelectComponent(selectedComponent === n.id ? null : n.id)
                    }
                  />
                ))
              )}
            </Zone>

            <div className="hidden md:flex flex-col justify-center items-center text-muted-foreground">
              <ArrowRightLeft className="h-5 w-5" />
              <span className="text-xs mt-1">{edges.length} flows</span>
            </div>

            <Zone label="Internal">
              {internal.length === 0 ? (
                <EmptyZone />
              ) : (
                internal.map((n) => (
                  <NodeBox
                    key={n.id}
                    label={n.label}
                    issueCount={n.issueCount}
                    criticalCount={n.criticalCount}
                    selected={selectedComponent === n.id}
                    onClick={() =>
                      onSelectComponent(selectedComponent === n.id ? null : n.id)
                    }
                  />
                ))
              )}
            </Zone>
          </div>
        )}

        {edges.length > 0 && (
          <div className="mt-6">
            <h4 className="text-xs font-semibold text-muted-foreground mb-2">Observed flows</h4>
            <ul className="space-y-1">
              {edges.map((e, idx) => (
                <li key={idx} className="text-sm font-mono text-muted-foreground">
                  {e.from} → {e.to}
                  <span className="text-xs ml-2">({e.count})</span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>

      {scope && (scope.in_scope?.length || scope.out_of_scope?.length) ? (
        <div className="grid md:grid-cols-2 gap-4">
          {scope.in_scope && scope.in_scope.length > 0 && (
            <div className="border rounded-lg p-4">
              <h4 className="text-xs font-semibold text-muted-foreground mb-2">
                In Scope ({scope.in_scope.length})
              </h4>
              <ul className="space-y-1 text-sm">
                {scope.in_scope.map((s, i) => (
                  <li key={i}>
                    <span className="font-medium">{s.name}</span>
                    <span className="text-xs text-muted-foreground ml-2">({s.type})</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
          {scope.out_of_scope && scope.out_of_scope.length > 0 && (
            <div className="border rounded-lg p-4">
              <h4 className="text-xs font-semibold text-muted-foreground mb-2">
                Out of Scope ({scope.out_of_scope.length})
              </h4>
              <ul className="space-y-1 text-sm">
                {scope.out_of_scope.map((s, i) => (
                  <li key={i}>
                    <span className="font-medium">{s.name}</span>
                    <span className="text-xs text-muted-foreground ml-2">({s.type})</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      ) : null}
    </div>
  )
}

function StatCard({
  icon,
  label,
  value,
}: {
  icon?: React.ReactNode
  label: string
  value: number | string
}) {
  return (
    <div className="p-3 bg-background rounded-lg border">
      <div className="flex items-center gap-2 mb-1 text-muted-foreground">
        {icon}
        <span className="text-xs font-medium">{label}</span>
      </div>
      <p className="text-2xl font-bold">{value}</p>
    </div>
  )
}

function Zone({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-2">
      <p className="text-xs uppercase tracking-wider text-muted-foreground">{label}</p>
      <div className="flex flex-col gap-2">{children}</div>
    </div>
  )
}

function EmptyZone() {
  return (
    <div className="p-4 border border-dashed rounded-lg text-xs text-muted-foreground text-center">
      (none)
    </div>
  )
}

function NodeBox({
  label,
  issueCount,
  criticalCount,
  selected,
  onClick,
}: {
  label: string
  issueCount: number
  criticalCount: number
  selected: boolean
  onClick: () => void
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`text-left p-3 rounded-lg border transition-colors ${
        selected
          ? "bg-primary/10 border-primary"
          : "bg-background hover:border-primary/50"
      }`}
    >
      <p className="font-medium text-sm">{label}</p>
      <div className="flex items-center gap-2 mt-1 text-xs text-muted-foreground">
        <span>{issueCount} threats</span>
        {criticalCount > 0 && (
          <span className="text-red-600 font-medium">· {criticalCount} critical</span>
        )}
      </div>
    </button>
  )
}
