"use client"

import { useState } from "react"
import {
  ArrowRightLeft,
  Box,
  ChevronDown,
  ChevronRight,
  Code,
  Layers,
  Shield,
  Target,
  UserX,
} from "lucide-react"
import { AnalysisData, ScopeData } from "../lib/types"

export function ScopeSection({
  analysis,
  scope,
}: {
  analysis?: AnalysisData
  scope?: ScopeData
}) {
  const [expanded, setExpanded] = useState(false)

  const hasAnalysis =
    analysis &&
    (analysis.languages?.length ||
      analysis.frameworks?.length ||
      analysis.components ||
      analysis.data_flows)
  const hasScope = scope && (scope.in_scope?.length || scope.out_of_scope?.length)

  if (!hasAnalysis && !hasScope) {
    return null
  }

  return (
    <div className="border rounded-lg bg-muted/30">
      <button
        className="w-full p-4 flex items-center justify-between text-left"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-center gap-2">
          <Target className="h-4 w-4 text-muted-foreground" />
          <span className="font-medium">Analysis Scope</span>
          {analysis && (
            <span className="text-sm text-muted-foreground">
              {analysis.components || 0} components, {analysis.data_flows || 0} data flows
            </span>
          )}
        </div>
        {expanded ? (
          <ChevronDown className="h-4 w-4 text-muted-foreground" />
        ) : (
          <ChevronRight className="h-4 w-4 text-muted-foreground" />
        )}
      </button>

      {expanded && (
        <div className="px-4 pb-4 space-y-4">
          {hasAnalysis && (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              {analysis!.languages && analysis!.languages.length > 0 && (
                <div className="p-3 bg-background rounded-lg border">
                  <div className="flex items-center gap-2 mb-1">
                    <Code className="h-3.5 w-3.5 text-muted-foreground" />
                    <span className="text-xs font-medium text-muted-foreground">Languages</span>
                  </div>
                  <p className="text-sm font-medium">{analysis!.languages.join(", ")}</p>
                </div>
              )}
              {analysis!.frameworks && analysis!.frameworks.length > 0 && (
                <div className="p-3 bg-background rounded-lg border">
                  <div className="flex items-center gap-2 mb-1">
                    <Layers className="h-3.5 w-3.5 text-muted-foreground" />
                    <span className="text-xs font-medium text-muted-foreground">Frameworks</span>
                  </div>
                  <p className="text-sm font-medium">{analysis!.frameworks.join(", ")}</p>
                </div>
              )}
              {analysis!.components !== undefined && (
                <div className="p-3 bg-background rounded-lg border">
                  <div className="flex items-center gap-2 mb-1">
                    <Box className="h-3.5 w-3.5 text-muted-foreground" />
                    <span className="text-xs font-medium text-muted-foreground">Components</span>
                  </div>
                  <p className="text-sm font-medium">{analysis!.components}</p>
                </div>
              )}
              {analysis!.data_flows !== undefined && (
                <div className="p-3 bg-background rounded-lg border">
                  <div className="flex items-center gap-2 mb-1">
                    <ArrowRightLeft className="h-3.5 w-3.5 text-muted-foreground" />
                    <span className="text-xs font-medium text-muted-foreground">Data Flows</span>
                  </div>
                  <p className="text-sm font-medium">{analysis!.data_flows}</p>
                </div>
              )}
            </div>
          )}

          {hasScope && (
            <div className="grid md:grid-cols-2 gap-4">
              {scope!.in_scope && scope!.in_scope.length > 0 && (
                <div>
                  <h4 className="text-xs font-semibold text-muted-foreground mb-2 flex items-center gap-1">
                    <Shield className="h-3 w-3 text-green-600" />
                    In Scope ({scope!.in_scope.length})
                  </h4>
                  <ul className="space-y-1">
                    {scope!.in_scope.map((item, idx) => (
                      <li
                        key={idx}
                        className="text-sm p-2 bg-green-500/5 rounded border border-green-200/50"
                      >
                        <span className="font-medium">{item.name}</span>
                        <span className="text-muted-foreground ml-2 text-xs">({item.type})</span>
                        {item.description && (
                          <p className="text-xs text-muted-foreground mt-0.5">{item.description}</p>
                        )}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              {scope!.out_of_scope && scope!.out_of_scope.length > 0 && (
                <div>
                  <h4 className="text-xs font-semibold text-muted-foreground mb-2 flex items-center gap-1">
                    <UserX className="h-3 w-3 text-gray-500" />
                    Out of Scope ({scope!.out_of_scope.length})
                  </h4>
                  <ul className="space-y-1">
                    {scope!.out_of_scope.map((item, idx) => (
                      <li key={idx} className="text-sm p-2 bg-muted/50 rounded border">
                        <span className="font-medium">{item.name}</span>
                        <span className="text-muted-foreground ml-2 text-xs">({item.type})</span>
                        {item.description && (
                          <p className="text-xs text-muted-foreground mt-0.5">{item.description}</p>
                        )}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
