"use client"

import { useState } from "react"
import { Issue } from "../types"
import { AlertTriangle, Box, Shield } from "lucide-react"
import { ThreatRow } from "../components/ThreatRow"
import { ThreatDetailPanel } from "../components/ThreatDetailPanel"
import { groupByComponent } from "../lib/aggregations"
import { getSystemContext } from "../lib/parse"

export function IssuesView({
  issues,
  filterComponent,
  onClearFilter,
}: {
  issues: Issue[]
  filterComponent: string | null
  onClearFilter: () => void
}) {
  const [selectedIssue, setSelectedIssue] = useState<Issue | null>(null)

  const filtered = filterComponent
    ? issues.filter((i) => {
        const ctx = getSystemContext(i)
        return (
          ctx.components.includes(filterComponent) ||
          ctx.boundaryFrom === filterComponent ||
          ctx.boundaryTo === filterComponent
        )
      })
    : issues

  const groups = groupByComponent(filtered)
  const groupNames = Object.keys(groups).sort((a, b) => groups[b].length - groups[a].length)

  if (filtered.length === 0) {
    return (
      <div className="text-center py-8 text-muted-foreground">
        <Shield className="h-12 w-12 mx-auto mb-3 opacity-50" />
        <p>
          {filterComponent
            ? `No threats match component "${filterComponent}"`
            : "No threats identified"}
        </p>
        {filterComponent && (
          <button className="text-sm text-primary hover:underline mt-2" onClick={onClearFilter}>
            Clear filter
          </button>
        )}
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h3 className="font-medium flex items-center gap-2">
          <AlertTriangle className="h-4 w-4" />
          Threats ({filtered.length})
          {filterComponent && (
            <span className="text-sm font-normal text-muted-foreground">
              · filtered by {filterComponent}
            </span>
          )}
        </h3>
        {filterComponent && (
          <button className="text-sm text-primary hover:underline" onClick={onClearFilter}>
            Clear filter
          </button>
        )}
      </div>

      <div className="space-y-6">
        {groupNames.map((name) => (
          <div key={name} className="border rounded-lg overflow-hidden">
            <div className="flex items-center gap-2 px-4 py-2 bg-muted/40 border-b">
              <Box className="h-4 w-4 text-muted-foreground" />
              <h4 className="font-medium text-sm">{name}</h4>
              <span className="text-xs text-muted-foreground">
                ({groups[name].length} {groups[name].length === 1 ? "issue" : "issues"})
              </span>
            </div>
            <div>
              {groups[name].map((issue, index) => (
                <ThreatRow
                  key={issue.issue_id || `${name}-${index}`}
                  issue={issue}
                  onOpen={() => setSelectedIssue(issue)}
                />
              ))}
            </div>
          </div>
        ))}
      </div>

      <ThreatDetailPanel
        issue={selectedIssue}
        onClose={() => setSelectedIssue(null)}
      />
    </div>
  )
}
