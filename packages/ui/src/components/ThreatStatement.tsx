"use client"

import { BookOpen } from "lucide-react"
import { Issue } from "../types"

// Renders a colored threat statement: actor (red) with prerequisites (muted)
// can action the asset (orange), which leads to impact. Sources fields from
// issue.metadata first, then falls back to parsed description text.
export function ThreatStatement({
  issue,
  fallback,
}: {
  issue: Issue
  fallback?: string
}) {
  const actor = str(issue.metadata?.threat_source)
  const prerequisites = str(issue.metadata?.prerequisites)
  const action = str(issue.metadata?.threat_action)
  const impact = str(issue.metadata?.threat_impact)
  const assetsRaw = issue.metadata?.impacted_assets
  const assets = Array.isArray(assetsRaw)
    ? assetsRaw.filter(Boolean).join(", ")
    : str(assetsRaw)

  const hasStructured = actor || action || assets || impact

  return (
    <section>
      <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
        <BookOpen className="h-4 w-4 text-primary" />
        Threat Statement
      </h3>
      <div className="bg-muted/50 rounded-lg p-4 border">
        {hasStructured ? (
          <p className="text-sm leading-relaxed">
            A{" "}
            <span className="text-red-600 font-medium">{actor || "threat actor"}</span>
            {prerequisites && (
              <>
                {" "}
                <span className="text-muted-foreground">with {prerequisites}</span>
              </>
            )}
            {" "}can {action || "perform an action"}
            {assets && (
              <>
                {" "}on{" "}
                <span className="text-orange-600 font-medium">{assets}</span>
              </>
            )}
            {impact && (
              <>
                , which leads to <span className="font-medium">{impact}</span>
              </>
            )}
            .
          </p>
        ) : (
          <p className="text-sm leading-relaxed text-muted-foreground">
            {fallback || "Threat details not available."}
          </p>
        )}
      </div>
    </section>
  )
}

function str(v: unknown): string {
  return typeof v === "string" ? v.trim() : ""
}
