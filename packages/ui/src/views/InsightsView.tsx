"use client"

import { Issue, Severity } from "../types"
import {
  STRIDE_CATEGORIES,
  SEVERITIES,
  SEVERITY_COLORS,
  getStrideColor,
  getStrideLabel,
} from "../lib/constants"
import {
  computeByStride,
  computeBySeverity,
  deriveInsights,
} from "../lib/aggregations"

export function InsightsView({ issues }: { issues: Issue[] }) {
  const byStride = computeByStride(issues)
  const bySeverity = computeBySeverity(issues)
  const insights = deriveInsights(issues)

  const maxStride = Math.max(1, ...STRIDE_CATEGORIES.map((s) => byStride[s] || 0))
  const maxSeverity = Math.max(1, ...SEVERITIES.map((s) => bySeverity[s] || 0))

  return (
    <div className="space-y-6">
      {insights.length > 0 && (
        <div className="grid gap-3 md:grid-cols-2">
          {insights.map((ins, idx) => (
            <div key={idx} className="p-4 border rounded-lg bg-background">
              <p className="text-xs uppercase tracking-wider text-muted-foreground">
                {ins.label}
              </p>
              <p className="text-lg font-semibold mt-1">{ins.value}</p>
              {ins.detail && (
                <p className="text-xs text-muted-foreground mt-1">{ins.detail}</p>
              )}
            </div>
          ))}
        </div>
      )}

      <div>
        <h3 className="text-sm font-medium text-muted-foreground mb-3">STRIDE distribution</h3>
        <div className="space-y-2">
          {STRIDE_CATEGORIES.map((stride) => {
            const count = byStride[stride] || 0
            const pct = (count / maxStride) * 100
            return (
              <div key={stride} className="flex items-center gap-3">
                <div className="w-48 text-sm">{getStrideLabel(stride)}</div>
                <div className="flex-1 h-6 bg-muted rounded overflow-hidden">
                  <div
                    className={`h-full ${getStrideColor(stride).split(" ")[0]}`}
                    style={{ width: `${pct}%` }}
                  />
                </div>
                <div className="w-10 text-right text-sm font-medium">{count}</div>
              </div>
            )
          })}
        </div>
      </div>

      <div>
        <h3 className="text-sm font-medium text-muted-foreground mb-3">Severity distribution</h3>
        <div className="grid grid-cols-5 gap-2">
          {SEVERITIES.map((severity: Severity) => (
            <div
              key={severity}
              className={`p-3 rounded-lg text-center border ${SEVERITY_COLORS[severity]}`}
            >
              <p className="text-2xl font-bold">{bySeverity[severity] || 0}</p>
              <p className="text-xs uppercase">{severity}</p>
              <p className="text-xs mt-1 opacity-80">
                {Math.round(((bySeverity[severity] || 0) / Math.max(1, issues.length)) * 100)}%
              </p>
            </div>
          ))}
        </div>
        <div className="mt-3 h-3 rounded-full overflow-hidden flex bg-muted">
          {SEVERITIES.map((severity: Severity) => {
            const count = bySeverity[severity] || 0
            const pct = (count / Math.max(1, issues.length)) * 100
            if (pct === 0) return null
            return (
              <div
                key={severity}
                className={`${SEVERITY_COLORS[severity].split(" ")[0]}`}
                style={{ width: `${pct}%` }}
                title={`${severity}: ${count}`}
              />
            )
          })}
        </div>
      </div>
    </div>
  )
}
