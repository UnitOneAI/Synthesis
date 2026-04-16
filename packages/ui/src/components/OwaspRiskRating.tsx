"use client"

import { useState } from "react"
import { Badge } from "../primitives"
import { ChevronDown, ChevronRight, ShieldAlert } from "lucide-react"
import {
  FACTOR_LABELS,
  IMPACT_FACTORS,
  LIKELIHOOD_FACTORS,
  OwaspRiskRating as RiskRating,
  RiskLevel,
  RiskSeverity,
  owaspBarColor,
  riskSeverityColor,
} from "../lib/owasp-risk"

export function OwaspRiskRating({ rating }: { rating: RiskRating }) {
  const [showFactors, setShowFactors] = useState(false)

  return (
    <section>
      <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
        <ShieldAlert className="h-4 w-4 text-primary" />
        OWASP Risk Rating
      </h3>

      <div className="border rounded-lg p-4 space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-[auto_1fr] gap-4 items-start">
          <RiskMatrix
            impactLevel={rating.impactLevel}
            likelihoodLevel={rating.likelihoodLevel}
            riskSeverity={rating.riskSeverity}
          />

          <div className="space-y-3">
            <ScoreBar label="Likelihood" score={rating.likelihoodScore} level={rating.likelihoodLevel} />
            <ScoreBar label="Impact" score={rating.impactScore} level={rating.impactLevel} />
            <div className="flex items-center gap-2 pt-2 border-t">
              <span className="text-xs text-muted-foreground">Overall Risk:</span>
              <Badge variant="outline" className={riskSeverityColor(rating.riskSeverity)}>
                {rating.riskSeverity}
              </Badge>
            </div>
          </div>
        </div>

        <div className="border-t pt-3">
          <button
            type="button"
            onClick={() => setShowFactors(!showFactors)}
            className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground"
          >
            {showFactors ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
            Factor Breakdown
          </button>

          {showFactors && (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mt-3">
              <FactorGroup title="Likelihood factors" factors={LIKELIHOOD_FACTORS} values={rating.likelihood as any} />
              <FactorGroup title="Impact factors" factors={IMPACT_FACTORS} values={rating.impact as any} />
            </div>
          )}
        </div>
      </div>
    </section>
  )
}

function ScoreBar({
  label,
  score,
  level,
}: {
  label: string
  score: number
  level: RiskLevel
}) {
  const pct = (score / 9) * 100
  return (
    <div>
      <div className="flex items-center justify-between text-xs mb-1">
        <span className="text-muted-foreground">{label}</span>
        <span className="font-medium">
          {score.toFixed(1)} / 9 <span className="text-muted-foreground">({level})</span>
        </span>
      </div>
      <div className="h-2 bg-muted rounded-full overflow-hidden">
        <div
          className={`h-full ${owaspBarColor(score)} transition-all`}
          style={{ width: `${pct}%` }}
        />
      </div>
    </div>
  )
}

function FactorGroup({
  title,
  factors,
  values,
}: {
  title: string
  factors: string[]
  values: Record<string, number>
}) {
  return (
    <div>
      <p className="text-xs font-medium mb-2">{title}</p>
      <div className="space-y-1.5">
        {factors.map((f) => {
          const score = values[f] ?? 0
          const pct = (score / 9) * 100
          return (
            <div key={f} className="flex items-center gap-2 text-xs">
              <span className="text-muted-foreground flex-1 truncate">
                {FACTOR_LABELS[f] || f}
              </span>
              <div className="w-12 h-1.5 bg-muted rounded-full overflow-hidden">
                <div className={`h-full ${owaspBarColor(score)}`} style={{ width: `${pct}%` }} />
              </div>
              <span className="font-mono w-4 text-right">{score}</span>
            </div>
          )
        })}
      </div>
    </div>
  )
}

// 3x3 matrix. Rows = impact (H/M/L top to bottom), cols = likelihood (L/M/H left to right).
function RiskMatrix({
  impactLevel,
  likelihoodLevel,
  riskSeverity,
}: {
  impactLevel: RiskLevel
  likelihoodLevel: RiskLevel
  riskSeverity: RiskSeverity
}) {
  const rows: RiskLevel[] = ["HIGH", "MEDIUM", "LOW"]
  const cols: RiskLevel[] = ["LOW", "MEDIUM", "HIGH"]
  const matrix: Record<RiskLevel, Record<RiskLevel, RiskSeverity>> = {
    HIGH: { LOW: "Medium", MEDIUM: "High", HIGH: "Critical" },
    MEDIUM: { LOW: "Low", MEDIUM: "Medium", HIGH: "High" },
    LOW: { LOW: "Note", MEDIUM: "Low", HIGH: "Medium" },
  }

  function cellBg(sev: RiskSeverity, active: boolean) {
    const base =
      sev === "Critical"
        ? "bg-red-500/10 text-red-600"
        : sev === "High"
        ? "bg-orange-500/10 text-orange-600"
        : sev === "Medium"
        ? "bg-yellow-500/10 text-yellow-700"
        : "bg-green-500/10 text-green-600"
    return active ? `ring-2 ring-primary font-bold bg-primary/10 text-foreground` : base
  }

  return (
    <div className="flex items-stretch gap-2 shrink-0">
      <div className="flex flex-col items-center justify-center">
        <span className="text-[10px] text-muted-foreground rotate-[-90deg] whitespace-nowrap">
          Impact
        </span>
      </div>
      <div>
        <div className="grid grid-cols-[auto_repeat(3,minmax(0,1fr))] gap-1 text-[10px]">
          {rows.map((row) => (
            <>
              <div key={`label-${row}`} className="text-muted-foreground text-right pr-1 flex items-center justify-end">
                {row[0]}
              </div>
              {cols.map((col) => {
                const sev = matrix[row][col]
                const active = impactLevel === row && likelihoodLevel === col
                return (
                  <div
                    key={`${row}-${col}`}
                    className={`w-10 h-10 rounded flex items-center justify-center ${cellBg(sev, active)} border`}
                    title={`${sev} — impact ${row}, likelihood ${col}`}
                  >
                    {active ? riskSeverity[0] : ""}
                  </div>
                )
              })}
            </>
          ))}
          <div />
          {cols.map((col) => (
            <div key={`col-${col}`} className="text-muted-foreground text-center mt-0.5">
              {col[0]}
            </div>
          ))}
        </div>
        <p className="text-[10px] text-center text-muted-foreground mt-1">Likelihood →</p>
      </div>
    </div>
  )
}
