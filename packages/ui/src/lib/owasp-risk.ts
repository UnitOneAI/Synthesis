// Port of Synthesis's owasp-risk-engine to TypeScript on the frontend.
// Synthesis CLI outputs the raw likelihood/impact factor objects as part
// of issue.metadata; we compute scores + risk severity client-side.

export interface OwaspLikelihood {
  skillLevel: number
  motive: number
  opportunity: number
  size: number
  easeOfDiscovery: number
  easeOfExploit: number
  awareness: number
  intrusionDetection: number
}

export interface OwaspImpact {
  confidentiality: number
  integrity: number
  availability: number
  accountability: number
}

export type RiskLevel = "LOW" | "MEDIUM" | "HIGH"
export type RiskSeverity = "Note" | "Low" | "Medium" | "High" | "Critical"

export interface OwaspRiskRating {
  likelihood: OwaspLikelihood
  impact: OwaspImpact
  likelihoodScore: number
  impactScore: number
  likelihoodLevel: RiskLevel
  impactLevel: RiskLevel
  riskSeverity: RiskSeverity
  overallRiskScore: number
}

const LIKELIHOOD_DEFAULTS: OwaspLikelihood = {
  skillLevel: 5,
  motive: 5,
  opportunity: 5,
  size: 5,
  easeOfDiscovery: 5,
  easeOfExploit: 5,
  awareness: 5,
  intrusionDetection: 5,
}

const IMPACT_DEFAULTS: OwaspImpact = {
  confidentiality: 5,
  integrity: 5,
  availability: 5,
  accountability: 5,
}

function clamp(v: number): number {
  return Math.max(0, Math.min(9, Math.round(v)))
}

export function getLevel(score: number): RiskLevel {
  if (score < 3) return "LOW"
  if (score < 6) return "MEDIUM"
  return "HIGH"
}

const RISK_MATRIX: Record<RiskLevel, Record<RiskLevel, RiskSeverity>> = {
  HIGH: { LOW: "Medium", MEDIUM: "High", HIGH: "Critical" },
  MEDIUM: { LOW: "Low", MEDIUM: "Medium", HIGH: "High" },
  LOW: { LOW: "Note", MEDIUM: "Low", HIGH: "Medium" },
}

export function getRiskSeverity(
  impactLevel: RiskLevel,
  likelihoodLevel: RiskLevel
): RiskSeverity {
  return RISK_MATRIX[impactLevel][likelihoodLevel]
}

function validateLikelihood(raw: Partial<OwaspLikelihood> | undefined | null): OwaspLikelihood {
  if (!raw) return { ...LIKELIHOOD_DEFAULTS }
  const out = {} as OwaspLikelihood
  for (const key of Object.keys(LIKELIHOOD_DEFAULTS) as (keyof OwaspLikelihood)[]) {
    const value = raw[key]
    out[key] = typeof value === "number" ? clamp(value) : LIKELIHOOD_DEFAULTS[key]
  }
  return out
}

function validateImpact(raw: Partial<OwaspImpact> | undefined | null): OwaspImpact {
  if (!raw) return { ...IMPACT_DEFAULTS }
  const out = {} as OwaspImpact
  for (const key of Object.keys(IMPACT_DEFAULTS) as (keyof OwaspImpact)[]) {
    const value = raw[key]
    out[key] = typeof value === "number" ? clamp(value) : IMPACT_DEFAULTS[key]
  }
  return out
}

export function calculateRiskRating(
  rawLikelihood: Partial<OwaspLikelihood> | undefined | null,
  rawImpact: Partial<OwaspImpact> | undefined | null
): OwaspRiskRating {
  const likelihood = validateLikelihood(rawLikelihood)
  const impact = validateImpact(rawImpact)

  const likelihoodScore =
    (likelihood.skillLevel +
      likelihood.motive +
      likelihood.opportunity +
      likelihood.size +
      likelihood.easeOfDiscovery +
      likelihood.easeOfExploit +
      likelihood.awareness +
      likelihood.intrusionDetection) /
    8

  const impactScore =
    (impact.confidentiality + impact.integrity + impact.availability + impact.accountability) / 4

  const likelihoodLevel = getLevel(likelihoodScore)
  const impactLevel = getLevel(impactScore)
  const riskSeverity = getRiskSeverity(impactLevel, likelihoodLevel)

  return {
    likelihood,
    impact,
    likelihoodScore: Math.round(likelihoodScore * 100) / 100,
    impactScore: Math.round(impactScore * 100) / 100,
    likelihoodLevel,
    impactLevel,
    riskSeverity,
    overallRiskScore: Math.round(likelihoodScore * impactScore * 100) / 100,
  }
}

// Only return a rating if at least one factor was provided in the raw data.
// Avoids displaying a fake "Medium" rating for issues without OWASP scoring.
export function maybeCalculateRiskRating(
  rawLikelihood: unknown,
  rawImpact: unknown
): OwaspRiskRating | null {
  const hasLikelihood =
    rawLikelihood && typeof rawLikelihood === "object" && Object.keys(rawLikelihood).length > 0
  const hasImpact =
    rawImpact && typeof rawImpact === "object" && Object.keys(rawImpact).length > 0
  if (!hasLikelihood && !hasImpact) return null
  return calculateRiskRating(
    rawLikelihood as Partial<OwaspLikelihood>,
    rawImpact as Partial<OwaspImpact>
  )
}

export const LIKELIHOOD_FACTORS: (keyof OwaspLikelihood)[] = [
  "skillLevel",
  "motive",
  "opportunity",
  "size",
  "easeOfDiscovery",
  "easeOfExploit",
  "awareness",
  "intrusionDetection",
]

export const IMPACT_FACTORS: (keyof OwaspImpact)[] = [
  "confidentiality",
  "integrity",
  "availability",
  "accountability",
]

export const FACTOR_LABELS: Record<string, string> = {
  skillLevel: "Skill Level",
  motive: "Motive",
  opportunity: "Opportunity",
  size: "Size",
  easeOfDiscovery: "Ease of Discovery",
  easeOfExploit: "Ease of Exploit",
  awareness: "Awareness",
  intrusionDetection: "Intrusion Detection",
  confidentiality: "Confidentiality",
  integrity: "Integrity",
  availability: "Availability",
  accountability: "Accountability",
}

export function owaspBarColor(score: number): string {
  if (score < 3) return "bg-green-500"
  if (score < 6) return "bg-yellow-500"
  return "bg-red-500"
}

export function riskSeverityColor(severity: RiskSeverity): string {
  switch (severity) {
    case "Critical":
      return "bg-red-500/10 text-red-600 border-red-200"
    case "High":
      return "bg-orange-500/10 text-orange-600 border-orange-200"
    case "Medium":
      return "bg-yellow-500/10 text-yellow-700 border-yellow-200"
    case "Low":
    case "Note":
      return "bg-green-500/10 text-green-600 border-green-200"
  }
}
