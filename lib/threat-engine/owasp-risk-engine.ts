// OWASP Risk Rating Methodology
// https://owasp.org/www-community/OWASP_Risk_Rating_Methodology

export interface OwaspLikelihood {
  // Threat Agent Factors
  skillLevel: number;        // 0-9
  motive: number;            // 0-9
  opportunity: number;       // 0-9
  size: number;              // 0-9
  // Vulnerability Factors
  easeOfDiscovery: number;   // 0-9
  easeOfExploit: number;     // 0-9
  awareness: number;         // 0-9
  intrusionDetection: number;// 0-9
}

export interface OwaspImpact {
  // Technical Impact Factors
  confidentiality: number;   // 0-9
  integrity: number;         // 0-9
  availability: number;      // 0-9
  accountability: number;    // 0-9
}

export type RiskLevel = "LOW" | "MEDIUM" | "HIGH";
export type RiskSeverity = "Note" | "Low" | "Medium" | "High" | "Critical";

export interface OwaspRiskRating {
  likelihood: OwaspLikelihood;
  impact: OwaspImpact;
  likelihoodScore: number;
  impactScore: number;
  likelihoodLevel: RiskLevel;
  impactLevel: RiskLevel;
  riskSeverity: RiskSeverity;
  overallRiskScore: number;
}

function clamp(value: number): number {
  return Math.max(0, Math.min(9, Math.round(value)));
}

export function getLevel(score: number): RiskLevel {
  if (score < 3) return "LOW";
  if (score < 6) return "MEDIUM";
  return "HIGH";
}

// OWASP Risk Matrix
const RISK_MATRIX: Record<RiskLevel, Record<RiskLevel, RiskSeverity>> = {
  HIGH: {
    LOW: "Medium",
    MEDIUM: "High",
    HIGH: "Critical",
  },
  MEDIUM: {
    LOW: "Low",
    MEDIUM: "Medium",
    HIGH: "High",
  },
  LOW: {
    LOW: "Note",
    MEDIUM: "Low",
    HIGH: "Medium",
  },
};

export function getRiskSeverity(
  impactLevel: RiskLevel,
  likelihoodLevel: RiskLevel
): RiskSeverity {
  return RISK_MATRIX[impactLevel][likelihoodLevel];
}

export function validateLikelihood(
  raw: Partial<OwaspLikelihood> | undefined
): OwaspLikelihood {
  const defaults: OwaspLikelihood = {
    skillLevel: 5,
    motive: 5,
    opportunity: 5,
    size: 5,
    easeOfDiscovery: 5,
    easeOfExploit: 5,
    awareness: 5,
    intrusionDetection: 5,
  };
  if (!raw) return defaults;
  return {
    skillLevel: clamp(raw.skillLevel ?? defaults.skillLevel),
    motive: clamp(raw.motive ?? defaults.motive),
    opportunity: clamp(raw.opportunity ?? defaults.opportunity),
    size: clamp(raw.size ?? defaults.size),
    easeOfDiscovery: clamp(raw.easeOfDiscovery ?? defaults.easeOfDiscovery),
    easeOfExploit: clamp(raw.easeOfExploit ?? defaults.easeOfExploit),
    awareness: clamp(raw.awareness ?? defaults.awareness),
    intrusionDetection: clamp(
      raw.intrusionDetection ?? defaults.intrusionDetection
    ),
  };
}

export function validateImpact(
  raw: Partial<OwaspImpact> | undefined
): OwaspImpact {
  const defaults: OwaspImpact = {
    confidentiality: 5,
    integrity: 5,
    availability: 5,
    accountability: 5,
  };
  if (!raw) return defaults;
  return {
    confidentiality: clamp(raw.confidentiality ?? defaults.confidentiality),
    integrity: clamp(raw.integrity ?? defaults.integrity),
    availability: clamp(raw.availability ?? defaults.availability),
    accountability: clamp(raw.accountability ?? defaults.accountability),
  };
}

export function calculateRiskRating(
  rawLikelihood: Partial<OwaspLikelihood> | undefined,
  rawImpact: Partial<OwaspImpact> | undefined
): OwaspRiskRating {
  const likelihood = validateLikelihood(rawLikelihood);
  const impact = validateImpact(rawImpact);

  const likelihoodScore =
    (likelihood.skillLevel +
      likelihood.motive +
      likelihood.opportunity +
      likelihood.size +
      likelihood.easeOfDiscovery +
      likelihood.easeOfExploit +
      likelihood.awareness +
      likelihood.intrusionDetection) /
    8;

  const impactScore =
    (impact.confidentiality +
      impact.integrity +
      impact.availability +
      impact.accountability) /
    4;

  const likelihoodLevel = getLevel(likelihoodScore);
  const impactLevel = getLevel(impactScore);
  const riskSeverity = getRiskSeverity(impactLevel, likelihoodLevel);

  return {
    likelihood,
    impact,
    likelihoodScore: Math.round(likelihoodScore * 100) / 100,
    impactScore: Math.round(impactScore * 100) / 100,
    likelihoodLevel,
    impactLevel,
    riskSeverity,
    overallRiskScore:
      Math.round(likelihoodScore * impactScore * 100) / 100,
  };
}
