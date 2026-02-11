import type { ThreatRow, MitigationRow } from "../db";

// ── Types ──

export interface InsightMetrics {
  strideCoverage: {
    covered: string[];
    missing: string[];
    total: number;
    percentage: number;
  };
  severityDistribution: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  mitigationRate: {
    threatsWithMitigation: number;
    totalThreats: number;
    percentage: number;
  };
  statusDistribution: {
    identified: number;
    inProgress: number;
    mitigated: number;
    accepted: number;
  };
  strideBreakdown: {
    category: string;
    count: number;
    abbreviation: string;
  }[];
  riskScore: number; // 0-100, lower is better
  recommendations: string[];
}

// ── Constants ──

const ALL_STRIDE_CATEGORIES = [
  "Spoofing",
  "Tampering",
  "Repudiation",
  "Information Disclosure",
  "Denial of Service",
  "Elevation of Privilege",
];

const STRIDE_ABBREVIATIONS: Record<string, string> = {
  Spoofing: "S",
  Tampering: "T",
  Repudiation: "R",
  "Information Disclosure": "I",
  "Denial of Service": "D",
  "Elevation of Privilege": "E",
};

// ── Main Engine ──

export function computeInsights(
  threats: ThreatRow[],
  mitigationsByThreat: Map<string, MitigationRow[]>
): InsightMetrics {
  // STRIDE Coverage
  const coveredCategories = new Set(
    threats.map((t) => t.stride_category)
  );
  const covered = ALL_STRIDE_CATEGORIES.filter((c) =>
    coveredCategories.has(c)
  );
  const missing = ALL_STRIDE_CATEGORIES.filter(
    (c) => !coveredCategories.has(c)
  );

  const strideCoverage = {
    covered,
    missing,
    total: ALL_STRIDE_CATEGORIES.length,
    percentage: Math.round(
      (covered.length / ALL_STRIDE_CATEGORIES.length) * 100
    ),
  };

  // Severity Distribution
  const severityDistribution = {
    critical: threats.filter((t) => t.severity === "Critical").length,
    high: threats.filter((t) => t.severity === "High").length,
    medium: threats.filter((t) => t.severity === "Medium").length,
    low: threats.filter((t) => t.severity === "Low").length,
  };

  // Mitigation Rate
  const threatsWithMitigation = threats.filter((t) => {
    const mits = mitigationsByThreat.get(t.id) || [];
    return mits.length > 0;
  }).length;

  const mitigationRate = {
    threatsWithMitigation,
    totalThreats: threats.length,
    percentage:
      threats.length > 0
        ? Math.round((threatsWithMitigation / threats.length) * 100)
        : 0,
  };

  // Status Distribution
  const statusDistribution = {
    identified: threats.filter((t) => t.status === "Identified").length,
    inProgress: threats.filter((t) => t.status === "In Progress").length,
    mitigated: threats.filter((t) => t.status === "Mitigated").length,
    accepted: threats.filter((t) => t.status === "Accepted").length,
  };

  // STRIDE Breakdown
  const strideBreakdown = ALL_STRIDE_CATEGORIES.map((category) => ({
    category,
    count: threats.filter((t) => t.stride_category === category).length,
    abbreviation: STRIDE_ABBREVIATIONS[category] || "?",
  }));

  // Risk Score (0-100, lower is better)
  const riskScore = computeRiskScore(
    threats,
    severityDistribution,
    mitigationRate,
    statusDistribution
  );

  // Recommendations
  const recommendations = generateRecommendations(
    strideCoverage,
    severityDistribution,
    mitigationRate,
    statusDistribution,
    threats
  );

  return {
    strideCoverage,
    severityDistribution,
    mitigationRate,
    statusDistribution,
    strideBreakdown,
    riskScore,
    recommendations,
  };
}

function computeRiskScore(
  threats: ThreatRow[],
  severity: InsightMetrics["severityDistribution"],
  mitigation: InsightMetrics["mitigationRate"],
  status: InsightMetrics["statusDistribution"]
): number {
  if (threats.length === 0) return 0;

  // Weighted severity score (higher severity = more risk)
  const severityScore =
    (severity.critical * 10 +
      severity.high * 7 +
      severity.medium * 4 +
      severity.low * 1) /
    threats.length;

  // Mitigation penalty (unmitigated threats = more risk)
  const unmitigatedRatio = 1 - mitigation.percentage / 100;

  // Status penalty (identified/unaddressed threats = more risk)
  const identifiedRatio = status.identified / threats.length;

  // Combine: base severity × unmitigated factor × identified factor
  const rawScore =
    severityScore * 10 * (0.5 + unmitigatedRatio * 0.5) * (0.5 + identifiedRatio * 0.5);

  return Math.min(100, Math.round(rawScore));
}

function generateRecommendations(
  strideCoverage: InsightMetrics["strideCoverage"],
  severity: InsightMetrics["severityDistribution"],
  mitigation: InsightMetrics["mitigationRate"],
  status: InsightMetrics["statusDistribution"],
  threats: ThreatRow[]
): string[] {
  const recs: string[] = [];

  // Missing STRIDE categories
  if (strideCoverage.missing.length > 0) {
    recs.push(
      `Consider threats in uncovered STRIDE categories: ${strideCoverage.missing.join(", ")}. Your model covers ${strideCoverage.percentage}% of categories.`
    );
  }

  // Unmitigated critical threats
  if (severity.critical > 0) {
    const unmitigatedCritical = threats.filter(
      (t) => t.severity === "Critical" && t.status !== "Mitigated"
    ).length;
    if (unmitigatedCritical > 0) {
      recs.push(
        `${unmitigatedCritical} critical threat(s) remain unmitigated. Prioritize these immediately.`
      );
    }
  }

  // Low mitigation rate
  if (mitigation.percentage < 50) {
    recs.push(
      `Mitigation rate is ${mitigation.percentage}%. Aim for at least 80% of threats to have defined mitigations.`
    );
  }

  // Many identified (unstarted) threats
  if (status.identified > threats.length * 0.5 && threats.length > 3) {
    recs.push(
      `${status.identified} of ${threats.length} threats are still in "Identified" status. Begin triaging and assigning mitigations.`
    );
  }

  // Perfect score
  if (
    strideCoverage.percentage === 100 &&
    mitigation.percentage >= 80 &&
    severity.critical === 0
  ) {
    recs.push(
      "Threat model quality is high. Consider scheduling a review to validate mitigations are effective."
    );
  }

  return recs;
}

// ── Convenience: compute insights from raw DB data ──

export function computeInsightsFromDb(
  threats: ThreatRow[],
  getMitigations: (threatId: string) => MitigationRow[]
): InsightMetrics {
  const mitigationsByThreat = new Map<string, MitigationRow[]>();
  for (const t of threats) {
    mitigationsByThreat.set(t.id, getMitigations(t.id));
  }
  return computeInsights(threats, mitigationsByThreat);
}
