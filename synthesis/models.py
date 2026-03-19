"""
Threat Model Data Types.

Python equivalents of the TypeScript types in lib/threat-data.ts
Follows OWASP Risk Rating Methodology and AWS Threat Grammar.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any


# ─────────────────────────────────────────────────────────────────────────────
# Enums
# ─────────────────────────────────────────────────────────────────────────────

class StrideCategory(str, Enum):
    """STRIDE threat categories."""
    SPOOFING = "Spoofing"
    TAMPERING = "Tampering"
    REPUDIATION = "Repudiation"
    INFORMATION_DISCLOSURE = "Information Disclosure"
    DENIAL_OF_SERVICE = "Denial of Service"
    ELEVATION_OF_PRIVILEGE = "Elevation of Privilege"


class Severity(str, Enum):
    """Threat severity levels."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    NOTE = "Note"  # OWASP lowest level


class ThreatStatus(str, Enum):
    """Status of a threat."""
    IDENTIFIED = "Identified"
    IN_PROGRESS = "In Progress"
    MITIGATED = "Mitigated"
    ACCEPTED = "Accepted"


class MitigationStatus(str, Enum):
    """Status of a mitigation."""
    PROPOSED = "Proposed"
    IMPLEMENTED = "Implemented"
    VERIFIED = "Verified"


class RiskLevel(str, Enum):
    """OWASP risk level (Low/Medium/High)."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


# ─────────────────────────────────────────────────────────────────────────────
# OWASP Risk Rating
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class OwaspLikelihood:
    """OWASP likelihood factors (0-9 scale)."""
    # Threat Agent Factors
    skill_level: int = 5
    motive: int = 5
    opportunity: int = 5
    size: int = 5
    # Vulnerability Factors
    ease_of_discovery: int = 5
    ease_of_exploit: int = 5
    awareness: int = 5
    intrusion_detection: int = 5

    def __post_init__(self):
        """Clamp all values to 0-9."""
        for f in ['skill_level', 'motive', 'opportunity', 'size',
                  'ease_of_discovery', 'ease_of_exploit', 'awareness', 'intrusion_detection']:
            setattr(self, f, max(0, min(9, getattr(self, f))))

    @property
    def score(self) -> float:
        """Calculate average likelihood score."""
        values = [
            self.skill_level, self.motive, self.opportunity, self.size,
            self.ease_of_discovery, self.ease_of_exploit, self.awareness, self.intrusion_detection
        ]
        return sum(values) / len(values)

    def to_dict(self) -> Dict[str, int]:
        return {
            "skill_level": self.skill_level,
            "motive": self.motive,
            "opportunity": self.opportunity,
            "size": self.size,
            "ease_of_discovery": self.ease_of_discovery,
            "ease_of_exploit": self.ease_of_exploit,
            "awareness": self.awareness,
            "intrusion_detection": self.intrusion_detection,
        }

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "OwaspLikelihood":
        if not data:
            return cls()
        return cls(
            skill_level=data.get("skill_level", data.get("skillLevel", 5)),
            motive=data.get("motive", 5),
            opportunity=data.get("opportunity", 5),
            size=data.get("size", 5),
            ease_of_discovery=data.get("ease_of_discovery", data.get("easeOfDiscovery", 5)),
            ease_of_exploit=data.get("ease_of_exploit", data.get("easeOfExploit", 5)),
            awareness=data.get("awareness", 5),
            intrusion_detection=data.get("intrusion_detection", data.get("intrusionDetection", 5)),
        )


@dataclass
class OwaspImpact:
    """OWASP impact factors (0-9 scale)."""
    # Technical Impact
    confidentiality: int = 5
    integrity: int = 5
    availability: int = 5
    accountability: int = 5

    def __post_init__(self):
        """Clamp all values to 0-9."""
        for f in ['confidentiality', 'integrity', 'availability', 'accountability']:
            setattr(self, f, max(0, min(9, getattr(self, f))))

    @property
    def score(self) -> float:
        """Calculate average impact score."""
        values = [self.confidentiality, self.integrity, self.availability, self.accountability]
        return sum(values) / len(values)

    def to_dict(self) -> Dict[str, int]:
        return {
            "confidentiality": self.confidentiality,
            "integrity": self.integrity,
            "availability": self.availability,
            "accountability": self.accountability,
        }

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "OwaspImpact":
        if not data:
            return cls()
        return cls(
            confidentiality=data.get("confidentiality", 5),
            integrity=data.get("integrity", 5),
            availability=data.get("availability", 5),
            accountability=data.get("accountability", 5),
        )


# OWASP Risk Matrix
RISK_MATRIX: Dict[RiskLevel, Dict[RiskLevel, Severity]] = {
    RiskLevel.HIGH: {
        RiskLevel.LOW: Severity.MEDIUM,
        RiskLevel.MEDIUM: Severity.HIGH,
        RiskLevel.HIGH: Severity.CRITICAL,
    },
    RiskLevel.MEDIUM: {
        RiskLevel.LOW: Severity.LOW,
        RiskLevel.MEDIUM: Severity.MEDIUM,
        RiskLevel.HIGH: Severity.HIGH,
    },
    RiskLevel.LOW: {
        RiskLevel.LOW: Severity.NOTE,
        RiskLevel.MEDIUM: Severity.LOW,
        RiskLevel.HIGH: Severity.MEDIUM,
    },
}


def get_risk_level(score: float) -> RiskLevel:
    """Convert score (0-9) to risk level."""
    if score < 3:
        return RiskLevel.LOW
    if score < 6:
        return RiskLevel.MEDIUM
    return RiskLevel.HIGH


def calculate_risk_severity(impact_level: RiskLevel, likelihood_level: RiskLevel) -> Severity:
    """Calculate risk severity from impact and likelihood levels."""
    return RISK_MATRIX[impact_level][likelihood_level]


@dataclass
class OwaspRiskRating:
    """Complete OWASP risk rating."""
    likelihood: OwaspLikelihood
    impact: OwaspImpact
    likelihood_score: float = 0.0
    impact_score: float = 0.0
    likelihood_level: RiskLevel = RiskLevel.MEDIUM
    impact_level: RiskLevel = RiskLevel.MEDIUM
    risk_severity: Severity = Severity.MEDIUM
    overall_risk_score: float = 0.0

    def __post_init__(self):
        """Calculate derived fields."""
        self.likelihood_score = round(self.likelihood.score, 2)
        self.impact_score = round(self.impact.score, 2)
        self.likelihood_level = get_risk_level(self.likelihood_score)
        self.impact_level = get_risk_level(self.impact_score)
        self.risk_severity = calculate_risk_severity(self.impact_level, self.likelihood_level)
        self.overall_risk_score = round(self.likelihood_score * self.impact_score, 2)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "likelihood": self.likelihood.to_dict(),
            "impact": self.impact.to_dict(),
            "likelihood_score": self.likelihood_score,
            "impact_score": self.impact_score,
            "likelihood_level": self.likelihood_level.value,
            "impact_level": self.impact_level.value,
            "risk_severity": self.risk_severity.value,
            "overall_risk_score": self.overall_risk_score,
        }

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "OwaspRiskRating":
        if not data:
            return cls(
                likelihood=OwaspLikelihood(),
                impact=OwaspImpact(),
            )
        return cls(
            likelihood=OwaspLikelihood.from_dict(data.get("likelihood")),
            impact=OwaspImpact.from_dict(data.get("impact")),
        )

    @classmethod
    def calculate(
        cls,
        likelihood: Optional[Dict[str, Any]] = None,
        impact: Optional[Dict[str, Any]] = None,
    ) -> "OwaspRiskRating":
        """Calculate risk rating from raw likelihood and impact dicts."""
        return cls(
            likelihood=OwaspLikelihood.from_dict(likelihood),
            impact=OwaspImpact.from_dict(impact),
        )


# ─────────────────────────────────────────────────────────────────────────────
# Threat Model Types
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ThreatStatement:
    """AWS Threat Grammar: [Actor] can [Action] against [Asset] leading to [Impact]."""
    actor: str
    action: str
    asset: str
    impact: str

    def to_dict(self) -> Dict[str, str]:
        return {
            "actor": self.actor,
            "action": self.action,
            "asset": self.asset,
            "impact": self.impact,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ThreatStatement":
        return cls(
            actor=data.get("actor", ""),
            action=data.get("action", ""),
            asset=data.get("asset", ""),
            impact=data.get("impact", ""),
        )

    def __str__(self) -> str:
        return f"A {self.actor} can {self.action} against {self.asset}, leading to {self.impact}."


@dataclass
class CodeSnippet:
    """Code location and fix for a mitigation."""
    file: str
    line: int
    original: str = ""
    fixed: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file": self.file,
            "line": self.line,
            "original": self.original,
            "fixed": self.fixed,
        }

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> Optional["CodeSnippet"]:
        if not data:
            return None
        return cls(
            file=data.get("file", ""),
            line=data.get("line", 0),
            original=data.get("original", ""),
            fixed=data.get("fixed", ""),
        )


@dataclass
class JiraTicket:
    """Jira ticket reference for a mitigation."""
    key: str
    summary: str
    status: str = "To Do"

    def to_dict(self) -> Dict[str, str]:
        return {
            "key": self.key,
            "summary": self.summary,
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> Optional["JiraTicket"]:
        if not data:
            return None
        return cls(
            key=data.get("key", ""),
            summary=data.get("summary", ""),
            status=data.get("status", "To Do"),
        )


@dataclass
class Mitigation:
    """A mitigation for a threat."""
    id: str
    description: str
    status: MitigationStatus = MitigationStatus.PROPOSED
    code_snippet: Optional[CodeSnippet] = None
    jira_ticket: Optional[JiraTicket] = None

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "id": self.id,
            "description": self.description,
            "status": self.status.value,
        }
        if self.code_snippet:
            result["codeSnippet"] = self.code_snippet.to_dict()
        if self.jira_ticket:
            result["jiraTicket"] = self.jira_ticket.to_dict()
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Mitigation":
        return cls(
            id=data.get("id", ""),
            description=data.get("description", ""),
            status=MitigationStatus(data.get("status", "Proposed")),
            code_snippet=CodeSnippet.from_dict(data.get("codeSnippet")),
            jira_ticket=JiraTicket.from_dict(data.get("jiraTicket")),
        )


@dataclass
class Threat:
    """A threat in the threat model."""
    id: str
    title: str
    stride: StrideCategory
    severity: Severity
    status: ThreatStatus = ThreatStatus.IDENTIFIED
    threat_statement: Optional[ThreatStatement] = None
    trust_boundary: str = ""
    assumptions: List[str] = field(default_factory=list)
    mitigations: List[Mitigation] = field(default_factory=list)
    related_cve: Optional[str] = None
    owasp_risk: Optional[OwaspRiskRating] = None
    impacted_assets: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "id": self.id,
            "title": self.title,
            "stride": self.stride.value,
            "severity": self.severity.value,
            "status": self.status.value,
            "trustBoundary": self.trust_boundary,
            "assumptions": self.assumptions,
            "mitigations": [m.to_dict() for m in self.mitigations],
            "impactedAssets": self.impacted_assets,
        }
        if self.threat_statement:
            result["threatStatement"] = self.threat_statement.to_dict()
        if self.related_cve:
            result["relatedCVE"] = self.related_cve
        if self.owasp_risk:
            result["owaspRisk"] = self.owasp_risk.to_dict()
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Threat":
        return cls(
            id=data.get("id", ""),
            title=data.get("title", ""),
            stride=StrideCategory(data.get("stride", "Tampering")),
            severity=Severity(data.get("severity", "Medium")),
            status=ThreatStatus(data.get("status", "Identified")),
            threat_statement=ThreatStatement.from_dict(data["threatStatement"]) if data.get("threatStatement") else None,
            trust_boundary=data.get("trustBoundary", ""),
            assumptions=data.get("assumptions", []),
            mitigations=[Mitigation.from_dict(m) for m in data.get("mitigations", [])],
            related_cve=data.get("relatedCVE"),
            owasp_risk=OwaspRiskRating.from_dict(data.get("owaspRisk")),
            impacted_assets=data.get("impactedAssets", []),
        )


@dataclass
class ThreatModelStats:
    """Statistics for a threat model session."""
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    mitigated: int = 0

    def to_dict(self) -> Dict[str, int]:
        return {
            "total": self.total,
            "critical": self.critical,
            "high": self.high,
            "medium": self.medium,
            "low": self.low,
            "mitigated": self.mitigated,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ThreatModelStats":
        return cls(
            total=data.get("total", 0),
            critical=data.get("critical", 0),
            high=data.get("high", 0),
            medium=data.get("medium", 0),
            low=data.get("low", 0),
            mitigated=data.get("mitigated", 0),
        )

    @classmethod
    def from_threats(cls, threats: List[Threat]) -> "ThreatModelStats":
        """Calculate stats from a list of threats."""
        return cls(
            total=len(threats),
            critical=sum(1 for t in threats if t.severity == Severity.CRITICAL),
            high=sum(1 for t in threats if t.severity == Severity.HIGH),
            medium=sum(1 for t in threats if t.severity == Severity.MEDIUM),
            low=sum(1 for t in threats if t.severity == Severity.LOW),
            mitigated=sum(1 for t in threats if t.status == ThreatStatus.MITIGATED),
        )


@dataclass
class ThreatModelSession:
    """A threat modeling session."""
    id: str
    name: str
    description: str = ""
    source: str = "github-repo"  # "design-doc" | "github-repo"
    source_ref: str = ""
    created_at: str = ""
    status: str = "Processing"  # "Processing" | "Review" | "Complete"
    threats: List[Threat] = field(default_factory=list)
    data_flow_diagram: str = ""  # Mermaid.js
    stats: Optional[ThreatModelStats] = None

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.utcnow().isoformat() + "Z"
        if not self.stats:
            self.stats = ThreatModelStats.from_threats(self.threats)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "source": self.source,
            "sourceRef": self.source_ref,
            "createdAt": self.created_at,
            "status": self.status,
            "threats": [t.to_dict() for t in self.threats],
            "dataFlowDiagram": self.data_flow_diagram,
            "stats": self.stats.to_dict() if self.stats else {},
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ThreatModelSession":
        return cls(
            id=data.get("id", ""),
            name=data.get("name", ""),
            description=data.get("description", ""),
            source=data.get("source", "github-repo"),
            source_ref=data.get("sourceRef", ""),
            created_at=data.get("createdAt", ""),
            status=data.get("status", "Processing"),
            threats=[Threat.from_dict(t) for t in data.get("threats", [])],
            data_flow_diagram=data.get("dataFlowDiagram", ""),
            stats=ThreatModelStats.from_dict(data["stats"]) if data.get("stats") else None,
        )
