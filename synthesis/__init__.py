"""
Synthesis - AI-powered threat modeling tool.

This package provides:
- SynthesisThreatModelTool: Tool implementation for UnitoneController integration
- Data models: Threat, ThreatModelSession, OWASP risk rating types
- Standalone CLI: `python -m synthesis.tool <repo-path>`

Usage with UnitoneController:

    from synthesis import SynthesisThreatModelTool

    # Register with UnitoneController
    tool = SynthesisThreatModelTool()
    registry.register(tool)

    # Or run directly
    ctx = ToolContext(repo_path="/path/to/repo")
    output = tool.run(ctx)

Standalone usage:

    python -m synthesis.tool /path/to/repo --framework STRIDE
"""

from synthesis.models import (
    # Enums
    StrideCategory,
    Severity,
    ThreatStatus,
    MitigationStatus,
    RiskLevel,
    # OWASP Risk Rating
    OwaspLikelihood,
    OwaspImpact,
    OwaspRiskRating,
    RISK_MATRIX,
    get_risk_level,
    calculate_risk_severity,
    # Threat Model Types
    ThreatStatement,
    CodeSnippet,
    JiraTicket,
    Mitigation,
    Threat,
    ThreatModelStats,
    ThreatModelSession,
)

from synthesis.tool import (
    SynthesisThreatModelTool,
    ToolContext,
    ToolOutput,
    Issue,
    IssueLocation,
)

__version__ = "1.0.0"

__all__ = [
    # Main tool
    "SynthesisThreatModelTool",
    # Tool interface types
    "ToolContext",
    "ToolOutput",
    "Issue",
    "IssueLocation",
    # Enums
    "StrideCategory",
    "Severity",
    "ThreatStatus",
    "MitigationStatus",
    "RiskLevel",
    # OWASP
    "OwaspLikelihood",
    "OwaspImpact",
    "OwaspRiskRating",
    "RISK_MATRIX",
    "get_risk_level",
    "calculate_risk_severity",
    # Threat Model Types
    "ThreatStatement",
    "CodeSnippet",
    "JiraTicket",
    "Mitigation",
    "Threat",
    "ThreatModelStats",
    "ThreatModelSession",
]
