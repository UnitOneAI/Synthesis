# Synthesis Python Package

## Overview

This Python package provides UnitoneController integration for the Synthesis threat modeling tool. It implements the Tool interface pattern, allowing Synthesis to be used as a dependency in UnitoneController.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    UnitoneController                             │
│                                                                  │
│  registry.register(SynthesisThreatModelTool())                   │
│  result = unitone.run("synthesis")                               │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    synthesis/tool.py                             │
│                    SynthesisThreatModelTool                      │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │ run(context: ToolContext) -> ToolOutput                 │    │
│  │                                                         │    │
│  │  1. Validate context (repo_path exists)                 │    │
│  │  2. Call TypeScript CLI via subprocess                  │    │
│  │  3. Parse JSON output to Issue objects                  │    │
│  │  4. Return ToolOutput with issues and summary           │    │
│  └─────────────────────────────────────────────────────────┘    │
└───────────────────────────┬─────────────────────────────────────┘
                            │ subprocess: npx ts-node cli/scan.ts
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    cli/scan.ts                                   │
│                    TypeScript CLI                                │
│                                                                  │
│  1. analyzeRepo() - Detect components, data flows               │
│  2. generateThreats() - LLM-powered STRIDE analysis             │
│  3. Convert to UnitoneController Issue format                    │
│  4. Output JSON to stdout                                        │
└─────────────────────────────────────────────────────────────────┘
```

## Package Structure

```
synthesis/
├── __init__.py           # Package exports
├── models.py             # Data models
│   ├── StrideCategory    # STRIDE threat categories (enum)
│   ├── Severity          # Critical/High/Medium/Low/Note
│   ├── ThreatStatus      # Identified/In Progress/Mitigated/Accepted
│   ├── OwaspLikelihood   # 8 likelihood factors (0-9)
│   ├── OwaspImpact       # 4 impact factors (0-9)
│   ├── OwaspRiskRating   # Calculated risk with matrix lookup
│   ├── ThreatStatement   # AWS Threat Grammar format
│   ├── Mitigation        # Fix with code snippet and Jira link
│   ├── Threat            # Full threat with mitigations
│   └── ThreatModelSession # Session with threats and stats
│
├── tool.py               # Tool implementation
│   ├── SynthesisThreatModelTool  # Main tool class
│   ├── ToolContext       # Execution context
│   ├── ToolOutput        # Execution result
│   └── Issue             # Finding/issue
│
└── CLAUDE.md             # This file
```

## Data Flow

### Input
```python
context = ToolContext(
    repo_path="/path/to/repo",
    config={"framework": "STRIDE"},  # or "OWASP Top 10"
)
```

### Output
```python
ToolOutput(
    tool_id="synthesis",
    tool_version="1.0.0",
    issues=[
        Issue(
            id="uuid",
            title="[Spoofing] Cross-Tenant API Access",
            severity="critical",
            category="threat-model",
            description="Threat statement...",
            location=IssueLocation(file_path="api/auth.py", line_start=42),
            metadata={
                "stride_category": "Spoofing",
                "threat_source": "authenticated user",
                "impacted_assets": ["API Gateway", "User DB"],
                "owasp_likelihood": {...},
                "owasp_impact": {...},
                "mitigations": [...],
            }
        ),
        ...
    ],
    summary={
        "total": 8,
        "by_severity": {"critical": 2, "high": 3, "medium": 2, "low": 1},
        "by_stride_category": {"Spoofing": 2, "Tampering": 2, ...},
    },
    output_data={
        "analysis": {"languages": ["python"], "frameworks": ["fastapi"]},
        "framework": "STRIDE",
    }
)
```

## OWASP Risk Rating

The package implements the full OWASP Risk Rating Methodology:

### Likelihood Factors (0-9 each)
| Factor | Description |
|--------|-------------|
| skill_level | Technical skill required |
| motive | Attacker motivation |
| opportunity | Access/opportunity |
| size | Threat agent population |
| ease_of_discovery | How easy to find vulnerability |
| ease_of_exploit | How easy to exploit |
| awareness | Public knowledge level |
| intrusion_detection | Detection likelihood |

### Impact Factors (0-9 each)
| Factor | Description |
|--------|-------------|
| confidentiality | Data disclosure impact |
| integrity | Data modification impact |
| availability | Service disruption impact |
| accountability | Audit/traceability impact |

### Risk Matrix
```
             │  LOW Likelihood  │  MED Likelihood  │  HIGH Likelihood
─────────────┼──────────────────┼──────────────────┼──────────────────
HIGH Impact  │     Medium       │      High        │     Critical
MED Impact   │      Low         │     Medium       │      High
LOW Impact   │      Note        │      Low         │     Medium
```

## Design Principles

### 1. Tool Interface Compliance
The `SynthesisThreatModelTool` implements the UnitoneController Tool pattern:
- `tool_id` property returns "synthesis"
- `run(context)` returns `ToolOutput` with issues
- Uses subprocess to call TypeScript CLI (no HTTP dependency)

### 2. Standalone Capability
The package works both:
- **With UnitoneController**: `from synthesis import SynthesisThreatModelTool`
- **Standalone**: `python -m synthesis.tool /path/to/repo`

### 3. Data Model Parity
Python models in `models.py` match TypeScript types in `lib/threat-data.ts`:
- Same field names (converted to snake_case)
- Same enums and values
- Bidirectional JSON serialization

### 4. No HTTP Dependency
The tool calls the TypeScript CLI via subprocess, not HTTP:
```python
# CORRECT: subprocess call
subprocess.run(["npx", "ts-node", "cli/scan.ts", repo_path])

# WRONG: HTTP call (violates design)
requests.post("http://synthesis-service/analyze")
```

## Configuration

### Config Schema
```json
{
  "type": "object",
  "properties": {
    "framework": {
      "type": "string",
      "enum": ["STRIDE", "OWASP Top 10"],
      "default": "STRIDE"
    }
  }
}
```

### Environment Variables
| Variable | Required | Description |
|----------|----------|-------------|
| `ANTHROPIC_API_KEY` | No | For LLM analysis |
| `GOOGLE_GEMINI_API_KEY` | No | Alternative LLM |

## Testing

```bash
# Run tests
pytest tests/

# Run with coverage
pytest --cov=synthesis tests/
```

## Invariants

| ID | Rule |
|----|------|
| SYN-001 | Tool must return ToolOutput, never raise unhandled exceptions |
| SYN-002 | Issues must have valid severity (critical/high/medium/low/info) |
| SYN-003 | OWASP scores must be clamped to 0-9 range |
| SYN-004 | CLI must output valid JSON to stdout |
| SYN-005 | Python models must serialize/deserialize to same TypeScript format |

## STOP Conditions

```
STOP: Never make HTTP calls to a Synthesis service - use subprocess
STOP: Never duplicate threat generation logic in Python - call TypeScript
STOP: Never change Issue format without updating UnitoneController
STOP: Never add required credentials - LLM keys are optional (demo mode)
```
