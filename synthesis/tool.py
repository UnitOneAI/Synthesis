"""
Synthesis Threat Model Tool.

Implements the UnitoneController Tool interface for threat model generation.
This tool can be imported by UnitoneController as a dependency.
"""

import json
import os
import subprocess
import time
from pathlib import Path
from typing import List, Dict, Any, Optional

from synthesis.models import (
    Threat,
    ThreatModelSession,
    ThreatModelStats,
    Severity,
    StrideCategory,
    ThreatStatus,
    OwaspRiskRating,
)


# ─────────────────────────────────────────────────────────────────────────────
# Standalone data types (no unitone dependency for standalone use)
# ─────────────────────────────────────────────────────────────────────────────

class IssueLocation:
    """Location of an issue in code."""

    def __init__(
        self,
        file_path: str = "",
        line_start: Optional[int] = None,
        line_end: Optional[int] = None,
    ):
        self.file_path = file_path
        self.line_start = line_start
        self.line_end = line_end

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
        }


class Issue:
    """A finding/issue from a tool."""

    def __init__(
        self,
        id: str,
        tool_id: str,
        title: str,
        severity: str,
        category: str,
        description: str = "",
        location: Optional[IssueLocation] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.id = id
        self.tool_id = tool_id
        self.title = title
        self.severity = severity
        self.category = category
        self.description = description
        self.location = location or IssueLocation()
        self.metadata = metadata or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "tool_id": self.tool_id,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "description": self.description,
            "location": self.location.to_dict(),
            "metadata": self.metadata,
        }


class ToolOutput:
    """Output from a tool execution."""

    def __init__(
        self,
        tool_id: str,
        tool_version: str,
        issues: List[Issue],
        output_data: Dict[str, Any],
        summary: Optional[Dict[str, Any]] = None,
        execution_time_ms: int = 0,
        warnings: Optional[List[str]] = None,
        errors: Optional[List[str]] = None,
        renderer: Optional[str] = None,
    ):
        self.tool_id = tool_id
        self.tool_version = tool_version
        self.issues = issues
        self.output_data = output_data
        self.summary = summary or {}
        self.execution_time_ms = execution_time_ms
        self.warnings = warnings or []
        self.errors = errors or []
        self.renderer = renderer

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool_id": self.tool_id,
            "tool_version": self.tool_version,
            "issues": [i.to_dict() for i in self.issues],
            "output_data": self.output_data,
            "summary": self.summary,
            "execution_time_ms": self.execution_time_ms,
            "warnings": self.warnings,
            "errors": self.errors,
            "renderer": self.renderer,
        }


class ToolContext:
    """Context for tool execution."""

    def __init__(
        self,
        repo_path: str = "",
        config: Optional[Dict[str, Any]] = None,
        credentials: Optional[Dict[str, str]] = None,
    ):
        self.repo_path = repo_path
        self.config = config or {}
        self.credentials = credentials or {}

    def has_credential(self, key: str) -> bool:
        return key in self.credentials and self.credentials[key]


# ─────────────────────────────────────────────────────────────────────────────
# Tool Implementation
# ─────────────────────────────────────────────────────────────────────────────

class SynthesisThreatModelTool:
    """
    Threat Model generation tool using Synthesis.

    This tool implements the UnitoneController Tool interface pattern.
    It can be used standalone or imported by UnitoneController.

    Usage:
        # Standalone
        tool = SynthesisThreatModelTool()
        ctx = ToolContext(repo_path="/path/to/repo")
        output = tool.run(ctx)

        # With UnitoneController
        from synthesis import SynthesisThreatModelTool
        registry.register(SynthesisThreatModelTool())
    """

    VERSION = "1.0.0"

    @property
    def tool_id(self) -> str:
        return "synthesis"

    @property
    def version(self) -> str:
        return self.VERSION

    @property
    def display_name(self) -> str:
        return "Synthesis Threat Model"

    @property
    def description(self) -> str:
        return "AI-powered threat modeling using STRIDE methodology and OWASP risk rating"

    @property
    def category(self) -> str:
        return "threat-model"

    @property
    def renderer(self) -> Optional[str]:
        return "shared:threat-model"

    @property
    def required_credentials(self) -> List[str]:
        return []  # Uses local LLM or configured API key

    @property
    def optional_credentials(self) -> List[str]:
        return ["anthropic_api_key", "openai_api_key"]

    @property
    def tags(self) -> List[str]:
        return ["security", "threat-model", "stride", "owasp"]

    def validate_context(self, context: ToolContext) -> List[str]:
        """Validate execution context."""
        errors = []
        if not context.repo_path:
            errors.append("repo_path is required")
        elif not Path(context.repo_path).exists():
            errors.append(f"repo_path does not exist: {context.repo_path}")
        return errors

    def run(self, context: ToolContext) -> ToolOutput:
        """
        Execute threat model generation.

        Calls the TypeScript CLI and parses JSON output.

        Args:
            context: Tool execution context with repo_path

        Returns:
            ToolOutput with threats as Issues
        """
        start_time = time.time()
        warnings: List[str] = []
        errors: List[str] = []

        # Validate context
        validation_errors = self.validate_context(context)
        if validation_errors:
            return ToolOutput(
                tool_id=self.tool_id,
                tool_version=self.version,
                issues=[],
                output_data={},
                errors=validation_errors,
            )

        # Get framework from config
        framework = context.config.get("framework", "STRIDE")

        # Call TypeScript CLI
        try:
            cli_output = self._call_cli(context.repo_path, framework)
        except Exception as e:
            return ToolOutput(
                tool_id=self.tool_id,
                tool_version=self.version,
                issues=[],
                output_data={},
                errors=[f"CLI execution failed: {str(e)}"],
            )

        # Parse CLI output
        try:
            issues = self._parse_cli_output(cli_output)
        except Exception as e:
            return ToolOutput(
                tool_id=self.tool_id,
                tool_version=self.version,
                issues=[],
                output_data={"raw_output": cli_output},
                errors=[f"Failed to parse CLI output: {str(e)}"],
            )

        # Build summary
        summary = self._build_summary(issues)

        execution_time = int((time.time() - start_time) * 1000)

        return ToolOutput(
            tool_id=self.tool_id,
            tool_version=self.version,
            issues=issues,
            output_data={
                "analysis": cli_output.get("output_data", {}).get("analysis", {}),
                "framework": framework,
            },
            summary=summary,
            execution_time_ms=execution_time,
            warnings=warnings,
            errors=errors,
            renderer=self.renderer,
        )

    def _call_cli(self, repo_path: str, framework: str) -> Dict[str, Any]:
        """Call the TypeScript CLI and return parsed JSON."""
        # Find CLI script relative to this file
        synthesis_root = Path(__file__).parent.parent
        cli_script = synthesis_root / "cli" / "scan.ts"

        if not cli_script.exists():
            raise FileNotFoundError(f"CLI script not found: {cli_script}")

        # Run CLI
        cmd = [
            "npx", "ts-node",
            str(cli_script),
            repo_path,
            "--framework", framework,
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=str(synthesis_root),
            timeout=300,  # 5 minute timeout
        )

        if result.returncode != 0:
            raise RuntimeError(f"CLI failed: {result.stderr}")

        # Parse JSON from stdout
        return json.loads(result.stdout)

    def _parse_cli_output(self, cli_output: Dict[str, Any]) -> List[Issue]:
        """Convert CLI output to Issue objects."""
        issues = []

        for issue_data in cli_output.get("issues", []):
            location = IssueLocation(
                file_path=issue_data.get("location", {}).get("file_path", ""),
                line_start=issue_data.get("location", {}).get("line_start"),
                line_end=issue_data.get("location", {}).get("line_end"),
            )

            issue = Issue(
                id=issue_data.get("id", ""),
                tool_id=self.tool_id,
                title=issue_data.get("title", ""),
                severity=issue_data.get("severity", "medium"),
                category=issue_data.get("category", "threat-model"),
                description=issue_data.get("description", ""),
                location=location,
                metadata=issue_data.get("metadata", {}),
            )
            issues.append(issue)

        return issues

    def _build_summary(self, issues: List[Issue]) -> Dict[str, Any]:
        """Build summary statistics."""
        by_severity: Dict[str, int] = {}
        by_stride: Dict[str, int] = {}

        for issue in issues:
            # Count by severity
            sev = issue.severity
            by_severity[sev] = by_severity.get(sev, 0) + 1

            # Count by STRIDE category from metadata
            stride = issue.metadata.get("stride_category", "Unknown")
            by_stride[stride] = by_stride.get(stride, 0) + 1

        return {
            "total": len(issues),
            "by_severity": by_severity,
            "by_stride_category": by_stride,
        }

    def get_config_schema(self) -> Dict[str, Any]:
        """Return JSON Schema for configuration."""
        return {
            "type": "object",
            "properties": {
                "framework": {
                    "type": "string",
                    "enum": ["STRIDE", "OWASP Top 10"],
                    "default": "STRIDE",
                    "description": "Threat modeling framework to use",
                },
            },
        }

    def get_default_config(self) -> Dict[str, Any]:
        """Return default configuration."""
        return {
            "framework": "STRIDE",
        }


# ─────────────────────────────────────────────────────────────────────────────
# Standalone Entry Point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    """CLI entry point for standalone execution."""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m synthesis.tool <repo-path> [--framework STRIDE|OWASP]")
        sys.exit(1)

    repo_path = sys.argv[1]
    framework = "STRIDE"

    if "--framework" in sys.argv:
        idx = sys.argv.index("--framework")
        if idx + 1 < len(sys.argv):
            framework = sys.argv[idx + 1]

    tool = SynthesisThreatModelTool()
    context = ToolContext(repo_path=repo_path, config={"framework": framework})
    output = tool.run(context)

    print(json.dumps(output.to_dict(), indent=2))


if __name__ == "__main__":
    main()
