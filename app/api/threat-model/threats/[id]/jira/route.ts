import { NextRequest, NextResponse } from "next/server";
import { getThreat, listMitigations, updateMitigation, getSettingValue } from "@/lib/db";
import {
  createJiraIssue,
  mapSeverityToPriority,
  type JiraConfig,
} from "@/lib/jira-client";

// POST /api/threat-model/threats/[id]/jira — Create Jira ticket for threat
export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;

    // Get Jira config from settings
    const jiraUrl = getSettingValue("jira_url");
    const jiraEmail = getSettingValue("jira_email");
    const jiraToken = getSettingValue("jira_token");
    const jiraProjectKey = getSettingValue("jira_project_key");

    if (!jiraUrl || !jiraEmail || !jiraToken || !jiraProjectKey) {
      return NextResponse.json(
        { error: "Jira is not configured. Go to Settings > Integrations to set up Jira." },
        { status: 400 }
      );
    }

    const config: JiraConfig = {
      url: jiraUrl,
      email: jiraEmail,
      apiToken: jiraToken,
      projectKey: jiraProjectKey,
    };

    // Get threat details
    const threat = getThreat(id);
    if (!threat) {
      return NextResponse.json({ error: "Threat not found" }, { status: 404 });
    }

    const mitigations = listMitigations(id);

    // Build Jira issue
    const mitigationText = mitigations.length > 0
      ? mitigations.map((m, i) => `${i + 1}. ${m.description}`).join("\n")
      : "No mitigations defined yet.";

    const description = [
      `Threat ID: ${threat.id}`,
      `STRIDE Category: ${threat.stride_category}`,
      `Severity: ${threat.severity}`,
      `Trust Boundary: ${threat.trust_boundary}`,
      "",
      "Threat Statement:",
      `${threat.threat_source} ${threat.prerequisites ? `with ${threat.prerequisites} ` : ""}${threat.threat_action}, which leads to ${threat.threat_impact}.`,
      "",
      "Mitigations:",
      mitigationText,
    ].join("\n");

    const summary = `[${threat.id}] ${threat.title}`;
    const priority = mapSeverityToPriority(threat.severity);

    const result = await createJiraIssue(config, {
      summary,
      description,
      priority,
      labels: ["security", "threat-model", threat.stride_category.toLowerCase().replace(/\s+/g, "-")],
    });

    // Update the first mitigation with jira info (or all if body specifies)
    const body = await request.json().catch(() => ({}));
    const mitigationId = body.mitigationId || (mitigations.length > 0 ? mitigations[0].id : null);

    if (mitigationId) {
      updateMitigation(mitigationId, {
        jiraKey: result.key,
        jiraSummary: summary,
        jiraStatus: "To Do",
      });
    }

    return NextResponse.json({
      jiraKey: result.key,
      jiraId: result.id,
      jiraUrl: `${jiraUrl}/browse/${result.key}`,
      summary,
    });
  } catch (error) {
    console.error("Failed to create Jira ticket:", error);
    const message = error instanceof Error ? error.message : "Unknown error";
    return NextResponse.json(
      { error: `Failed to create Jira ticket: ${message}` },
      { status: 500 }
    );
  }
}
