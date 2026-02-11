// Jira REST API v3 client

export interface JiraConfig {
  url: string;
  email: string;
  apiToken: string;
  projectKey: string;
}

export interface JiraIssueInput {
  summary: string;
  description: string;
  priority: "Highest" | "High" | "Medium" | "Low" | "Lowest";
  labels?: string[];
}

export interface JiraIssueResult {
  key: string;
  id: string;
  self: string;
}

function getAuthHeader(email: string, apiToken: string): string {
  const credentials = Buffer.from(`${email}:${apiToken}`).toString("base64");
  return `Basic ${credentials}`;
}

export async function testJiraConnection(config: JiraConfig): Promise<boolean> {
  try {
    const res = await fetch(`${config.url}/rest/api/3/myself`, {
      headers: {
        Authorization: getAuthHeader(config.email, config.apiToken),
        Accept: "application/json",
      },
    });
    return res.ok;
  } catch {
    return false;
  }
}

export async function createJiraIssue(
  config: JiraConfig,
  issue: JiraIssueInput
): Promise<JiraIssueResult> {
  const priorityMap: Record<string, string> = {
    Highest: "1",
    High: "2",
    Medium: "3",
    Low: "4",
    Lowest: "5",
  };

  const body = {
    fields: {
      project: { key: config.projectKey },
      summary: issue.summary,
      description: {
        type: "doc",
        version: 1,
        content: [
          {
            type: "paragraph",
            content: [{ type: "text", text: issue.description }],
          },
        ],
      },
      issuetype: { name: "Task" },
      priority: { id: priorityMap[issue.priority] || "3" },
      labels: issue.labels || ["security", "threat-model"],
    },
  };

  const res = await fetch(`${config.url}/rest/api/3/issue`, {
    method: "POST",
    headers: {
      Authorization: getAuthHeader(config.email, config.apiToken),
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(`Jira API error (${res.status}): ${errorText}`);
  }

  return res.json();
}

export function mapSeverityToPriority(
  severity: string
): JiraIssueInput["priority"] {
  switch (severity) {
    case "Critical":
      return "Highest";
    case "High":
      return "High";
    case "Medium":
      return "Medium";
    case "Low":
      return "Low";
    default:
      return "Medium";
  }
}
