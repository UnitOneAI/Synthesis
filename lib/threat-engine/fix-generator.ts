import Anthropic from "@anthropic-ai/sdk";
import fs from "fs";
import path from "path";

// ── Types ──

export interface GeneratedFix {
  description: string;
  codeFile: string;
  codeLine: number;
  codeOriginal: string;
  codeFixed: string;
}

export interface ProseMitigation {
  description: string;
  recommendation: string;
  references: string[];
}

// ── Code Fix Generator (for repo sources) ──

export async function generateCodeFix(
  threat: {
    title: string;
    strideCategory: string;
    severity: string;
    threatSource: string;
    threatAction: string;
    threatImpact: string;
    trustBoundary: string;
  },
  vulnerableFile: {
    path: string;
    content: string;
    line?: number;
  }
): Promise<GeneratedFix> {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    throw new Error("ANTHROPIC_API_KEY environment variable is required");
  }

  const client = new Anthropic({ apiKey });

  const systemPrompt = `You are a Principal Software Development Engineer fixing security vulnerabilities.
Given a threat description and the vulnerable source code, generate a minimal, correct code fix.

Rules:
1. Only modify what is necessary to fix the security issue.
2. Preserve the existing code style and patterns.
3. The fix must be syntactically correct for the language.
4. Include necessary imports/requires if adding new dependencies.
5. Do NOT add comments explaining the fix — the code should be self-evident.
6. Return the EXACT original lines that need changing, and the fixed replacement lines.

Output format (JSON only, no markdown):
{
  "codeOriginal": "the exact original lines from the file that are vulnerable",
  "codeFixed": "the replacement lines that fix the vulnerability",
  "description": "one-sentence description of the fix",
  "startLine": <line number where the original code starts>
}`;

  // Limit file content to relevant section around the vulnerable line
  const fileLines = vulnerableFile.content.split("\n");
  const targetLine = vulnerableFile.line || 1;
  const contextRadius = 30;
  const startLine = Math.max(0, targetLine - contextRadius);
  const endLine = Math.min(fileLines.length, targetLine + contextRadius);
  const relevantContent = fileLines
    .slice(startLine, endLine)
    .map((line, i) => `${startLine + i + 1}: ${line}`)
    .join("\n");

  const userPrompt = `## Threat
- Title: ${threat.title}
- STRIDE Category: ${threat.strideCategory}
- Severity: ${threat.severity}
- Threat Source: ${threat.threatSource}
- Threat Action: ${threat.threatAction}
- Threat Impact: ${threat.threatImpact}
- Trust Boundary: ${threat.trustBoundary}

## Vulnerable File: ${vulnerableFile.path}
## Vulnerable Area (around line ${targetLine}):
\`\`\`
${relevantContent}
\`\`\`

Generate the minimal code fix. Output ONLY valid JSON.`;

  const message = await client.messages.create({
    model: "claude-sonnet-4-5-20250929",
    max_tokens: 4096,
    system: systemPrompt,
    messages: [{ role: "user", content: userPrompt }],
  });

  const textBlock = message.content.find((b) => b.type === "text");
  if (!textBlock || textBlock.type !== "text") {
    throw new Error("No text response from LLM");
  }

  const parsed = parseFixResponse(textBlock.text);

  return {
    description: parsed.description,
    codeFile: vulnerableFile.path,
    codeLine: parsed.startLine || targetLine,
    codeOriginal: parsed.codeOriginal,
    codeFixed: parsed.codeFixed,
  };
}

function parseFixResponse(text: string): {
  codeOriginal: string;
  codeFixed: string;
  description: string;
  startLine: number;
} {
  let jsonStr = text.trim();

  // Extract JSON from markdown blocks if present
  const jsonMatch = jsonStr.match(/```(?:json)?\s*([\s\S]*?)```/);
  if (jsonMatch) {
    jsonStr = jsonMatch[1].trim();
  }

  // Find JSON object
  const objStart = jsonStr.indexOf("{");
  const objEnd = jsonStr.lastIndexOf("}");
  if (objStart !== -1 && objEnd !== -1) {
    jsonStr = jsonStr.substring(objStart, objEnd + 1);
  }

  try {
    const parsed = JSON.parse(jsonStr);
    return {
      codeOriginal: String(parsed.codeOriginal || ""),
      codeFixed: String(parsed.codeFixed || ""),
      description: String(parsed.description || "Security fix applied"),
      startLine: typeof parsed.startLine === "number" ? parsed.startLine : 1,
    };
  } catch (e) {
    throw new Error(`Failed to parse fix response: ${e}`);
  }
}

// ── Prose Mitigation Generator (for doc sources) ──

export async function generateProseMitigation(
  threat: {
    title: string;
    strideCategory: string;
    severity: string;
    threatSource: string;
    threatAction: string;
    threatImpact: string;
  }
): Promise<ProseMitigation> {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    throw new Error("ANTHROPIC_API_KEY environment variable is required");
  }

  const client = new Anthropic({ apiKey });

  const message = await client.messages.create({
    model: "claude-sonnet-4-5-20250929",
    max_tokens: 2048,
    system: `You are a Principal Security Engineer providing mitigation guidance.
Given a threat, provide a clear, actionable mitigation recommendation.

Output format (JSON only):
{
  "description": "brief summary of the mitigation",
  "recommendation": "detailed step-by-step mitigation guidance (2-4 paragraphs)",
  "references": ["relevant security standard or best practice references"]
}`,
    messages: [
      {
        role: "user",
        content: `Threat: ${threat.title}
STRIDE: ${threat.strideCategory}
Severity: ${threat.severity}
Threat Source: ${threat.threatSource}
Action: ${threat.threatAction}
Impact: ${threat.threatImpact}

Provide a mitigation recommendation. Output ONLY valid JSON.`,
      },
    ],
  });

  const textBlock = message.content.find((b) => b.type === "text");
  if (!textBlock || textBlock.type !== "text") {
    throw new Error("No text response from LLM");
  }

  let jsonStr = textBlock.text.trim();
  const jsonMatch = jsonStr.match(/```(?:json)?\s*([\s\S]*?)```/);
  if (jsonMatch) jsonStr = jsonMatch[1].trim();

  const objStart = jsonStr.indexOf("{");
  const objEnd = jsonStr.lastIndexOf("}");
  if (objStart !== -1 && objEnd !== -1) {
    jsonStr = jsonStr.substring(objStart, objEnd + 1);
  }

  try {
    const parsed = JSON.parse(jsonStr);
    return {
      description: String(parsed.description || ""),
      recommendation: String(parsed.recommendation || ""),
      references: Array.isArray(parsed.references)
        ? parsed.references.map(String)
        : [],
    };
  } catch {
    return {
      description: `Mitigate ${threat.title}`,
      recommendation: `Address the ${threat.strideCategory} threat by implementing appropriate security controls.`,
      references: ["OWASP Top 10", "NIST SP 800-53"],
    };
  }
}

// ── Read file from cloned repo ──

export function readRepoFile(
  repoDir: string,
  filePath: string
): { content: string; exists: boolean } {
  try {
    const fullPath = path.join(repoDir, filePath);
    const content = fs.readFileSync(fullPath, "utf-8");
    return { content, exists: true };
  } catch {
    return { content: "", exists: false };
  }
}
