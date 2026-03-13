/**
 * @synthesis/core — Diff and file analysis
 *
 * Parses unified diffs, extracts architectural components from code,
 * classifies trust boundaries, and identifies entry points and data flows.
 *
 * SECURITY:
 * - All file paths are validated and sanitized (no path traversal).
 * - Diff size is limited to prevent denial-of-service.
 * - Component names are sanitized to prevent downstream injection.
 */

import {
  type Component,
  type DataFlow,
  type FileChange,
  FileChangeSchema,
  ComponentSchema,
  DataFlowSchema,
} from "./types.js";
import type { Intent } from "./intent.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Maximum diff size in characters (1 MB) to prevent DoS. */
const MAX_DIFF_SIZE = 1_000_000;

/** Maximum number of files to process in a single batch. */
const MAX_FILES = 500;

// ---------------------------------------------------------------------------
// Path validation
// ---------------------------------------------------------------------------

/**
 * Validate and sanitize a file path to prevent path traversal.
 * Rejects paths containing `..`, null bytes, or absolute paths
 * outside expected patterns.
 */
export function sanitizeFilePath(filePath: string): string {
  // Reject null bytes
  if (filePath.includes("\0")) {
    throw new Error(`Invalid file path: contains null byte`);
  }

  // Normalize and reject path traversal
  const normalized = filePath.replace(/\\/g, "/");
  if (normalized.includes("../") || normalized.includes("/..")) {
    throw new Error(`Invalid file path: path traversal detected in "${filePath}"`);
  }

  // Reject overly long paths
  if (normalized.length > 1024) {
    throw new Error(`Invalid file path: exceeds maximum length of 1024 characters`);
  }

  return normalized;
}

// ---------------------------------------------------------------------------
// Diff parsing
// ---------------------------------------------------------------------------

/**
 * Parse a unified diff string into structured FileChange objects.
 *
 * Handles standard `diff --git` format with `---`/`+++` file markers
 * and `@@` hunk headers.
 */
export function parseDiff(diff: string): FileChange[] {
  if (diff.length > MAX_DIFF_SIZE) {
    throw new Error(
      `Diff size (${diff.length} chars) exceeds maximum allowed (${MAX_DIFF_SIZE} chars)`,
    );
  }

  const files: FileChange[] = [];
  const fileDiffs = diff.split(/^diff --git /m).filter(Boolean);

  if (fileDiffs.length > MAX_FILES) {
    throw new Error(
      `Diff contains ${fileDiffs.length} files, exceeding maximum of ${MAX_FILES}`,
    );
  }

  for (const fileDiff of fileDiffs) {
    const lines = fileDiff.split("\n");

    // Extract file path from the +++ line (or the diff header)
    let path = "";
    for (const line of lines) {
      if (line.startsWith("+++ b/")) {
        path = line.slice(6).trim();
        break;
      }
      if (line.startsWith("+++ ")) {
        path = line.slice(4).trim();
        break;
      }
    }

    // Fallback: extract from diff header (a/path b/path)
    if (!path && lines[0]) {
      const match = /b\/(.+)$/.exec(lines[0]);
      if (match?.[1]) {
        path = match[1].trim();
      }
    }

    if (!path) continue;

    // Validate the path
    path = sanitizeFilePath(path);

    // Detect language from extension
    const language = detectLanguage(path);

    // Extract only the diff content (hunk headers + changes)
    const diffContent = lines
      .filter(
        (line) =>
          line.startsWith("@@") ||
          line.startsWith("+") ||
          line.startsWith("-") ||
          line.startsWith(" "),
      )
      .join("\n");

    const fileChange: FileChange = { path, diff: diffContent, language };
    const parsed = FileChangeSchema.safeParse(fileChange);
    if (parsed.success) {
      files.push(parsed.data);
    }
  }

  return files;
}

// ---------------------------------------------------------------------------
// Language detection
// ---------------------------------------------------------------------------

const EXTENSION_LANGUAGE_MAP: Record<string, string> = {
  ".ts": "typescript",
  ".tsx": "typescript",
  ".js": "javascript",
  ".jsx": "javascript",
  ".py": "python",
  ".go": "go",
  ".rs": "rust",
  ".java": "java",
  ".kt": "kotlin",
  ".cs": "csharp",
  ".rb": "ruby",
  ".php": "php",
  ".swift": "swift",
  ".yaml": "yaml",
  ".yml": "yaml",
  ".json": "json",
  ".toml": "toml",
  ".xml": "xml",
  ".sql": "sql",
  ".sh": "shell",
  ".bash": "shell",
  ".tf": "terraform",
  ".hcl": "hcl",
  ".dockerfile": "dockerfile",
  ".proto": "protobuf",
  ".graphql": "graphql",
  ".gql": "graphql",
};

function detectLanguage(filePath: string): string {
  const lower = filePath.toLowerCase();

  // Special filenames
  if (lower.endsWith("dockerfile") || lower.includes("dockerfile.")) return "dockerfile";
  if (lower.endsWith("makefile")) return "makefile";

  const dotIndex = lower.lastIndexOf(".");
  if (dotIndex === -1) return "unknown";

  const ext = lower.slice(dotIndex);
  return EXTENSION_LANGUAGE_MAP[ext] ?? "unknown";
}

// ---------------------------------------------------------------------------
// Component extraction
// ---------------------------------------------------------------------------

/**
 * Pattern-based extraction of architectural components from file changes.
 * Identifies services, data stores, API gateways, external integrations,
 * and message queues from code patterns and file paths.
 */
export function extractComponents(files: FileChange[]): Component[] {
  const componentMap = new Map<string, Component>();

  for (const file of files) {
    const pathLower = file.path.toLowerCase();
    const diffLower = file.diff.toLowerCase();

    // Detect services from file paths and code patterns
    if (
      pathLower.includes("/controllers/") ||
      pathLower.includes("/handlers/") ||
      pathLower.includes("/routes/") ||
      pathLower.includes("/api/")
    ) {
      const name = extractServiceName(file.path);
      addOrMergeComponent(componentMap, {
        name,
        type: "service",
        entryPoints: identifyEntryPointsFromDiff(file.diff),
        dataFlows: [],
        trustBoundary: undefined,
      });
    }

    // Detect data stores
    if (
      diffLower.includes("createtable") ||
      diffLower.includes("create_table") ||
      diffLower.includes("mongoose.model") ||
      diffLower.includes("prisma") ||
      diffLower.includes("typeorm") ||
      diffLower.includes("sequelize") ||
      diffLower.includes("knex") ||
      pathLower.includes("/migrations/") ||
      pathLower.includes("/models/") ||
      pathLower.includes("/entities/") ||
      pathLower.includes("/schema")
    ) {
      const name = extractDatastoreName(file.path, file.diff);
      addOrMergeComponent(componentMap, {
        name,
        type: "datastore",
        entryPoints: [],
        dataFlows: [],
        trustBoundary: undefined,
      });
    }

    // Detect external services
    if (
      diffLower.includes("fetch(") ||
      diffLower.includes("axios.") ||
      diffLower.includes("http.request") ||
      diffLower.includes("httpsclient") ||
      diffLower.includes("requests.") ||
      diffLower.includes("webhook")
    ) {
      addOrMergeComponent(componentMap, {
        name: "External API Integration",
        type: "external",
        entryPoints: [],
        dataFlows: [],
        trustBoundary: "third-party",
      });
    }

    // Detect API gateways / reverse proxies
    if (
      pathLower.includes("gateway") ||
      pathLower.includes("proxy") ||
      pathLower.includes("nginx") ||
      pathLower.includes("envoy") ||
      pathLower.includes("traefik") ||
      diffLower.includes("rate_limit") ||
      diffLower.includes("ratelimit")
    ) {
      addOrMergeComponent(componentMap, {
        name: "API Gateway",
        type: "gateway",
        entryPoints: identifyEntryPointsFromDiff(file.diff),
        dataFlows: [],
        trustBoundary: "dmz",
      });
    }

    // Detect message queues
    if (
      diffLower.includes("kafka") ||
      diffLower.includes("rabbitmq") ||
      diffLower.includes("amqp") ||
      diffLower.includes("sqs") ||
      diffLower.includes("pubsub") ||
      diffLower.includes("nats") ||
      diffLower.includes("bullmq") ||
      pathLower.includes("/queue") ||
      pathLower.includes("/workers/") ||
      pathLower.includes("/consumers/")
    ) {
      addOrMergeComponent(componentMap, {
        name: "Message Queue",
        type: "queue",
        entryPoints: [],
        dataFlows: [],
        trustBoundary: "internal-network",
      });
    }
  }

  return Array.from(componentMap.values()).map((c) => ComponentSchema.parse(c));
}

function extractServiceName(filePath: string): string {
  const parts = filePath.split("/");
  // Look for a meaningful directory name near the file
  for (let i = parts.length - 2; i >= 0; i--) {
    const part = parts[i];
    if (
      part &&
      !["src", "lib", "app", "controllers", "handlers", "routes", "api"].includes(
        part.toLowerCase(),
      )
    ) {
      return sanitizeComponentName(part) + " Service";
    }
  }
  const fileName = parts[parts.length - 1];
  if (fileName) {
    const baseName = fileName.replace(/\.[^.]+$/, "");
    return sanitizeComponentName(baseName) + " Service";
  }
  return "Application Service";
}

function extractDatastoreName(filePath: string, diff: string): string {
  // Try to extract table/model name from diff
  const tableMatch = /(?:create\s+table|model)\s+["'`]?(\w+)/i.exec(diff);
  if (tableMatch?.[1]) {
    return sanitizeComponentName(tableMatch[1]) + " Datastore";
  }

  const parts = filePath.split("/");
  const fileName = parts[parts.length - 1];
  if (fileName) {
    const baseName = fileName.replace(/\.[^.]+$/, "");
    return sanitizeComponentName(baseName) + " Datastore";
  }
  return "Database";
}

/**
 * Sanitize a component name to prevent injection in downstream
 * rendering (Mermaid diagrams, markdown, etc.).
 */
function sanitizeComponentName(name: string): string {
  return name
    .replace(/[^a-zA-Z0-9\s_-]/g, "")
    .trim()
    .slice(0, 128);
}

function addOrMergeComponent(
  map: Map<string, Component>,
  component: Component,
): void {
  const existing = map.get(component.name);
  if (existing) {
    existing.entryPoints = [
      ...new Set([...existing.entryPoints, ...component.entryPoints]),
    ];
    if (component.trustBoundary && !existing.trustBoundary) {
      existing.trustBoundary = component.trustBoundary;
    }
  } else {
    map.set(component.name, { ...component });
  }
}

// ---------------------------------------------------------------------------
// Entry point identification
// ---------------------------------------------------------------------------

/**
 * Identify HTTP handlers, API routes, event listeners, and other
 * entry points from file changes.
 */
export function identifyEntryPoints(files: FileChange[]): string[] {
  const entryPoints = new Set<string>();

  for (const file of files) {
    for (const ep of identifyEntryPointsFromDiff(file.diff)) {
      entryPoints.add(ep);
    }
  }

  return Array.from(entryPoints);
}

function identifyEntryPointsFromDiff(diff: string): string[] {
  const entryPoints: string[] = [];

  // HTTP route patterns (Express, Fastify, Koa, Flask, Django, Go, etc.)
  const routePatterns = [
    // Express / Fastify style
    /(?:app|router|server)\.(get|post|put|patch|delete|all)\s*\(\s*['"`]([^'"`]+)['"`]/gi,
    // Decorator-based (NestJS, Spring, Flask)
    /@(?:Get|Post|Put|Patch|Delete|RequestMapping|app\.route)\s*\(\s*['"`]([^'"`]+)['"`]/gi,
    // Go http.HandleFunc
    /(?:HandleFunc|Handle)\s*\(\s*["']([^"']+)["']/gi,
    // Python FastAPI / Flask
    /@(?:app|router)\.\s*(?:get|post|put|patch|delete)\s*\(\s*["']([^"']+)["']/gi,
  ];

  for (const pattern of routePatterns) {
    let match;
    while ((match = pattern.exec(diff)) !== null) {
      // The route path is in the last capturing group
      const route = match[match.length - 1];
      if (route) {
        entryPoints.push(route);
      }
    }
  }

  // Event listener patterns
  const eventPatterns = [
    /\.on\s*\(\s*['"`]([^'"`]+)['"`]/gi,
    /addEventListener\s*\(\s*['"`]([^'"`]+)['"`]/gi,
    /subscribe\s*\(\s*['"`]([^'"`]+)['"`]/gi,
  ];

  for (const pattern of eventPatterns) {
    let match;
    while ((match = pattern.exec(diff)) !== null) {
      if (match[1]) {
        entryPoints.push(`event:${match[1]}`);
      }
    }
  }

  return entryPoints;
}

// ---------------------------------------------------------------------------
// Trust boundary classification
// ---------------------------------------------------------------------------

/**
 * Assign trust boundaries to components based on their type and
 * characteristics. Components without an explicit boundary are
 * classified heuristically.
 */
export function classifyTrustBoundaries(components: Component[]): Component[] {
  return components.map((component) => {
    if (component.trustBoundary) return component;

    let trustBoundary: string;
    switch (component.type) {
      case "gateway":
        trustBoundary = "dmz";
        break;
      case "external":
        trustBoundary = "third-party";
        break;
      case "datastore":
        trustBoundary = "internal-network";
        break;
      case "queue":
        trustBoundary = "internal-network";
        break;
      case "service":
        // Services with public entry points go in the DMZ
        trustBoundary = component.entryPoints.length > 0 ? "dmz" : "internal-network";
        break;
    }

    return ComponentSchema.parse({ ...component, trustBoundary });
  });
}

// ---------------------------------------------------------------------------
// Data flow identification
// ---------------------------------------------------------------------------

/**
 * Identify data flows between components based on their types,
 * entry points, and trust boundaries. Generates a conservative
 * set of flows representing likely communication paths.
 */
export function identifyDataFlows(components: Component[]): DataFlow[] {
  const flows: DataFlow[] = [];

  // Sort components by type for deterministic pairing
  const gateways = components.filter((c) => c.type === "gateway");
  const services = components.filter((c) => c.type === "service");
  const datastores = components.filter((c) => c.type === "datastore");
  const queues = components.filter((c) => c.type === "queue");
  const externals = components.filter((c) => c.type === "external");

  // Gateway → Services (gateway routes traffic to backend services)
  for (const gw of gateways) {
    for (const svc of services) {
      flows.push(
        DataFlowSchema.parse({
          source: gw.name,
          destination: svc.name,
          protocol: "HTTPS",
          dataClassification: "Internal",
          crossesTrustBoundary: gw.trustBoundary !== svc.trustBoundary,
        }),
      );
    }
  }

  // Services → Datastores
  for (const svc of services) {
    for (const ds of datastores) {
      flows.push(
        DataFlowSchema.parse({
          source: svc.name,
          destination: ds.name,
          protocol: "TCP/TLS",
          dataClassification: "Confidential",
          crossesTrustBoundary: svc.trustBoundary !== ds.trustBoundary,
        }),
      );
    }
  }

  // Services → Queues and Queues → Services
  for (const svc of services) {
    for (const q of queues) {
      flows.push(
        DataFlowSchema.parse({
          source: svc.name,
          destination: q.name,
          protocol: "AMQP/TLS",
          dataClassification: "Internal",
          crossesTrustBoundary: svc.trustBoundary !== q.trustBoundary,
        }),
      );
    }
  }

  // Services → External APIs
  for (const svc of services) {
    for (const ext of externals) {
      flows.push(
        DataFlowSchema.parse({
          source: svc.name,
          destination: ext.name,
          protocol: "HTTPS",
          dataClassification: "Confidential",
          crossesTrustBoundary: true,
        }),
      );
    }
  }

  return flows;
}

// ---------------------------------------------------------------------------
// Intent-aware data flow classification (B5)
// ---------------------------------------------------------------------------

/** Keywords that suggest a component handles PCI-scoped data. */
const PCI_COMPONENT_KEYWORDS = [
  "payment",
  "card",
  "token",
  "billing",
  "checkout",
  "stripe",
  "braintree",
  "adyen",
  "pan",
  "cardholder",
];

/**
 * Reclassify data flows based on project intent declarations.
 *
 * If the intent declares PCI data sensitivity and a component's name
 * suggests it handles payment data, upgrade the dataClassification to
 * "PCI" and mark external flows as crossing a trust boundary.
 *
 * @param flows - Existing data flows
 * @param components - System components
 * @param intent - Validated project intent declaration
 * @returns Updated data flows with intent-aware classification
 */
export function classifyDataFlowsWithIntent(
  flows: DataFlow[],
  components: Component[],
  intent: Intent,
): DataFlow[] {
  // Check if intent declares PCI data sensitivity
  const hasPCI = intent.intent.data_sensitivity.some(
    (ds) => ds.type === "PCI",
  );

  if (!hasPCI) return flows;

  // Build a set of component names that likely handle PCI data
  const pciComponentNames = new Set<string>();
  for (const component of components) {
    const nameLower = component.name.toLowerCase();
    if (PCI_COMPONENT_KEYWORDS.some((kw) => nameLower.includes(kw))) {
      pciComponentNames.add(component.name);
    }
  }

  if (pciComponentNames.size === 0) return flows;

  return flows.map((flow) => {
    const sourceIsPCI = pciComponentNames.has(flow.source);
    const destIsPCI = pciComponentNames.has(flow.destination);

    if (sourceIsPCI || destIsPCI) {
      // Find if one endpoint is external (crosses trust boundary for external flows)
      const sourceComponent = components.find((c) => c.name === flow.source);
      const destComponent = components.find((c) => c.name === flow.destination);
      const isExternal =
        sourceComponent?.type === "external" ||
        destComponent?.type === "external";

      return DataFlowSchema.parse({
        ...flow,
        dataClassification: "PCI",
        crossesTrustBoundary: flow.crossesTrustBoundary || isExternal,
      });
    }

    return flow;
  });
}
