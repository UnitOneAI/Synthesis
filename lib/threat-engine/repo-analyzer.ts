import simpleGit from "simple-git";
import fs from "fs";
import path from "path";
import os from "os";

// ── Types ──

export interface ComponentInfo {
  name: string;
  type: "api" | "service" | "database" | "queue" | "gateway" | "external" | "frontend" | "config";
  files: string[];
  description: string;
}

export interface DataFlow {
  from: string;
  to: string;
  protocol: string;
  dataType: string;
}

export interface TrustBoundary {
  name: string;
  components: string[];
}

export interface SecurityFinding {
  file: string;
  line: number;
  pattern: string;
  snippet: string;
  severity: "Critical" | "High" | "Medium" | "Low";
}

export interface RepoAnalysis {
  repoUrl: string;
  languages: string[];
  frameworks: string[];
  components: ComponentInfo[];
  dataFlows: DataFlow[];
  trustBoundaries: TrustBoundary[];
  securityFindings: SecurityFinding[];
  fileTree: string[];
  entryPoints: string[];
}

// ── Constants ──

const MAX_FILE_SIZE = 50 * 1024; // 50KB per file
const MAX_FILES = 500;
const SKIP_DIRS = new Set([
  "node_modules", ".git", "__pycache__", ".next", "dist", "build",
  ".venv", "venv", "vendor", ".terraform", ".cache", "coverage",
  ".idea", ".vscode", "target", "bin", "obj",
]);
const SKIP_EXTENSIONS = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
  ".ttf", ".eot", ".mp3", ".mp4", ".zip", ".tar", ".gz", ".pdf",
  ".lock", ".min.js", ".min.css", ".map",
]);

// ── Security Patterns ──

interface SecurityPattern {
  name: string;
  pattern: RegExp;
  severity: "Critical" | "High" | "Medium" | "Low";
  description: string;
}

const SECURITY_PATTERNS: SecurityPattern[] = [
  {
    name: "hardcoded_secret",
    pattern: /(?:api[_-]?key|apikey|secret|password|token|auth)\s*[:=]\s*["'][^"']{8,}["']/gi,
    severity: "Critical",
    description: "Hardcoded secret or API key found",
  },
  {
    name: "sql_concatenation",
    pattern: /(?:execute|query|raw)\s*\(\s*(?:f["']|["']\s*\+|`[^`]*\$\{)/gi,
    severity: "Critical",
    description: "Potential SQL injection via string concatenation",
  },
  {
    name: "eval_usage",
    pattern: /\b(?:eval|exec)\s*\(/g,
    severity: "High",
    description: "Use of eval/exec which may allow code injection",
  },
  {
    name: "missing_https",
    pattern: /http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)/g,
    severity: "Medium",
    description: "Non-HTTPS URL found (potential cleartext transmission)",
  },
  {
    name: "command_injection",
    pattern: /(?:child_process|subprocess|os\.system|os\.popen|Runtime\.exec)\s*\(/g,
    severity: "High",
    description: "System command execution (potential command injection)",
  },
  {
    name: "cors_wildcard",
    pattern: /(?:Access-Control-Allow-Origin|cors)\s*[:=]\s*["']\*["']/gi,
    severity: "Medium",
    description: "CORS wildcard configuration",
  },
  {
    name: "debug_enabled",
    pattern: /(?:DEBUG|debug)\s*[:=]\s*(?:true|True|1|["']true["'])/g,
    severity: "Low",
    description: "Debug mode enabled",
  },
  {
    name: "no_auth_check",
    pattern: /(?:@app\.route|router\.(?:get|post|put|delete|patch))\s*\([^)]+\)\s*\n(?:(?!@require_auth|@login_required|@authenticated|auth|protect|guard).)*/gm,
    severity: "High",
    description: "Route handler potentially missing authentication",
  },
  {
    name: "insecure_deserialization",
    pattern: /(?:pickle\.loads|yaml\.load\s*\((?!.*Loader)|unserialize|JSON\.parse\s*\(\s*req)/g,
    severity: "High",
    description: "Potentially insecure deserialization",
  },
  {
    name: "weak_crypto",
    pattern: /\b(?:md5|sha1|DES|RC4)\b/gi,
    severity: "Medium",
    description: "Weak cryptographic algorithm usage",
  },
];

// ── Framework Detection ──

interface FrameworkSignature {
  file: string;
  key?: string;
  framework: string;
  type: "backend" | "frontend" | "infra" | "database";
}

const FRAMEWORK_SIGNATURES: FrameworkSignature[] = [
  { file: "package.json", key: "express", framework: "Express.js", type: "backend" },
  { file: "package.json", key: "fastify", framework: "Fastify", type: "backend" },
  { file: "package.json", key: "next", framework: "Next.js", type: "frontend" },
  { file: "package.json", key: "react", framework: "React", type: "frontend" },
  { file: "package.json", key: "vue", framework: "Vue.js", type: "frontend" },
  { file: "package.json", key: "angular", framework: "Angular", type: "frontend" },
  { file: "package.json", key: "nestjs", framework: "NestJS", type: "backend" },
  { file: "requirements.txt", key: "flask", framework: "Flask", type: "backend" },
  { file: "requirements.txt", key: "django", framework: "Django", type: "backend" },
  { file: "requirements.txt", key: "fastapi", framework: "FastAPI", type: "backend" },
  { file: "go.mod", key: "gin", framework: "Gin", type: "backend" },
  { file: "go.mod", key: "fiber", framework: "Fiber", type: "backend" },
  { file: "Cargo.toml", key: "actix", framework: "Actix", type: "backend" },
  { file: "pom.xml", key: "spring", framework: "Spring Boot", type: "backend" },
  { file: "Dockerfile", framework: "Docker", type: "infra" },
  { file: "docker-compose.yml", framework: "Docker Compose", type: "infra" },
  { file: "docker-compose.yaml", framework: "Docker Compose", type: "infra" },
  { file: "terraform.tf", framework: "Terraform", type: "infra" },
  { file: ".github/workflows", framework: "GitHub Actions", type: "infra" },
];

// ── Main Analyzer ──

export async function analyzeRepo(repoUrl: string, sessionId: string): Promise<RepoAnalysis> {
  const tmpDir = path.join(os.tmpdir(), `threat-model-${sessionId}`);

  try {
    // 1. Clone the repo
    await cloneRepo(repoUrl, tmpDir);

    // 2. Walk file tree
    const fileTree = walkDir(tmpDir, tmpDir);

    // 3. Detect languages
    const languages = detectLanguages(fileTree);

    // 4. Detect frameworks
    const frameworks = await detectFrameworks(tmpDir, fileTree);

    // 5. Find entry points
    const entryPoints = findEntryPoints(fileTree);

    // 6. Scan for security patterns
    const securityFindings = await scanSecurity(tmpDir, fileTree);

    // 7. Extract architecture
    const { components, dataFlows, trustBoundaries } = await extractArchitecture(
      tmpDir,
      fileTree,
      frameworks,
      securityFindings
    );

    return {
      repoUrl,
      languages,
      frameworks,
      components,
      dataFlows,
      trustBoundaries,
      securityFindings,
      fileTree: fileTree.slice(0, 200), // Cap for response size
      entryPoints,
    };
  } finally {
    // Cleanup
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup errors
    }
  }
}

async function cloneRepo(url: string, dir: string): Promise<void> {
  // Normalize GitHub URLs
  let gitUrl = url;
  if (!gitUrl.startsWith("http") && !gitUrl.startsWith("git@")) {
    gitUrl = `https://${gitUrl}`;
  }
  if (!gitUrl.endsWith(".git")) {
    gitUrl = `${gitUrl}.git`;
  }

  const git = simpleGit();
  await git.clone(gitUrl, dir, ["--depth", "1"]);
}

function walkDir(dir: string, rootDir: string, files: string[] = []): string[] {
  if (files.length >= MAX_FILES) return files;

  const entries = fs.readdirSync(dir, { withFileTypes: true });

  for (const entry of entries) {
    if (files.length >= MAX_FILES) break;

    if (SKIP_DIRS.has(entry.name)) continue;
    if (entry.name.startsWith(".") && entry.name !== ".env" && entry.name !== ".env.example") continue;

    const fullPath = path.join(dir, entry.name);
    const relativePath = path.relative(rootDir, fullPath);

    if (entry.isDirectory()) {
      walkDir(fullPath, rootDir, files);
    } else {
      const ext = path.extname(entry.name).toLowerCase();
      if (SKIP_EXTENSIONS.has(ext)) continue;

      try {
        const stat = fs.statSync(fullPath);
        if (stat.size <= MAX_FILE_SIZE) {
          files.push(relativePath);
        }
      } catch {
        // Skip unreadable files
      }
    }
  }

  return files;
}

function detectLanguages(files: string[]): string[] {
  const langMap: Record<string, string> = {
    ".ts": "TypeScript", ".tsx": "TypeScript",
    ".js": "JavaScript", ".jsx": "JavaScript",
    ".py": "Python",
    ".go": "Go",
    ".rs": "Rust",
    ".java": "Java",
    ".cs": "C#",
    ".c": "C", ".h": "C",
    ".cpp": "C++", ".hpp": "C++",
    ".rb": "Ruby",
    ".php": "PHP",
    ".swift": "Swift",
    ".kt": "Kotlin",
    ".tf": "Terraform/HCL",
    ".yaml": "YAML", ".yml": "YAML",
    ".sql": "SQL",
    ".sh": "Shell",
  };

  const langs = new Set<string>();
  for (const f of files) {
    const ext = path.extname(f).toLowerCase();
    if (langMap[ext]) langs.add(langMap[ext]);
  }
  return Array.from(langs);
}

async function detectFrameworks(rootDir: string, files: string[]): Promise<string[]> {
  const detected = new Set<string>();

  for (const sig of FRAMEWORK_SIGNATURES) {
    const match = files.find(
      (f) => f === sig.file || f.endsWith(`/${sig.file}`) || f.startsWith(sig.file)
    );
    if (!match) continue;

    if (!sig.key) {
      detected.add(sig.framework);
      continue;
    }

    try {
      const content = fs.readFileSync(path.join(rootDir, match), "utf-8");
      if (content.toLowerCase().includes(sig.key.toLowerCase())) {
        detected.add(sig.framework);
      }
    } catch {
      // Skip unreadable
    }
  }

  return Array.from(detected);
}

function findEntryPoints(files: string[]): string[] {
  const entryPatterns = [
    /^(?:src\/)?(?:index|main|app|server)\.[tj]sx?$/,
    /^(?:src\/)?(?:index|main|app|server)\.py$/,
    /^(?:cmd\/|main).*\.go$/,
    /^(?:src\/)?main\.rs$/,
    /routes?\//i,
    /controllers?\//i,
    /api\//i,
    /handlers?\//i,
  ];

  return files.filter((f) =>
    entryPatterns.some((p) => p.test(f))
  );
}

async function scanSecurity(
  rootDir: string,
  files: string[]
): Promise<SecurityFinding[]> {
  const findings: SecurityFinding[] = [];
  const codeExtensions = new Set([
    ".ts", ".tsx", ".js", ".jsx", ".py", ".go", ".rs", ".java",
    ".cs", ".c", ".cpp", ".rb", ".php", ".yaml", ".yml", ".json",
    ".env", ".cfg", ".conf", ".ini", ".toml",
  ]);

  for (const relFile of files) {
    const ext = path.extname(relFile).toLowerCase();
    if (!codeExtensions.has(ext) && !relFile.includes(".env")) continue;

    try {
      const fullPath = path.join(rootDir, relFile);
      const content = fs.readFileSync(fullPath, "utf-8");
      const lines = content.split("\n");

      for (const pattern of SECURITY_PATTERNS) {
        // Reset regex state
        pattern.pattern.lastIndex = 0;
        let match: RegExpExecArray | null;

        while ((match = pattern.pattern.exec(content)) !== null) {
          // Find line number
          const upToMatch = content.substring(0, match.index);
          const lineNum = upToMatch.split("\n").length;

          // Get the surrounding line
          const snippetLine = lines[lineNum - 1] || "";

          findings.push({
            file: relFile,
            line: lineNum,
            pattern: pattern.name,
            snippet: snippetLine.trim().substring(0, 200),
            severity: pattern.severity,
          });

          // Limit findings per file
          if (findings.filter((f) => f.file === relFile).length >= 10) break;
        }
      }
    } catch {
      // Skip unreadable files
    }
  }

  return findings;
}

async function extractArchitecture(
  rootDir: string,
  files: string[],
  frameworks: string[],
  findings: SecurityFinding[]
): Promise<{
  components: ComponentInfo[];
  dataFlows: DataFlow[];
  trustBoundaries: TrustBoundary[];
}> {
  const components: ComponentInfo[] = [];
  const dataFlows: DataFlow[] = [];
  const trustBoundaries: TrustBoundary[] = [];

  // Detect API components
  const apiFiles = files.filter(
    (f) =>
      /(?:routes?|controllers?|handlers?|api|endpoints?)\//i.test(f) ||
      /(?:routes?|controllers?|handlers?)\.(?:ts|js|py|go)$/i.test(f)
  );
  if (apiFiles.length > 0) {
    components.push({
      name: "API Server",
      type: "api",
      files: apiFiles.slice(0, 20),
      description: `API layer with ${apiFiles.length} route/controller files`,
    });
  }

  // Detect frontend
  const frontendFiles = files.filter(
    (f) =>
      /(?:pages?|views?|components?|screens?)\//i.test(f) &&
      /\.[tj]sx?$/.test(f)
  );
  if (frontendFiles.length > 0) {
    components.push({
      name: "Frontend Application",
      type: "frontend",
      files: frontendFiles.slice(0, 20),
      description: `Frontend with ${frontendFiles.length} component/page files`,
    });
  }

  // Detect database connections
  const dbPatterns = /(?:mongoose|sequelize|prisma|typeorm|knex|sqlalchemy|gorm|diesel|pg|mysql|mongodb|redis)/i;
  const dbFiles = files.filter((f) => {
    try {
      const content = fs.readFileSync(path.join(rootDir, f), "utf-8");
      return dbPatterns.test(content);
    } catch {
      return false;
    }
  });
  if (dbFiles.length > 0) {
    components.push({
      name: "Database",
      type: "database",
      files: dbFiles.slice(0, 10),
      description: "Data persistence layer",
    });
  }

  // Detect message queues
  const queuePatterns = /(?:mqtt|kafka|rabbitmq|sqs|pubsub|amqp|bull|celery|nats)/i;
  const queueFiles = files.filter((f) => {
    try {
      const content = fs.readFileSync(path.join(rootDir, f), "utf-8");
      return queuePatterns.test(content);
    } catch {
      return false;
    }
  });
  if (queueFiles.length > 0) {
    components.push({
      name: "Message Queue",
      type: "queue",
      files: queueFiles.slice(0, 10),
      description: "Asynchronous messaging layer",
    });
  }

  // Detect auth services
  const authFiles = files.filter(
    (f) => /(?:auth|login|session|jwt|oauth|passport|guard)/i.test(f)
  );
  if (authFiles.length > 0) {
    components.push({
      name: "Auth Service",
      type: "service",
      files: authFiles.slice(0, 10),
      description: "Authentication and authorization service",
    });
  }

  // Detect config/infra
  const infraFiles = files.filter(
    (f) =>
      /(?:Dockerfile|docker-compose|\.tf$|cloudformation|k8s|helm)/i.test(f) ||
      f.endsWith(".env") ||
      f.endsWith(".env.example")
  );
  if (infraFiles.length > 0) {
    components.push({
      name: "Infrastructure",
      type: "config",
      files: infraFiles.slice(0, 10),
      description: "Infrastructure and configuration files",
    });
  }

  // Detect gateway/proxy
  const gatewayFiles = files.filter(
    (f) => /(?:gateway|proxy|nginx|haproxy|envoy|middleware)/i.test(f)
  );
  if (gatewayFiles.length > 0) {
    components.push({
      name: "API Gateway",
      type: "gateway",
      files: gatewayFiles.slice(0, 10),
      description: "API gateway or reverse proxy",
    });
  }

  // If no components were found, create generic ones from the file tree
  if (components.length === 0) {
    const srcFiles = files.filter(
      (f) => /\.(ts|js|py|go|rs|java|cs|rb|php)$/.test(f)
    );
    components.push({
      name: "Application",
      type: "service",
      files: srcFiles.slice(0, 20),
      description: `Application with ${srcFiles.length} source files`,
    });
  }

  // Build data flows from component relationships
  const hasApi = components.find((c) => c.type === "api");
  const hasDb = components.find((c) => c.type === "database");
  const hasQueue = components.find((c) => c.type === "queue");
  const hasAuth = components.find((c) => c.name === "Auth Service");
  const hasFrontend = components.find((c) => c.type === "frontend");
  const hasGateway = components.find((c) => c.type === "gateway");

  // External user entity
  components.push({
    name: "End User",
    type: "external",
    files: [],
    description: "External user accessing the application",
  });

  if (hasFrontend && hasApi) {
    dataFlows.push({ from: "End User", to: "Frontend Application", protocol: "HTTPS", dataType: "User Requests" });
    dataFlows.push({ from: "Frontend Application", to: "API Server", protocol: "HTTPS/REST", dataType: "API Calls" });
  } else if (hasApi) {
    dataFlows.push({ from: "End User", to: hasGateway ? "API Gateway" : "API Server", protocol: "HTTPS", dataType: "API Requests" });
  }

  if (hasGateway && hasApi) {
    dataFlows.push({ from: "API Gateway", to: "API Server", protocol: "HTTP/Internal", dataType: "Proxied Requests" });
  }

  if (hasAuth && hasApi) {
    dataFlows.push({ from: "API Server", to: "Auth Service", protocol: "Internal", dataType: "Auth Tokens" });
  }

  if (hasApi && hasDb) {
    dataFlows.push({ from: "API Server", to: "Database", protocol: "TCP", dataType: "Queries/Data" });
  }

  if (hasAuth && hasDb) {
    dataFlows.push({ from: "Auth Service", to: "Database", protocol: "TCP", dataType: "User Credentials" });
  }

  if (hasQueue && hasApi) {
    dataFlows.push({ from: "API Server", to: "Message Queue", protocol: "AMQP/MQTT", dataType: "Events/Commands" });
  }

  // Build trust boundaries
  const internalComponents = components
    .filter((c) => c.type !== "external")
    .map((c) => c.name);

  if (internalComponents.length > 0) {
    trustBoundaries.push({
      name: "Application Boundary",
      components: internalComponents,
    });
  }

  const externalComponents = components
    .filter((c) => c.type === "external")
    .map((c) => c.name);

  if (externalComponents.length > 0) {
    trustBoundaries.push({
      name: "External",
      components: externalComponents,
    });
  }

  // If there's infra (Docker, cloud), create a separate boundary
  const infraComponent = components.find((c) => c.type === "config");
  if (infraComponent) {
    trustBoundaries.push({
      name: "Infrastructure",
      components: [infraComponent.name],
    });
  }

  return { components, dataFlows, trustBoundaries };
}
