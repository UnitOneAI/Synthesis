import path from "node:path";
import { id, sha, localSource, githubSource } from "./sources.mjs";
import { parseXml } from "./inventory.mjs";

export const ENGINE_VERSION = "static-pilot-0.1.0";
const short = (value) =>
  String(value ?? "")
    .replace(/[\u0000-\u001f]/g, " ")
    .slice(0, 300);
export function safeLabel(value) {
  return short(value)
    .replace(/([a-z]+:\/\/)[^\s/@]+:[^\s/@]+@/gi, "$1[redacted]@")
    .replace(
      /([?&](?:token|key|secret|password|sig|code)=)[^&\s]*/gi,
      "$1[redacted]",
    );
}
const walkObject = (value, fn, pointer = "", depth = 0) => {
  if (depth > 48) throw new Error("Configuration nesting exceeds 48 levels");
  if (!value || typeof value !== "object") return;
  for (const [key, item] of Object.entries(value)) {
    const p = pointer + "/" + key.replace(/~/g, "~0").replace(/\//g, "~1");
    fn(key, item, p);
    walkObject(item, fn, p, depth + 1);
  }
};
function routeLiteral(value) {
  return value && !/[?=]|password|secret|token=/i.test(value)
    ? short(value)
    : "[expression or sensitive literal omitted]";
}

// These bounded lexical collectors locate review candidates, not complete call graphs
// or effective security controls. Only structured declarations get source-supported status.
const RULES = [
  {
    kind: "http-inbound",
    direction: "inbound",
    protocol: "HTTP",
    regex:
      /\[Http(Get|Post|Put|Delete|Patch|Head|Options)(?:\(\s*"([^"\n]*)"[^\n]*\))?\]/g,
    label: (m) =>
      `${m[1].toUpperCase()} ${routeLiteral(m[2] || "[controller route]")}`,
  },
  {
    kind: "http-inbound",
    direction: "inbound",
    protocol: "HTTP",
    regex: /\.Map(Get|Post|Put|Delete|Patch)\(\s*"([^"\n]+)"/g,
    label: (m) => `${m[1].toUpperCase()} ${routeLiteral(m[2])}`,
  },
  {
    kind: "http-inbound",
    direction: "inbound",
    protocol: "HTTP",
    regex:
      /\b(?:app|router)\.(get|post|put|delete|patch|use)\(\s*['"]([^'"\n]+)['"]/g,
    label: (m) => `${m[1].toUpperCase()} ${routeLiteral(m[2])}`,
  },
  {
    kind: "http-outbound",
    direction: "outbound",
    protocol: "HTTP",
    regex:
      /\b(?:GetAsync|PostAsync|PutAsync|DeleteAsync|SendAsync|GetStringAsync|fetch|axios\.(?:get|post|put|delete|request))\s*\(/g,
    label: (m) =>
      `${m[0].replace(/\s*\($/, "")} call; destination requires review`,
  },
  {
    kind: "message-publish",
    direction: "outbound",
    protocol: "messaging",
    regex: /\b(?:BasicPublish(?:Async)?|PublishAsync|SendMessageAsync)\s*\(/g,
    label: () => "Message publish candidate; broker and resource unresolved",
  },
  {
    kind: "message-consume",
    direction: "inbound",
    protocol: "messaging",
    regex:
      /\b(?:BasicConsume(?:Async)?|SubscribeAsync|RegisterMessageHandler)\s*\(/g,
    label: () => "Message consumer candidate; broker and resource unresolved",
  },
  {
    kind: "message-provision",
    direction: "resource",
    protocol: "messaging",
    regex:
      /\b(?:QueueDeclare(?:Async)?|ExchangeDeclare(?:Async)?|QueueBind(?:Async)?)\s*\(/g,
    label: () => "Broker topology declaration candidate",
  },
  {
    kind: "database",
    direction: "resource",
    protocol: "database",
    regex:
      /\b(?:SqlConnection|DbContext|ExecuteReader(?:Async)?|ExecuteNonQuery(?:Async)?|ExecuteSqlRaw(?:Async)?|GraphDB|SparqlQuery)\b/g,
    label: (m) =>
      `${m[0]} data access candidate; resource and permissions unresolved`,
  },
  {
    kind: "rpc",
    direction: "unknown",
    protocol: "RPC",
    regex: /\[(?:ServiceContract|OperationContract)\b|\bChannelFactory\s*</g,
    label: () => "WCF contract or client candidate",
  },
  {
    kind: "device",
    direction: "unknown",
    protocol: "device",
    regex:
      /\b(?:BACnet|BacnetClient|BACnetSC|BACnet\/SC|bacnet_client|MmsClient)\b/g,
    label: () => "Device protocol reference; operations and peer unresolved",
  },
  {
    kind: "certificate",
    direction: "resource",
    protocol: "certificate",
    regex:
      /\b(?:X509Store|X509Certificate2|ImportPkcs12|CertificateRequest|Import-PfxCertificate)\b/g,
    label: (m) => `${m[0]} certificate operation candidate`,
  },
  {
    kind: "privileged-execution",
    direction: "resource",
    protocol: "host",
    regex:
      /\b(?:Process\.Start|Start-Process|CreateProcess|execFile|child_process)\b/g,
    label: () => "Process execution candidate; effective identity unresolved",
  },
  {
    kind: "control",
    direction: "control",
    protocol: "identity",
    regex:
      /\[(?:Authorize|AllowAnonymous)\b|\b(?:UseAuthentication|UseAuthorization|AddJwtBearer|RequireAuthorization|ValidateToken|CheckAccess|IsInRole)\s*\(/g,
    label: (m) =>
      `${m[0].replace(/[\[(]\s*$/, "")} control reference; enforcement scope unverified`,
  },
];
function stripComments(text, extension) {
  // Preserve line offsets; string literals are retained. Complex language constructs remain a coverage limitation.
  if (
    [
      ".xml",
      ".config",
      ".wxs",
      ".wxi",
      ".csproj",
      ".props",
      ".targets",
      ".wixproj",
    ].includes(extension)
  )
    return text.replace(/<!--[\s\S]*?-->/g, (m) => m.replace(/[^\n]/g, " "));
  if (
    [
      ".cs",
      ".js",
      ".ts",
      ".tsx",
      ".jsx",
      ".mjs",
      ".cpp",
      ".c",
      ".h",
      ".hpp",
      ".cc",
    ].includes(extension)
  ) {
    return text.replace(
      /"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\/\/[^\n]*|\/\*[\s\S]*?\*\//g,
      (m) =>
        m.startsWith("//") || m.startsWith("/*") ? m.replace(/[^\n]/g, " ") : m,
    );
  }
  return text;
}
export function extract(source, files) {
  const components = [],
    interfaces = [],
    evidence = [],
    dependencies = [],
    diagnostics = [];
  const projects = files
    .filter((f) =>
      /\.(csproj|vbproj|vcxproj|wixproj)$|(^|\/)package\.json$/i.test(f.path),
    )
    .map((f) => ({ file: f.path, dir: path.posix.dirname(f.path) }));
  const componentFor = (file) => {
    const owner = projects
      .filter(
        (p) => p.dir === "." || file === p.file || file.startsWith(p.dir + "/"),
      )
      .sort((a, b) => b.dir.length - a.dir.length)[0];
    const key = owner?.file ?? ".";
    let c = components.find((v) => v.sourceRoot === key);
    if (!c) {
      c = {
        id: id("component", source.name, key),
        repository: source.name,
        name: owner ? `${source.name} / ${owner.file}` : source.name,
        sourceRoot: key,
        kind: "source-component",
        execution: "unknown",
        basis: "source grouping; not an established process or trust domain",
      };
      components.push(c);
    }
    return c;
  };
  const add = (
    file,
    pointer,
    offset,
    kind,
    direction,
    protocol,
    operation,
    basis,
  ) => {
    if (interfaces.length >= 2000) return;
    const line = file.text.slice(0, offset).split("\n").length,
      c = componentFor(file.path);
    const e = {
      id: id(
        "evidence",
        source.name,
        file.path,
        pointer || offset,
        kind,
        file.hash,
      ),
      repository: source.name,
      path: file.path,
      line,
      pointer: pointer || null,
      blobSha256: file.hash,
      extractor: ENGINE_VERSION,
      basis,
      excerpt: "Source text omitted; inspect the referenced file locally.",
    };
    const item = {
      id: id(
        "interface",
        source.name,
        file.path,
        kind,
        pointer || `${line}:${operation}`,
      ),
      component: c.id,
      repository: source.name,
      kind,
      direction,
      protocol,
      operation: safeLabel(operation),
      evidence: [e.id],
      basis,
      resolution: "unresolved",
      controls: "unknown",
      effectiveExposure: "unknown",
      effectiveIdentity: "unknown",
    };
    if (!interfaces.some((x) => x.id === item.id)) {
      evidence.push(e);
      interfaces.push(item);
    }
  };
  for (const file of files) {
    const ext = path.posix.extname(file.path).toLowerCase();
    componentFor(file.path);
    let tree;
    try {
      if (ext === ".json") tree = JSON.parse(file.text);
      else if (
        [
          ".xml",
          ".config",
          ".wxs",
          ".wxi",
          ".csproj",
          ".vbproj",
          ".vcxproj",
          ".wixproj",
          ".props",
          ".targets",
        ].includes(ext)
      )
        tree = parseXml(file.text);
      if (tree)
        walkObject(tree, (key, value, pointer) => {
          if (
            key === "paths" &&
            value &&
            typeof value === "object" &&
            (tree.openapi || tree.swagger)
          ) {
            for (const [route, methods] of Object.entries(value))
              for (const method of Object.keys(methods ?? {}))
                if (/^(get|post|put|patch|delete|head|options)$/i.test(method))
                  add(
                    file,
                    pointer + "/" + route.replace(/\//g, "~1") + "/" + method,
                    0,
                    "http-contract",
                    "inbound",
                    "HTTP",
                    `${method.toUpperCase()} ${routeLiteral(route)}`,
                    "source-supported declaration; implementation and deployment unverified",
                  );
          }
          if (
            [
              "ServiceInstall",
              "CustomAction",
              "Permission",
              "PermissionEx",
              "ServiceConfig",
              "SqlDatabase",
              "SqlScript",
              "Certificate",
              "binding",
              "rewrite",
              "endpoint",
            ].includes(key)
          ) {
            const protocol = /^Sql/.test(key)
              ? "database"
              : /binding|rewrite|endpoint/.test(key)
                ? "configuration"
                : "installation";
            add(
              file,
              pointer,
              0,
              "configuration",
              "resource",
              protocol,
              `${key} declaration; effective values and applicability require review`,
              "source-supported declaration; effective behavior unverified",
            );
          }
          if (
            [
              "PackageReference",
              "ProjectReference",
              "dependencies",
              "devDependencies",
            ].includes(key)
          ) {
            const names =
              key.endsWith("Dependencies") || key === "dependencies"
                ? Object.keys(value ?? {})
                : (Array.isArray(value) ? value : [value])
                    .map((v) => v?.["@Include"])
                    .filter(Boolean);
            for (const name of names)
              dependencies.push({
                repository: source.name,
                path: file.path,
                pointer,
                name: short(name),
                basis:
                  "source dependency declaration; repository mapping unresolved",
              });
          }
          if (
            /^(ConnectionStrings|AllowedHosts|Authentication|Authorization|RabbitMQ|GraphDB|Kestrel|ReverseProxy)$/i.test(
              key,
            )
          )
            add(
              file,
              pointer,
              0,
              "configuration",
              "resource",
              "configuration",
              `${key} configuration section; values omitted`,
              "source-supported declaration; effective behavior unverified",
            );
        });
    } catch {
      diagnostics.push({
        repository: source.name,
        path: file.path,
        kind: "parse-failed",
        message:
          "Structured configuration could not be parsed safely; contents omitted",
      });
    }
    if (
      /\.(cs|js|mjs|ts|tsx|jsx|cpp|cc|c|h|hpp|ps1|sql|proto|graphql|sh|bat|cmd)$/i.test(
        file.path,
      )
    ) {
      const text = stripComments(file.text, ext);
      let count = 0;
      for (const rule of RULES) {
        rule.regex.lastIndex = 0;
        for (const match of text.matchAll(rule.regex)) {
          if (++count > 100) break;
          add(
            file,
            null,
            match.index,
            rule.kind,
            rule.direction,
            rule.protocol,
            rule.label(match),
            "inferred lexical candidate; source and call context need review",
          );
        }
        if (count > 100) break;
      }
      if (count > 100)
        diagnostics.push({
          repository: source.name,
          path: file.path,
          kind: "candidate-limit",
          message: "Only the first 100 candidates in this file were collected",
        });
    } else if (!tree)
      diagnostics.push({
        repository: source.name,
        path: file.path,
        kind: "discovery-only",
        message:
          "File hashed and inventoried; no semantic adapter for this format",
      });
  }
  if (interfaces.length >= 2000)
    diagnostics.push({
      repository: source.name,
      kind: "candidate-limit",
      message:
        "Repository interface budget of 2000 reached; additional candidates not recorded",
    });
  return { components, interfaces, evidence, dependencies, diagnostics };
}

const threatFor = (item) => {
  if (item.direction === "control") return null;
  if (item.protocol === "HTTP" && item.direction === "inbound")
    return [
      "Spoofing / elevation of privilege",
      "Untrusted caller",
      "Caller can reach this interface and submit requests",
      "If identity or operation-level authorization is absent or bypassable, the caller could invoke a protected operation.",
      "Verify route composition, inherited middleware, token issuer/audience validation and operation/object authorization.",
    ];
  if (item.protocol === "HTTP")
    return [
      "Spoofing / information disclosure",
      "Compromised calling workload",
      "Attacker controls the caller or destination input",
      "If destination selection or peer validation is inadequate, a request could expose credentials/data or reach unintended services.",
      "Trace destination configuration, permitted hosts, credential forwarding and TLS peer validation.",
    ];
  if (item.protocol === "messaging")
    return [
      "Tampering / elevation of privilege",
      "Malicious or compromised messaging participant",
      "Attacker has broker connectivity and a relevant publish/consume credential",
      "If resource permissions or receiver validation are insufficient, a participant could inject or read messages outside its authority.",
      "Resolve broker/vhost/queue bindings; inspect per-principal permissions, payload validation, replay handling and consumer authorization.",
    ];
  if (item.protocol === "database")
    return [
      "Tampering / information disclosure",
      "Compromised data-access workload",
      "Attacker controls a workload or input reaching this data operation",
      "If input handling or database permissions exceed the intended authority, protected records could be read or modified.",
      "Trace connection identity, query parameterization, object authorization, synchronization direction and database grants.",
    ];
  if (item.protocol === "certificate")
    return [
      "Spoofing / tampering",
      "Unauthorized certificate operator",
      "Attacker reaches certificate administration or controls certificate input",
      "If certificate and private-key operations lack appropriate authorization or validation, an untrusted peer could gain trust or keys could be exposed.",
      "Review enrollment/import authorization, key ACLs, trust-store changes, rotation and peer validation.",
    ];
  if (item.protocol === "host" || item.protocol === "installation")
    return [
      "Elevation of privilege / tampering",
      "Attacker controlling installation or command inputs",
      "Attacker can modify consumed artifacts, configuration or invocation parameters",
      "If a privileged operation consumes attacker-controlled inputs without adequate controls, it could execute or install unintended content.",
      "Review execution identity, argument handling, artifact integrity, file/registry ACLs and installation conditions separately from steady-state permissions.",
    ];
  if (item.protocol === "device" || item.protocol === "RPC")
    return [
      "Spoofing / tampering / denial of service",
      "Untrusted or compromised peer",
      "Attacker has protocol reachability or controls a connected peer",
      "If peer authentication, message validation or authorization is insufficient, an untrusted peer could influence protected operations or availability.",
      "Identify protocol endpoints, credentials/certificate trust, permitted operations, parser limits and safety-relevant effects.",
    ];
  return null;
};
export function compose(model, declarations = {}) {
  const interfaces = new Map(model.interfaces.map((i) => [i.id, i]));
  model.flows = [];
  model.boundaries = [];
  model.actors = [];
  model.threats = [];
  const bindings = declarations.bindings ?? [];
  if (!Array.isArray(bindings) || bindings.length > 2000)
    throw new Error("Invalid bindings");
  const used = new Set(),
    acceptedBindings = [];
  for (const binding of bindings) {
    const from = interfaces.get(binding.from),
      to = interfaces.get(binding.to);
    if (!from || !to || from.id === to.id || !short(binding.reason).trim())
      throw new Error(
        "Each binding needs two distinct current interface IDs and a rationale",
      );
    if (used.has(from.id))
      throw new Error(
        "Only one declared destination per source interface is supported in this pilot",
      );
    if (binding.profile !== model.profile)
      throw new Error("Binding profile does not match the analysis profile");
    const evidenceFingerprint = sha(
      JSON.stringify(
        model.sources.map((s) => [s.name, s.snapshot || "unavailable"]),
      ),
    );
    if (
      binding.evidenceFingerprint &&
      binding.evidenceFingerprint !== evidenceFingerprint
    )
      throw new Error(
        "Source snapshots changed; remove and review saved connection declarations before reusing them",
      );
    acceptedBindings.push({ ...binding, evidenceFingerprint });
    used.add(from.id);
    const flow = {
      id: id("flow", from.id, to.id, model.profile),
      from: from.id,
      to: to.id,
      source: from.component,
      target: to.component,
      operation: from.operation,
      basis: "declared",
      reason: short(binding.reason),
      reviewer: short(binding.reviewer || "local reviewer"),
      data: short(binding.data || "unknown"),
      controls: short(binding.controls || "unknown"),
      evidence: [...from.evidence, ...to.evidence],
    };
    model.flows.push(flow);
    from.resolution = "declared";
    if (binding.dimension) {
      if (
        ![
          "identity",
          "privilege",
          "network",
          "execution",
          "data-ownership",
          "third-party",
        ].includes(binding.dimension) ||
        !short(binding.before).trim() ||
        !short(binding.after).trim() ||
        binding.before === binding.after
      )
        throw new Error(
          "Boundary needs a supported dimension and distinct authority contexts",
        );
      model.boundaries.push({
        id: id("boundary", flow.id, binding.dimension),
        flow: flow.id,
        dimension: binding.dimension,
        before: short(binding.before),
        after: short(binding.after),
        enforcement: short(binding.controls || "unknown"),
        basis: "declared",
        evidence: flow.evidence,
      });
    }
  }
  for (const item of model.interfaces) {
    const rule = threatFor(item);
    if (!rule) continue;
    const [category, actorName, startingAccess, scenario, mitigation] = rule;
    const actorId = id("actor", actorName, item.component);
    if (!model.actors.some((a) => a.id === actorId))
      model.actors.push({
        id: actorId,
        name: actorName,
        component: item.component,
        startingAccess,
        basis: "assumed threat scenario; access and compromise not established",
        objectives:
          "Unauthorized access, modification or disruption of the affected operation",
      });
    const flow = model.flows.find(
      (f) => f.from === item.id || f.to === item.id,
    );
    model.threats.push({
      id: id("threat", actorId, item.id, category),
      actor: actorId,
      interface: item.id,
      category,
      asset: `${item.repository}: data, authority or availability associated with ${item.operation}`,
      scenario,
      prerequisites: [
        startingAccess,
        "Referenced candidate is active in the selected product profile",
        "The stated control failure is present; this has not been established",
      ],
      path: flow ? [flow.id] : [],
      evidence: item.evidence,
      controls:
        flow?.controls ||
        "unknown; control references are not proof of effective enforcement",
      mitigation,
      severity: "unassessed",
      confidence: "conditional review scenario",
      status: "needs-review",
    });
  }
  model.declarations = { bindings: acceptedBindings };
  model.modelRevision = sha(
    JSON.stringify({
      engine: ENGINE_VERSION,
      profile: model.profile,
      sources: model.sources,
      interfaces: model.interfaces,
      declarations: model.declarations,
    }),
  );
  return model;
}
export function validateManifest(manifest) {
  if (
    !manifest ||
    !Array.isArray(manifest.repositories) ||
    manifest.repositories.length > 1000
  )
    throw new Error("Manifest needs up to 1000 repository entries");
  if (
    typeof manifest.profile !== "string" ||
    !manifest.profile.trim() ||
    manifest.profile.length > 200
  )
    throw new Error("Choose one named product/configuration profile");
  const selected = manifest.repositories.filter((r) => r.selected !== false);
  if (!selected.length || selected.length > 100)
    throw new Error("Select 1–100 repositories for one analysis");
  const names = new Set();
  for (const r of selected) {
    if (
      !r ||
      typeof r.name !== "string" ||
      !/^[\w.-]{1,150}$/.test(r.name) ||
      r.name === "." ||
      r.name === ".." ||
      names.has(r.name.toLowerCase())
    )
      throw new Error("Repository names must be unique simple names");
    names.add(r.name.toLowerCase());
    if (r.source && !["local", "github"].includes(r.source))
      throw new Error("Source must be local or github");
    if (r.scope && !["primary", "supporting"].includes(r.scope))
      throw new Error("Scope must be primary or supporting");
    for (const key of ["localPath", "url", "ref"])
      if (
        r[key] != null &&
        (typeof r[key] !== "string" || r[key].length > 1000)
      )
        throw new Error(`Invalid ${key}`);
  }
  return selected;
}
export async function analyze(manifest, options = {}) {
  const selected = validateManifest(manifest);
  const model = {
    schemaVersion: 1,
    engine: ENGINE_VERSION,
    title: short(manifest.title || "Static system threat model"),
    profile: manifest.profile.trim(),
    createdAt: new Date().toISOString(),
    status: "draft-with-gaps",
    staticOnly: true,
    provider: "none",
    sources: [],
    components: [],
    interfaces: [],
    evidence: [],
    dependencies: [],
    diagnostics: [],
    inventoryCount: manifest.repositories.length,
    limitations: [
      "Lexical collectors propose interfaces; they do not establish complete call graphs, effective controls, or deployed reachability.",
      "Source grouping does not establish executable processes. No trust boundary is inferred from a repository boundary.",
      "Only explicit reviewer bindings form cross-component flows. Missing bindings remain unresolved.",
      "Conditional threat scenarios are review prompts, not verified vulnerabilities. Severity is unassessed.",
      "No target code, builds, installers, tests, hooks, runtime APIs, or AI providers are executed or contacted.",
      "Installation variants and runtime permissions require separate review within the selected profile.",
    ],
  };
  for (const source of selected) {
    options.progress?.(`Reading ${source.name}`);
    try {
      const snapshot =
        source.source === "github"
          ? await githubSource(source, options.githubToken)
          : await localSource(source, options.sourceRoot || process.cwd());
      model.sources.push({
        name: source.name,
        source: source.source || "local",
        scope: source.scope || "primary",
        revision: snapshot.revision,
        snapshot: snapshot.snapshot,
        revisionBasis: snapshot.revisionBasis,
        coverage: snapshot.coverage,
        status: "read",
      });
      if (model.interfaces.length >= 10000) {
        model.diagnostics.push({
          repository: source.name,
          kind: "candidate-limit",
          message:
            "System budget reached; files inventoried but interfaces not extracted",
        });
        continue;
      }
      const result = extract(source, snapshot.files);
      for (const key of [
        "components",
        "interfaces",
        "evidence",
        "dependencies",
        "diagnostics",
      ])
        model[key].push(...result[key]);
    } catch (error) {
      model.sources.push({
        name: source.name,
        source: source.source || "local",
        scope: source.scope || "primary",
        status: "unavailable",
      });
      model.diagnostics.push({
        repository: source.name,
        kind: "source-unavailable",
        message:
          error.code === "ENOENT"
            ? "Local source folder not found"
            : error.code === "EACCES"
              ? "Local source folder is not readable"
              : short(error.message).replace(
                  options.sourceRoot || "\0",
                  "[source-root]",
                ),
      });
    }
  }
  // Dependency suggestions are exact inventory-name matches only; they never add source scope or flows.
  model.dependencySuggestions = model.dependencies.flatMap((d) =>
    manifest.repositories
      .filter(
        (r) =>
          !selected.some((s) => s.name === r.name) &&
          (d.name === r.name || d.name.endsWith("/" + r.name + ".csproj")),
      )
      .map((r) => ({
        repository: r.name,
        requestedBy: d.repository,
        evidencePath: d.path,
        reason:
          "Dependency declaration resembles an inventory name; confirm package ownership before adding supporting scope",
      })),
  );
  return compose(model, manifest.declarations || {});
}
