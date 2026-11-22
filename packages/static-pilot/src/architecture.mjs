import path from "node:path";

// Scope labels affect presentation and scheduling. They never remove source from analysis.
export function sourceScope(file = "") {
  if (/(^|[/_.-])(tests?|specs?|fixtures?|mocks?)([/_.-]|$)/i.test(file))
    return "test";
  if (
    /(^|\/)(vendor|third_party|third-party|generated|dist|build)\//i.test(
      file,
    ) ||
    /(?:\.g|\.generated|\.min)\.[^.]+$/i.test(file)
  )
    return "generated-or-vendor";
  return "production-candidate";
}

// Only structural markers are retained; account names and command lines are not.
export function architectureFacts(file, text) {
  const facts = [];
  const add = (pattern, role, reason, extra = {}) => {
    const m = pattern.exec(text);
    if (m) facts.push({ offset: m.index, role, reason, ...extra });
  };
  if (/\.(?:csproj|vbproj|fsproj)$/i.test(file)) {
    add(
      /<IsTestProject>\s*true\s*<\/IsTestProject>|(?:Microsoft\.NET\.Test\.Sdk|xunit|NUnit)/i,
      "test",
      "Test project declaration",
    );
    add(
      /Sdk\s*=\s*"Microsoft\.NET\.Sdk\.Web"|<OutputType>\s*(?:WinExe|Exe)\s*<\/OutputType>/i,
      "process",
      "Executable or web project declaration",
    );
  }
  if (/(^|\/)package\.json$/i.test(file)) {
    try {
      const p = JSON.parse(text);
      if (
        Object.values(p.scripts || {}).some(
          (command) =>
            typeof command === "string" &&
            /\bnext\s+(?:start|dev)\b/.test(command),
        )
      )
        facts.push({
          offset: 0,
          role: "process",
          reason:
            "Next application start-script declaration; execution unverified",
        });
    } catch {
      /* The configuration parser separately reports malformed JSON. */
    }
  }
  if (/\.(?:cs|fs|vb|[cm]?[jt]sx?|py)$/i.test(file)) {
    add(
      /\b(?:WebApplication\.CreateBuilder|Host\.CreateDefaultBuilder|WebHost\.CreateDefaultBuilder|ServiceBase\.Run)\s*\(|\b(?:app|server)\.listen\s*\(/,
      "process",
      "Application host entry point",
    );
    add(
      /\b(?:MapReverseProxy|UseOcelot)\s*\(/,
      "gateway",
      "Reverse proxy registration",
    );
  }
  if (/\.(?:wxs|wxi|config|xml)$/i.test(file)) {
    add(
      /<ServiceInstall\b/,
      "process",
      "Installer service declaration; installed state unverified",
    );
    add(
      /<(?:ServiceInstall|processModel|identity)\b[^>]*(?:Account|identityType|impersonate)\s*=/i,
      "execution-identity",
      "Execution identity declaration; effective account and permissions unverified",
      { dimension: "execution" },
    );
  }
  return facts;
}

export function architectureComponents(model) {
  const evidence = new Map(model.evidence.map((e) => [e.id, e]));
  const byComponent = new Map();
  for (const i of model.interfaces) {
    if (!byComponent.has(i.component)) byComponent.set(i.component, []);
    byComponent.get(i.component).push(i);
  }
  const result = model.components.map((c) => {
    const items = byComponent.get(c.id) || [];
    const facts = items.filter((i) => i.connection?.kind === "architecture");
    const scope =
      facts.some((i) => i.connection.role === "test") ||
      sourceScope(c.sourceRoot) === "test"
        ? "test"
        : items.length &&
            items.every(
              (i) =>
                sourceScope(evidence.get(i.evidence[0])?.path) !==
                "production-candidate",
            )
          ? sourceScope(evidence.get(items[0].evidence[0])?.path)
          : "production-candidate";
    const role = ["gateway", "process"].find((role) =>
      facts.some((i) => i.connection.role === role),
    );
    const entries = items.filter(
      (i) =>
        i.kind === "http-inbound" &&
        sourceScope(evidence.get(i.evidence[0])?.path) ===
          "production-candidate",
    );
    const type =
      c.internalRole === "gateway"
        ? "gateway"
        : c.internalRole === "entrypoint"
          ? "process"
          : c.internalRole
            ? "source-group"
            : role || (entries.length ? "process" : "source-group");
    const support = facts.filter((i) => i.connection.role === role);
    const classificationEvidenceIds = [
      ...new Set(
        (support.length ? support : entries).flatMap((i) => i.evidence),
      ),
    ];
    const base =
      c.sourceRoot && c.sourceRoot !== "."
        ? path.posix
            .basename(c.sourceRoot)
            .replace(/\.(?:csproj|vbproj|vcxproj|wixproj)$/i, "")
        : c.repository;
    const directory = path.posix.basename(
      path.posix.dirname(c.sourceRoot || "."),
    );
    const name =
      base === "package.json"
        ? directory === "."
          ? c.repository
          : directory || c.repository
        : base;
    return {
      id: c.id,
      name: ["gateway", "entrypoint"].includes(c.internalRole)
        ? c.name
        : c.internalRole
          ? `${c.name} · ${c.internalRole === "worker" ? "background worker" : c.internalRole === "service" ? "service entry" : c.internalRole === "storage-adapter" ? "storage adapter" : "client adapter"}`
          : name,
      internalRole: c.internalRole,
      resourceKinds: c.resourceKinds,
      parentComponentId: c.parentComponentId,
      sourceRoot: c.sourceRoot,
      type,
      scope,
      classificationEvidenceIds: [
        ...classificationEvidenceIds,
        ...(c.declarationEvidence || []),
      ],
      classification: c.internalRole
        ? "Internal source unit; separate process and activation not established"
        : type === "source-group"
          ? "Source ownership only; executable host not identified"
          : role
            ? "Candidate from host or installer declaration"
            : "Candidate from implemented HTTP entry points; deployment unverified",
    };
  });
  const counts = new Map();
  for (const c of result) counts.set(c.name, (counts.get(c.name) || 0) + 1);
  for (const c of result)
    if (counts.get(c.name) > 1) {
      const original = model.components.find((n) => n.id === c.id);
      c.name = `${original.repository} / ${c.sourceRoot || c.name}`;
    }
  // A library may have one candidate host, but references never establish trust.
  const project = new Map(
    model.components.map((c) => [`${c.repository}:${c.sourceRoot}`, c.id]),
  );
  const refs = new Map();
  for (const d of model.dependencies || []) {
    if (!/\.(?:csproj|vbproj|vcxproj)$/i.test(d.name || "")) continue;
    const owner = project.get(`${d.repository}:${d.path}`);
    const target = project.get(
      `${d.repository}:${path.posix.normalize(path.posix.join(path.posix.dirname(d.path), d.name.replaceAll("\\", "/")))}`,
    );
    if (owner && target) {
      if (!refs.has(owner)) refs.set(owner, new Set());
      refs.get(owner).add(target);
    }
  }
  const owners = new Map();
  for (const host of result.filter(
    (c) => c.type !== "source-group" && c.scope === "production-candidate",
  )) {
    const seen = new Set([host.id]),
      pending = [...(refs.get(host.id) || [])];
    while (pending.length) {
      const current = pending.pop();
      if (seen.has(current)) continue;
      seen.add(current);
      if (!owners.has(current)) owners.set(current, new Set());
      owners.get(current).add(host.id);
      pending.push(...(refs.get(current) || []));
    }
  }
  for (const c of result)
    if (
      c.type === "source-group" &&
      c.scope === "production-candidate" &&
      owners.get(c.id)?.size === 1
    ) {
      c.hostCandidateId = [...owners.get(c.id)][0];
      c.hostBasis =
        "Unique executable project-reference owner in collected source; deployment requires review";
    }
  return result;
}

// Literal deployment declarations only; commands and configuration are never executed.
export function deploymentFacts(file, text) {
  const facts = [];
  const add = (m, role, extra) =>
    facts.push({
      offset: m.index,
      role,
      reason: `Static deployment ${role}`,
      ...extra,
    });
  if (/(^|\/)pyproject\.toml$/.test(file)) {
    const section =
      /^\[project\.scripts\]\s*\n([\s\S]*?)(?=^\[|$(?![\s\S]))/m.exec(text);
    if (section)
      for (const m of section[1].matchAll(
        /^\s*([\w-]+)\s*=\s*["']([\w.]+):\w+["']/gm,
      ))
        add(
          {
            index:
              section.index + section[0].length - section[1].length + m.index,
          },
          "entrypoint",
          {
            module: m[2],
            label: m[1],
          },
        );
  }
  if (!/(^|\/)Dockerfile(?:\.[\w-]+)?$|\.(?:conf|ini)$/i.test(file))
    return facts;
  const clean = text.replace(/^\s*#.*$/gm, (m) => m.replace(/[^\n]/g, " "));
  const workdirs = [...clean.matchAll(/^WORKDIR\s+(\/[\w/.-]+)\s*$/gm)];
  for (const m of clean.matchAll(
    /^command=[^\n]*?\buvicorn\s+([\w.]+):\w+[^\n]*?--port\s+(\d+)\b[^\n]*/gm,
  ))
    if (/--host\s+(?:127\.0\.0\.1|0\.0\.0\.0|localhost)\b/.test(m[0]))
      add(m, "host-binding", { module: m[1], port: Number(m[2]) });
  for (const m of clean.matchAll(
    /^\[program:([\w-]+)\]\s*\n([\s\S]*?)(?=^\[|^EOF|$(?![\s\S]))/gm,
  )) {
    if (!/^command=.*\bnode\s+[\w./-]+/m.test(m[2])) continue;
    const stage = clean.lastIndexOf("\nFROM ", m.index);
    const workdir = workdirs
      .filter((w) => w.index > stage && w.index < m.index)
      .at(-1)?.[1];
    const directory = m[2].match(/^directory=(\/[\w/.-]+)\s*$/m)?.[1];
    const port = m[2].match(/^environment=.*\bPORT="(\d+)"/m)?.[1];
    if (
      workdir &&
      directory &&
      port &&
      (directory === workdir || directory.startsWith(workdir + "/"))
    )
      add(m, "host-binding", {
        project: path.posix.join(
          path.posix.relative(workdir, directory),
          "package.json",
        ),
        port: Number(port),
      });
  }
  for (const m of clean.matchAll(
    /^\s*proxy_pass\s+(https?:\/\/(?:127\.0\.0\.1|localhost):(\d+))(?:\/[\w/.-]*)?\s*;/gm,
  ))
    add(m, "proxy-target", {
      port: Number(m[2]),
      transport: m[1].startsWith("https:") ? "HTTPS" : "HTTP",
    });
  return facts;
}
