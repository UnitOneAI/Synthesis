import path from "node:path";
import { id } from "./sources.mjs";
import { sourceScope } from "./architecture.mjs";

// Facts contain symbols and source locations, never source expressions or credentials.
// These adapters identify conditional source interactions, not runtime execution.
export function internalFacts(file, text) {
  const facts = [];
  const add = (m, role, extra = {}) =>
    facts.push({
      offset: m.index,
      role,
      reason: `Static ${role} ${extra.symbol || extra.label || ""}`,
      ...extra,
    });
  const python = file.endsWith(".py"),
    cs = file.endsWith(".cs");
  if (!python && !cs) return facts;
  // Mask literals for structural matching while preserving offsets and newlines.
  const code = text.replace(/"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'/g, (s) =>
    s.replace(/[^\n]/g, " "),
  );
  if (python) {
    for (const m of code.matchAll(/^class\s+(\w+)\b/gm))
      add(m, "symbol", { symbol: m[1] });
    for (const m of code.matchAll(/^(?:async\s+)?def\s+(\w+)\s*\(/gm))
      add(m, "symbol", { symbol: m[1] });
    for (const m of code.matchAll(
      /\bfrom\s+([.\w]+)\s+import\s+(\([^)]*\)|[^\n]+)/g,
    )) {
      for (const part of m[2].replace(/[()\n]/g, " ").split(",")) {
        const b = part.trim().match(/^(\w+)(?:\s+as\s+(\w+))?$/);
        if (b)
          add(m, "import-binding", {
            module: m[1],
            symbol: b[1],
            alias: b[2] || b[1],
          });
      }
    }
    for (const m of code.matchAll(/\b([A-Za-z_]\w*)\s*\(/g)) {
      if (
        /\b(?:def|class)\s*$/.test(
          code.slice(Math.max(0, m.index - 15), m.index),
        )
      )
        continue;
      if (
        code[m.index - 1] !== "." &&
        facts.some((f) => f.role === "import-binding" && f.alias === m[1])
      ) {
        const symbol = m[1];
        // Reject lexical shadowing/reassignment instead of guessing a binding.
        if (
          new RegExp(
            `\\b${symbol}\\s*=(?!=)|def\\s+\\w+\\s*\\([^)]*\\b${symbol}\\b`,
          ).test(code)
        )
          continue;
        add(m, "symbol-call", { symbol });
      }
    }
  } else {
    for (const m of code.matchAll(/\bclass\s+(\w+)\b/g))
      add(m, "symbol", { symbol: m[1] });
    for (const m of code.matchAll(
      /\b(?:new\s+(\w+)\s*\(|AddHostedService\s*<\s*(\w+)\s*>)/g,
    ))
      add(m, "symbol-call", { symbol: m[1] || m[2] });
  }
  const behaviors = [
    [
      /\b(?:threading\.Thread|ThreadPoolExecutor)\s*\(|\bclass\s+\w+\s*:\s*(?:BackgroundService|IHostedService)\b/g,
      "worker",
      "Background worker",
    ],
    [/\b(?:sqlite3|aiosqlite)\.connect\s*\(/g, "store-use", "SQLite"],
    [
      /\b(?:create_engine|SqlConnection|NpgsqlConnection|MongoClient)\s*\(/g,
      "store-use",
      "Database",
    ],
    [
      /\b(?:anthropic\.)?(?:AsyncAnthropic|Anthropic)\s*\(/g,
      "external-use",
      "Anthropic client",
    ],
    [
      /\b(?:openai\.)?(?:AsyncOpenAI|OpenAI)\s*\(/g,
      "external-use",
      "OpenAI-compatible client",
    ],
    [/\bFastMCP\s*\(/g, "service", "MCP service"],
  ];
  for (const [pattern, role, label] of behaviors)
    for (const m of code.matchAll(pattern)) {
      if (role === "external-use") {
        const module = label.startsWith("Anthropic") ? "anthropic" : "openai";
        const imported = new RegExp(
          `\\b(?:import\\s+${module}\\b|from\\s+${module}\\s+import\\b)`,
        ).test(code);
        if (!imported) continue;
      }
      const argument = text.slice(
        m.index + m[0].length,
        m.index + m[0].length + 300,
      );
      const resourceKey =
        role === "store-use"
          ? argument.match(
              /^\s*(?:\w+\.)?GetConnectionString\(\s*["']([\w:.-]+)["']/,
            )?.[1] ||
            argument.match(
              /^\s*(?:configuration|config|_configuration)\[\s*["']([\w:.-]+)["']/,
            )?.[1]
          : undefined;
      add(m, role, { label, ...(resourceKey ? { resourceKey } : {}) });
    }
  // A local file store requires both read and write operations, not a class name alone.
  if (
    /\b(?:json\.dump|write_text|write_bytes|os\.replace)\s*\(/.test(code) &&
    /\b(?:json\.load|read_text|read_bytes)\s*\(/.test(code) &&
    /\b(?:open|fdopen|write_text|write_bytes|read_text|read_bytes|os\.replace)\s*\(/.test(
      code,
    )
  ) {
    const m = /\b(?:json\.dump|write_text|write_bytes|os\.replace)\s*\(/.exec(
      code,
    );
    add(m, "store-use", { label: "File storage" });
  }
  const seen = new Set();
  return facts.filter((f) => {
    const key = JSON.stringify([
      f.role,
      f.symbol,
      f.module,
      f.alias,
      f.label,
      f.resourceKey,
    ]);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

// Project only evidence-backed internal units. Preserve original interface IDs and reviewer ownership.
export function internalTopology(model) {
  const evidence = new Map(model.evidence.map((e) => [e.id, e]));
  const files = new Map();
  for (const i of model.interfaces) {
    const e = evidence.get(i.evidence[0]);
    if (!e) continue;
    const key = `${i.repository}:${e.path}`;
    if (!files.has(key))
      files.set(key, {
        key,
        path: e.path,
        repository: i.repository,
        parent: i.component,
        items: [],
        facts: [],
      });
    const f = files.get(key);
    f.items.push(i);
    if (i.connection?.kind === "architecture") f.facts.push(i);
  }
  const components = [...model.components],
    owners = new Map(),
    extraFlows = [],
    entities = [],
    gaps = [];
  const specialized = new Map();
  for (const f of files.values()) {
    const behaviors = f.facts.filter((i) =>
      ["worker", "store-use", "external-use", "service"].includes(
        i.connection.role,
      ),
    );
    if (!behaviors.length) continue;
    // A host with HTTP entry points remains the host, even when it creates a thread pool.
    if (f.items.some((i) => i.kind === "http-inbound")) continue;
    const role = behaviors.some((i) => i.connection.role === "worker")
      ? "worker"
      : behaviors.some((i) => i.connection.role === "service")
        ? "service"
        : behaviors.some((i) => i.connection.role === "store-use")
          ? "storage-adapter"
          : "client-adapter";
    const name = path.posix
      .basename(f.path)
      .replace(/\.[^.]+$/, "")
      .replaceAll("_", " ");
    const cid = id("internal-unit", f.repository, f.path);
    components.push({
      id: cid,
      repository: f.repository,
      name,
      sourceRoot: f.path,
      kind: "internal-component",
      internalRole: role,
      declarationEvidence: [...new Set(behaviors.flatMap((i) => i.evidence))],
      resourceKinds: [
        ...new Set(
          behaviors
            .filter((i) => i.connection.role === "store-use")
            .map((i) => i.connection.label),
        ),
      ],
      parentComponentId: f.parent,
      basis:
        "Source-defined internal unit; process ownership and activation require review",
    });
    specialized.set(f.key, cid);
    for (const i of f.items) owners.set(i.id, cid);
  }
  // Separate entry points only when a packaging declaration names a collected module.
  for (const f of files.values())
    for (const entry of f.facts.filter(
      (i) => i.connection.role === "entrypoint",
    )) {
      const target = files.get(
        `${f.repository}:${entry.connection.module.replaceAll(".", "/")}.py`,
      );
      if (!target) continue;
      let cid = specialized.get(target.key);
      if (!cid) {
        cid = id("entry-unit", target.repository, target.path);
        components.push({
          id: cid,
          repository: target.repository,
          sourceRoot: target.path,
          kind: "internal-component",
          parentComponentId: target.parent,
        });
        specialized.set(target.key, cid);
        for (const i of target.items) owners.set(i.id, cid);
      }
      const c = components.find((c) => c.id === cid);
      Object.assign(c, {
        name: entry.connection.label + " CLI",
        internalRole: "entrypoint",
        declarationEvidence: entry.evidence,
      });
    }
  const flow = (source, target, item, protocol, operation, support = []) => {
    if (source === target) return;
    extraFlows.push({
      id: id("internal-flow", item.id, source, target, protocol),
      from: item.id,
      source,
      target,
      protocol,
      operation,
      basis: "static invocation candidate",
      confidence: "medium",
      reason:
        "Source invocation or resource access. Conditional execution, dispatch, effective destination and deployment require review.",
      data: "Unclassified",
      controls: "Not established",
      evidence: [...new Set([...item.evidence, ...support])],
      graphNodeIds: [item.id],
    });
  };
  const resolveModule = (f, name) => {
    let base;
    if (name.startsWith(".")) {
      const dots = name.match(/^\.+/)[0].length;
      base = path.posix.dirname(f.path);
      for (let n = 1; n < dots; n++) base = path.posix.dirname(base);
      base = path.posix.join(base, name.slice(dots).replaceAll(".", "/"));
    } else base = name.replaceAll(".", "/");
    return [base + ".py", base + "/__init__.py"]
      .map((p) => files.get(`${f.repository}:${p}`))
      .filter(Boolean);
  };
  const resolveSymbol = (f, symbol, seen = new Set()) => {
    const key = f.key + ":" + symbol;
    if (seen.has(key) || seen.size > 32) return [];
    seen = new Set(seen).add(key);
    const definitions = f.facts.filter(
      (i) => i.connection.role === "symbol" && i.connection.symbol === symbol,
    );
    const bindings = f.facts.filter(
      (i) =>
        i.connection.role === "import-binding" && i.connection.alias === symbol,
    );
    if (definitions.length && bindings.length) return []; // shadowed or ambiguous
    if (definitions.length === 1)
      return [{ file: f, evidence: definitions[0].evidence }];
    const results = [];
    for (const b of bindings)
      for (const target of resolveModule(f, b.connection.module))
        for (const r of resolveSymbol(target, b.connection.symbol, seen))
          results.push({ ...r, evidence: [...b.evidence, ...r.evidence] });
    return results;
  };
  for (const f of files.values()) {
    for (const item of f.facts) {
      const c = item.connection,
        source = owners.get(item.id) || item.component;
      if (c.role === "symbol-call") {
        let matches = [];
        if (f.path.endsWith(".py")) matches = resolveSymbol(f, c.symbol);
        else
          matches = [...files.values()]
            .filter(
              (t) => t.repository === f.repository && t.parent === f.parent,
            )
            .flatMap((t) =>
              t.facts
                .filter(
                  (i) =>
                    i.connection.role === "symbol" &&
                    i.connection.symbol === c.symbol,
                )
                .map((i) => ({ file: t, evidence: i.evidence })),
            );
        const unique = new Map(matches.map((r) => [r.file.key, r]));
        if (unique.size === 1) {
          const r = [...unique.values()][0],
            target = specialized.get(r.file.key);
          if (target)
            flow(
              source,
              target,
              item,
              "in-process",
              "Invoke internal unit",
              r.evidence,
            );
        }
      }
      if (["store-use", "external-use"].includes(c.role)) {
        if (c.resourceKey) {
          const configs = model.interfaces.filter(
            (i) =>
              i.component === f.parent &&
              i.connection?.kind === "resource" &&
              i.connection.key === c.resourceKey,
          );
          const identities = new Set(configs.map((i) => i.connection.identity));
          if (identities.size === 1) {
            const cfg = configs[0],
              target = id(
                "discovered-resource",
                cfg.connection.protocol,
                cfg.connection.identity,
              );
            if (
              model.connectionDiscovery?.entities?.some((e) => e.id === target)
            ) {
              flow(
                source,
                target,
                item,
                cfg.connection.protocol,
                "Use configured resource",
                configs.flatMap((i) => i.evidence),
              );
              continue;
            }
          }
        }
        gaps.push({
          interfaceId: item.id,
          reason:
            c.role === "store-use"
              ? "resource-identity-unresolved"
              : "provider-endpoint-unresolved",
          candidateCount: 0,
        });
        const target = id("logical-resource", f.repository, f.path, c.label);
        let entity = entities.find((e) => e.id === target);
        if (!entity) {
          entity = {
            id: target,
            name: `${c.label} (${path.posix.basename(f.path).replace(/\.[^.]+$/, "")})`,
            type: c.role === "store-use" ? "store" : "external",
            scope: sourceScope(f.path),
            resourceKind: c.label,
            parentComponentId: f.parent,
            repositories: [f.repository],
            interfaceIds: [],
            evidenceIds: [],
            basis: "static resource use",
            reviewState: "pending",
            description:
              "Logical resource accessed by source. Location, sharing with other resources, activation and effective endpoint are unresolved.",
          };
          entities.push(entity);
        }
        entity.interfaceIds.push(item.id);
        entity.evidenceIds.push(...item.evidence);
        flow(
          source,
          target,
          item,
          c.role === "store-use" ? "storage" : "SDK",
          "Access " + c.label,
        );
      }
    }
  }
  for (const f of files.values()) {
    const proxies = f.facts.filter((i) => i.connection.role === "proxy-target");
    if (!proxies.length) continue;
    const gateway = id("deployment-gateway", f.repository, f.path);
    components.push({
      id: gateway,
      repository: f.repository,
      name: "Reverse proxy",
      sourceRoot: f.path,
      internalRole: "gateway",
      kind: "internal-component",
      basis: "Proxy configuration candidate; deployment unverified",
    });
    for (const p of proxies) {
      owners.set(p.id, gateway);
      const hosts = f.facts.filter(
        (i) =>
          i.connection.role === "host-binding" &&
          i.connection.port === p.connection.port,
      );
      const targets = hosts
        .map((h) => ({
          h,
          component: h.connection.module
            ? files.get(
                `${f.repository}:${h.connection.module.replaceAll(".", "/")}.py`,
              )?.parent
            : model.components.find(
                (c) =>
                  c.repository === f.repository &&
                  c.sourceRoot === h.connection.project,
              )?.id,
        }))
        .filter((x) => x.component);
      if (new Set(targets.map((x) => x.component)).size === 1) {
        const x = targets[0];
        flow(
          gateway,
          x.component,
          p,
          "HTTP",
          "Configured proxy upstream",
          x.h.evidence,
        );
        const edge = extraFlows[extraFlows.length - 1];
        edge.transport = p.connection.transport;
        edge.basis = "static deployment candidate";
        edge.reason =
          "Literal loopback proxy port matches one declared host command in this configuration. Proxy route rewrites and actual deployment remain unverified.";
      } else
        gaps.push({
          interfaceId: p.id,
          reason: "proxy-host-binding-unresolved",
          candidateCount: new Set(targets.map((x) => x.component)).size,
        });
    }
  }
  return {
    ...model,
    components,
    interfaces: model.interfaces.map((i) => ({
      ...i,
      component: owners.get(i.id) || i.component,
    })),
    connectionDiscovery: {
      ...model.connectionDiscovery,
      gaps: [...(model.connectionDiscovery?.gaps || []), ...gaps],
      coverage: {
        ...model.connectionDiscovery?.coverage,
        internalConnections: extraFlows.length,
        internalResolutionGaps: gaps.length,
      },
      flows: [...(model.connectionDiscovery?.flows || []), ...extraFlows],
      entities: [...(model.connectionDiscovery?.entities || []), ...entities],
    },
  };
}
