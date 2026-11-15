import { id, sha } from "./sources.mjs";

// Only literal identities are retained. Credentials, query strings and source excerpts are never stored.
function endpoint(value) {
  if (
    typeof value !== "string" ||
    value.length > 2000 ||
    /\$\{|\$\(|%[A-Za-z_]|\{\{|[\r\n]/.test(value)
  )
    return null;
  try {
    const u = new URL(value);
    if (
      ![
        "http:",
        "https:",
        "amqp:",
        "amqps:",
        "postgres:",
        "postgresql:",
        "mongodb:",
        "redis:",
        "rediss:",
      ].includes(u.protocol)
    )
      return null;
    if (!u.hostname || /[{}\[\]]/.test(u.hostname)) return null;
    return {
      origin: `${u.protocol}//${u.host.toLowerCase()}`,
      path: u.pathname || "/",
      scheme: u.protocol.slice(0, -1),
    };
  } catch {
    return null;
  }
}
function route(value) {
  if (!value || /[?#\r\n]|\[controller\]|\[action\]|\$\{|\$\(/.test(value))
    return null;
  return ("/" + value).replace(/\/{2,}/g, "/").replace(/\/$/, "") || "/";
}
function literal(text) {
  return text.match(/^\s*["']([^"'\n]*)["']/)?.[1];
}

export function interfaceConnection(item, file, offset) {
  const tail = file.text.slice(offset, offset + 1000);
  if (item.protocol === "messaging") {
    const call = tail.slice(tail.indexOf("(") + 1);
    const consume = item.direction === "inbound";
    let channel = call.match(
      /(?:queue|routingKey|routing_key)\s*[:=]\s*["']([^"'\n]+)["']/,
    )?.[1];
    if (
      !channel &&
      /^(?:sendToQueue|consume|BasicConsume(?:Async)?)\b/.test(tail)
    )
      channel = literal(call);
    if (!channel && /^BasicPublish(?:Async)?\b/.test(tail))
      channel = call.match(/^\s*["']["']\s*,\s*["']([^"'\n]+)["']/)?.[1];
    const exchange = call.match(/exchange\s*[:=]\s*["']([^"'\n]*)["']/)?.[1];
    if (exchange) return undefined; // Non-default exchanges require binding/routing semantics.
    if (channel && !/[${}?#]/.test(channel))
      return {
        kind: "message",
        role: consume ? "consume" : "publish",
        channelHash: sha(channel),
      };
    return undefined;
  }
  if (item.protocol !== "HTTP") return undefined;
  if (item.direction === "inbound") {
    let method = item.operation.match(
      /^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b/,
    )?.[1];
    let p = item.operation.slice((method || "").length).trim();
    if (/export\s/.test(tail.slice(0, 30))) {
      const match = file.path.match(/(?:^|\/)app\/(.+)\/route\.[cm]?[jt]sx?$/);
      if (match)
        p =
          "/" +
          match[1]
            .split("/")
            .filter((s) => !/^\(.+\)$/.test(s))
            .join("/")
            .replace(/\[([^\]]+)\]/g, ":$1");
      else return undefined;
    }
    if (/^\[Http/.test(tail)) {
      const prefixes = [
        ...file.text.matchAll(/\[Route\(\s*"([^"\n]+)"\s*\)\]/g),
      ];
      if (prefixes.length === 1) {
        let prefix = prefixes[0][1];
        const controllers = [
          ...file.text.matchAll(/class\s+(\w+)Controller\b/g),
        ];
        if (controllers.length === 1)
          prefix = prefix.replace("[controller]", controllers[0][1]);
        p =
          p === "[controller route]"
            ? prefix
            : p.startsWith("/")
              ? p
              : `${prefix}/${p}`;
      } else if (prefixes.length > 1 || p === "[controller route]")
        return undefined;
    }
    if (file.path.endsWith(".py")) {
      const receiver = tail.match(/^@(\w+)\./)?.[1];
      if (receiver) {
        const definitions = [
          ...file.text.matchAll(/(\w+)\s*=\s*APIRouter\([^)]*\)/g),
        ].filter((m) => m[1] === receiver);
        if (definitions.length === 1) {
          const prefix = definitions[0][0].match(
            /prefix\s*=\s*["']([^"']+)["']/,
          )?.[1];
          if (prefix) p = prefix + "/" + p;
        }
      }
    }
    const pathname = route(p);
    return method && pathname && !/\s|requires review/.test(pathname)
      ? { kind: "http", role: "server", method, path: pathname }
      : undefined;
  }
  if (item.direction !== "outbound") return undefined;
  const opening = tail.indexOf("(");
  if (opening < 0) return undefined;
  const argument = tail.slice(opening + 1);
  if (!/^\s*["'][^"'\n]*["']\s*[,)]/.test(argument)) return undefined;
  const value = literal(argument);
  if (!value) return undefined;
  let method = tail
    .slice(0, opening)
    .match(/get|post|put|delete|patch|head/i)?.[0]
    ?.toUpperCase();
  // fetch defaults to GET only if there is no options expression; explicit literal method is safe to retain.
  if (/^fetch\b/.test(tail)) {
    method = argument
      .match(
        /^\s*['"][^'"\n]*['"]\s*,\s*\{\s*method\s*:\s*['"]([A-Za-z]+)['"]/,
      )?.[1]
      ?.toUpperCase();
    if (!method && /^\s*["'][^"'\n]*["']\s*\)/.test(tail.slice(opening + 1)))
      method = "GET";
  }
  const ep = endpoint(value);
  const pathname = ep?.path || (value.startsWith("/") ? route(value) : null);
  return pathname
    ? {
        kind: "http",
        role: "client",
        method: method || "UNKNOWN",
        path: pathname,
        origin: ep?.origin || null,
      }
    : undefined;
}

// Called only on safely parsed JSON/XML, not arbitrary target configuration scripts.
export function configurationConnection(key, value, pointer) {
  if (typeof value !== "string") return null;
  const ep = endpoint(value);
  if (
    ep &&
    ["http", "https"].includes(ep.scheme) &&
    /url|uri|address|endpoint/i.test(key)
  ) {
    const role = /kestrel|aspnetcore_urls|\/urls$|\/binding/i.test(pointer)
      ? "listener"
      : "base";
    return { kind: "http-config", role, ...ep };
  }
  if (ep && !["http", "https"].includes(ep.scheme)) {
    return {
      kind: "resource",
      protocol: /^amqp/.test(ep.scheme) ? "messaging" : "database",
      identity: sha(`${ep.origin}${ep.path}`),
      label: `${ep.scheme} resource ${sha(`${ep.origin}${ep.path}`).slice(0, 10)}`,
    };
  }
  if (/ConnectionStrings/i.test(pointer)) {
    const host = value
      .match(/(?:^|;)\s*(?:Server|Data Source|Host)\s*=\s*([^;]+)/i)?.[1]
      ?.trim();
    const database = value
      .match(/(?:^|;)\s*(?:Database|Initial Catalog)\s*=\s*([^;]+)/i)?.[1]
      ?.trim();
    if (host && database && !/[${}%]/.test(host + database)) {
      const identity = sha(
        `sql:${host.toLowerCase()}:${database.toLowerCase()}`,
      );
      return {
        kind: "resource",
        protocol: "database",
        identity,
        label: `SQL store ${identity.slice(0, 10)}`,
      };
    }
  }
  return null;
}
function matches(pattern, actual) {
  const a = pattern.split("/"),
    b = actual.split("/");
  return (
    a.length === b.length &&
    a.every((v, i) =>
      /^:\w+$|^\{[\w:]+\}$/.test(v) ? Boolean(b[i]) : v === b[i],
    )
  );
}
export function discoverConnections(model, nodes) {
  const indexed = new Map();
  for (const node of nodes)
    if (node.kind === "interface" && node.connection)
      indexed.set(node.id, node);
  const items = model.interfaces.filter((i) => indexed.has(i.id));
  const configs = items.filter(
    (i) => indexed.get(i.id).connection.kind === "http-config",
  );
  const servers = items.filter(
    (i) => indexed.get(i.id).connection.role === "server",
  );
  const flows = [],
    entities = [],
    gaps = [];
  for (const client of items.filter(
    (i) => indexed.get(i.id).connection.role === "client",
  )) {
    const c = indexed.get(client.id).connection;
    const bases = configs.filter(
      (i) =>
        i.component === client.component &&
        indexed.get(i.id).connection.role === "base",
    );
    const uniqueBases = [
      ...new Set(bases.map((i) => indexed.get(i.id).connection.origin)),
    ];
    const origin =
      c.origin || (uniqueBases.length === 1 ? uniqueBases[0] : null);
    const candidates = servers.filter((server) => {
      const s = indexed.get(server.id).connection;
      if (s.method !== c.method || !matches(s.path, c.path)) return false;
      const listeners = configs.filter(
        (i) =>
          i.component === server.component &&
          indexed.get(i.id).connection.role === "listener",
      );
      return (
        !origin ||
        !listeners.length ||
        listeners.some((i) => indexed.get(i.id).connection.origin === origin)
      );
    });
    // Collapse duplicated contracts for one component, but never guess between components.
    const targets = new Set(candidates.map((i) => i.component));
    if (targets.size !== 1) {
      gaps.push({
        interfaceId: client.id,
        reason: targets.size ? "ambiguous-route" : "no-route-match",
        candidateCount: targets.size,
      });
      continue;
    }
    const target = candidates[0];
    const listeners = configs.filter(
      (i) =>
        i.component === target.component &&
        indexed.get(i.id).connection.role === "listener" &&
        indexed.get(i.id).connection.origin === origin,
    );
    const exact = Boolean(origin && listeners.length);
    const configEvidence = [...(c.origin ? [] : bases), ...listeners].flatMap(
      (i) => i.evidence,
    );
    flows.push({
      id: id("discovered-flow", client.id, target.id),
      from: client.id,
      to: target.id,
      source: client.component,
      target: target.component,
      operation: `${c.method} ${c.path}`,
      protocol: "HTTP",
      basis: exact ? "static endpoint match" : "inferred route match",
      reason: exact
        ? "Literal client origin, listener origin, method and route match. Deployment and reachability require review."
        : "Method and route match one source component. Host identity, route mounts, proxy rewrites and deployment require review.",
      confidence: exact ? "high" : "medium",
      data: "Unclassified",
      controls: "Not established",
      evidence: [
        ...new Set([
          ...client.evidence,
          ...candidates.flatMap((i) => i.evidence),
          ...configEvidence,
        ]),
      ],
      graphNodeIds: [client.id, target.id],
    });
  }
  for (const item of items) {
    const c = indexed.get(item.id).connection;
    if (c.kind !== "resource") continue;
    const target = id("discovered-resource", c.protocol, c.identity);
    let entity = entities.find((e) => e.id === target);
    if (!entity) {
      entity = {
        id: target,
        name: c.label,
        type: c.protocol === "messaging" ? "broker" : "store",
        repositories: [],
        interfaceIds: [],
        evidenceIds: [],
        basis: "static configuration",
        reviewState: "pending",
        description:
          "Shared literal resource identity. Configuration use, deployment and permissions require review.",
      };
      entities.push(entity);
    }
    entity.repositories = [
      ...new Set([...entity.repositories, item.repository]),
    ];
    entity.interfaceIds.push(item.id);
    entity.evidenceIds.push(...item.evidence);
    flows.push({
      id: id("resource-flow", item.id, target),
      from: item.id,
      source: item.component,
      target,
      protocol: c.protocol,
      operation: "Configured resource reference",
      basis: "static configuration",
      reason: entity.description,
      confidence: "medium",
      data: "Unclassified",
      controls: "Not established",
      evidence: item.evidence,
      graphNodeIds: [item.id],
    });
  }
  for (const item of items) {
    const c = indexed.get(item.id).connection;
    if (c.kind !== "message") continue;
    const brokers = items.filter(
      (i) =>
        i.component === item.component &&
        indexed.get(i.id).connection.kind === "resource" &&
        indexed.get(i.id).connection.protocol === "messaging",
    );
    const identities = [
      ...new Set(brokers.map((i) => indexed.get(i.id).connection.identity)),
    ];
    if (identities.length !== 1) {
      gaps.push({
        interfaceId: item.id,
        reason: "broker-identity-unresolved",
        candidateCount: identities.length,
      });
      continue;
    }
    const target = id("discovered-queue", identities[0], c.channelHash);
    let entity = entities.find((e) => e.id === target);
    if (!entity) {
      entity = {
        id: target,
        name: `Message queue ${c.channelHash.slice(0, 10)}`,
        type: "broker",
        repositories: [],
        interfaceIds: [],
        evidenceIds: [],
        basis: "static queue candidate",
        reviewState: "pending",
        description:
          "Literal queue and one configured broker identity. Verify that the call uses this broker and the default exchange.",
      };
      entities.push(entity);
    }
    entity.repositories = [
      ...new Set([...entity.repositories, item.repository]),
    ];
    entity.interfaceIds.push(item.id);
    entity.evidenceIds.push(...item.evidence);
    const inbound = c.role === "consume";
    flows.push({
      id: id("queue-flow", item.id, target),
      from: inbound ? undefined : item.id,
      to: inbound ? item.id : undefined,
      source: inbound ? target : item.component,
      target: inbound ? item.component : target,
      protocol: "messaging",
      operation: inbound ? "Consume queue" : "Publish to queue",
      basis: "static queue candidate",
      confidence: "medium",
      reason: entity.description,
      data: "Unclassified",
      controls: "Not established",
      evidence: [...item.evidence, ...brokers.flatMap((i) => i.evidence)],
      graphNodeIds: [item.id],
    });
  }
  return {
    version: 1,
    graphFingerprint: model.sourceGraph.fingerprint,
    flows,
    entities,
    gaps,
    coverage: {
      indexedInterfaces: indexed.size,
      httpClients: items.filter(
        (i) => indexed.get(i.id).connection.role === "client",
      ).length,
      connectedFlows: flows.length,
      unresolvedClients: gaps.length,
    },
    limitations: [
      "Static candidates do not prove runtime reachability or trust boundaries.",
      "Dynamic URLs, DI, route mounts, broker topology and environment overrides may remain unresolved.",
      "Route-only matches are hypotheses; matching a protocol or repository name never creates a connection.",
    ],
  };
}

// A bounded same-file wrapper adapter: AST resolution supplies the caller and unique function.
export function wrapperConnection(callText, wrapperText) {
  const parameter = wrapperText.match(
    /function\s+\w+(?:<[^>]+>)?\s*\(\s*(\w+)/,
  )?.[1];
  if (!parameter || !/\bfetch\s*\(/.test(wrapperText)) return null;
  const direct = new RegExp(`fetch\\s*\\(\\s*${parameter}\\s*[,)]`).test(
    wrapperText,
  );
  const template = wrapperText.match(
    /(?:const|let)\s+(\w+)\s*=\s*`\$\{\w+\}\$\{(\w+)\}`/,
  );
  const viaUrl =
    template &&
    template[2] === parameter &&
    new RegExp(`fetch\\s*\\(\\s*${template[1]}\\s*[,)]`).test(wrapperText);
  if (!direct && !viaUrl) return null;
  const args = callText.slice(callText.indexOf("(") + 1);
  let m = args.match(/^\s*(['"`])([\s\S]*?)\1\s*([,)])/);
  if (!m || !m[2].startsWith("/") || m[2].length > 500) return null;
  let pathname = m[2]
    .replace(/\$\{qs\([^}]*\)\}$/, "")
    .replace(/\$\{[^}]+\}/g, "{parameter}");
  pathname = route(pathname);
  if (!pathname) return null;
  const method =
    m[3] === ")"
      ? "GET"
      : args
          .slice(m[0].length)
          .match(/^\s*\{\s*method\s*:\s*['"]([A-Za-z]+)['"]/)?.[1]
          ?.toUpperCase();
  if (!method) return null;
  return {
    kind: "http",
    role: "client",
    method,
    path: pathname,
    origin: null,
    via: "unique same-file fetch wrapper; binding and deployment require review",
  };
}
