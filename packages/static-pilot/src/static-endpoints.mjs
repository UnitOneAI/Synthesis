// Bounded expression interpretation. No evaluation, imports or target execution.
const escaped = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
function firstArgument(text) {
  let depth = 0,
    quote = "";
  for (let i = 0; i < Math.min(text.length, 2000); i++) {
    const c = text[i];
    if (quote) {
      if (c === "\\") i++;
      else if (c === quote) quote = "";
      continue;
    }
    if (c === '"' || c === "'") {
      quote = c;
      continue;
    }
    if (c === "(" || c === "[") depth++;
    if (c === ")" || c === "]") {
      if (depth === 0) return text.slice(0, i);
      depth--;
    }
    if (c === "," && depth === 0) return text.slice(0, i);
  }
  return null;
}
function expression(expr, text, before, seen = new Set()) {
  expr = expr?.trim();
  if (!expr || expr.length > 1500 || seen.size >= 6) return null;
  // Escaped strings and interpolation remain unresolved rather than being misdecoded.
  if (/^["'][^"'\\\r\n]*["']$/.test(expr))
    return { value: expr.slice(1, -1), offsets: [] };
  const uri = expr.match(/^new\s+Uri\((.*)\)$/s);
  if (uri) return expression(uri[1], text, before, seen);
  const config =
    expr.match(
      /^(?:\w+\.)?(?:Configuration|configuration|_configuration|config)\s*\[\s*"([\w:.-]+)"\s*\]$/,
    ) ||
    expr.match(
      /^(?:ConfigurationManager|WebConfigurationManager)\.AppSettings\[\s*"([\w:.-]+)"\s*\]$/,
    );
  if (config) return { configKey: config[1], offsets: [] };
  const concat = expr.match(/^(.*?)\s*\+\s*("[^"\\\n]*"|'[^'\\\n]*')$/s);
  if (concat) {
    const head = expression(concat[1], text, before, seen);
    const tail = concat[2].slice(1, -1);
    if (head?.value !== undefined) return { ...head, value: head.value + tail };
    if (head?.configKey) return { ...head, suffix: (head.suffix || "") + tail };
  }
  if (!/^[A-Za-z_]\w*$/.test(expr) || seen.has(expr)) return null;
  if (
    new RegExp(
      `(?:[,(]\\s*(?:string|Uri|object|var)\\s+${escaped(expr)}\\b|function\\s*\\w*\\s*\\([^)]*\\b${escaped(expr)}\\b|\\(\\s*${escaped(expr)}\\s*\\)\\s*=>)`,
    ).test(text)
  )
    return null;
  // One assignment in the whole file; reject mutation and shadowed declarations.
  const assignments = [
    ...text.matchAll(
      new RegExp(`(?<![\\w.])${escaped(expr)}\\s*=(?!=)\\s*([^;\\n]+)`, "g"),
    ),
  ];
  if (
    assignments.length !== 1 ||
    assignments[0].index >= before ||
    new RegExp(`\\b${escaped(expr)}\\s*(?:\\+=|\\?\\?=|\\+\\+|--)`).test(text)
  )
    return null;
  const next = expression(
    assignments[0][1],
    text,
    assignments[0].index,
    new Set([...seen, expr]),
  );
  return next
    ? { ...next, offsets: [...next.offsets, assignments[0].index] }
    : null;
}
function pythonFunctionScope(text, offset) {
  const definitions = [
    ...text.matchAll(/^([ \t]*)(?:async\s+)?def\s+\w+\s*\(/gm),
  ].filter((m) => m.index < offset);
  for (const def of definitions.reverse()) {
    const header = text
      .slice(def.index, Math.min(offset, def.index + 5000))
      .match(/\)\s*(?:->[^:\n]+)?\s*:\s*\n/);
    if (!header) continue;
    const bodyStart = def.index + header.index + header[0].length;
    let end = text.length;
    for (const line of text
      .slice(bodyStart)
      .matchAll(/^([ \t]*)(\S[^\n]*)/gm)) {
      if (line[1].length <= def[1].length) {
        end = bodyStart + line.index;
        break;
      }
    }
    if (offset < end)
      return { text: text.slice(def.index, end), offset: def.index };
  }
  return { text, offset: 0 };
}

export function symbolicHttpConnection(item, file, offset) {
  if (item.direction !== "outbound" || item.protocol !== "HTTP") return null;
  const tail = file.text.slice(offset, offset + 2500);
  const op = tail.match(
    /^(GetAsync|GetStringAsync|PostAsync|PutAsync|DeleteAsync|PatchAsync|SendAsync|fetch|axios\.(?:get|post|put|delete)|(?:requests|httpx|session|client)\.(?:get|post|put|delete|patch))\s*\(/,
  );
  if (!op) return null;
  let arg = firstArgument(tail.slice(op[0].length)),
    method;
  if (arg === null) return null;
  let requestOffset;
  if (op[1] === "SendAsync") {
    const assignments = [
      ...file.text.matchAll(
        new RegExp(
          `\\b${escaped(arg.trim())}\\s*=(?!=)\\s*new\\s+HttpRequestMessage\\(\\s*HttpMethod\\.(Get|Post|Put|Delete|Patch|Head|Options)\\s*,`,
          "g",
        ),
      ),
    ];
    if (
      !/^\w+$/.test(arg.trim()) ||
      assignments.length !== 1 ||
      assignments[0].index >= offset
    )
      return null;
    const anyAssignments = [
      ...file.text.matchAll(
        new RegExp(`\\b${escaped(arg.trim())}\\s*=(?!=)`, "g"),
      ),
    ];
    if (
      anyAssignments.length !== 1 ||
      new RegExp(`\\b${escaped(arg.trim())}\\.(?:RequestUri|Method)\\s*=`).test(
        file.text,
      )
    )
      return null;
    const m = assignments[0];
    method = m[1].toUpperCase();
    requestOffset = m.index;
    arg = firstArgument(file.text.slice(m.index + m[0].length));
  } else if (op[1] === "fetch") {
    const rest = tail.slice(op[0].length + arg.length);
    method = /^\s*\)/.test(rest)
      ? "GET"
      : rest
          .match(
            /^\s*,\s*\{\s*method\s*:\s*["'](GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)["']/i,
          )?.[1]
          ?.toUpperCase();
  } else method = op[1].match(/get|post|put|delete|patch/i)?.[0].toUpperCase();
  if (!method) return null;
  const scope = file.path.endsWith(".py")
    ? pythonFunctionScope(file.text, offset)
    : { text: file.text, offset: 0 };
  if (
    file.path.endsWith(".py") &&
    /^\w+$/.test(arg?.trim()) &&
    new RegExp(`def\\s+\\w+\\s*\\([^)]*\\b${escaped(arg.trim())}\\b`).test(
      scope.text,
    )
  )
    return null;
  const value = expression(
    arg,
    scope.text,
    (requestOffset ?? offset) - scope.offset,
  );
  if (value) value.offsets = value.offsets.map((n) => n + scope.offset);
  if (!value) return null;
  if (requestOffset !== undefined) value.offsets.push(requestOffset);
  const receiver = file.text
    .slice(Math.max(0, offset - 100), offset)
    .match(/\b(\w+)\.$/)?.[1];
  let base;
  if (receiver) {
    const assignments = [
      ...file.text.matchAll(
        new RegExp(
          `\\b${escaped(receiver)}\\.BaseAddress\\s*=(?!=)\\s*([^;\\n]+)`,
          "g",
        ),
      ),
    ];
    if (assignments.length > 1)
      return { kind: "http-unresolved", reason: "ambiguous-base-address" };
    if (assignments.length === 1) {
      if (assignments[0].index >= offset)
        return {
          kind: "http-unresolved",
          reason: "base-address-order-unresolved",
        };
      base = expression(assignments[0][1], file.text, assignments[0].index);
      if (!base)
        return {
          kind: "http-unresolved",
          reason: "base-address-expression-unresolved",
        };
      base.offsets.push(assignments[0].index);
    }
  }
  // Only endpoint/path values may leave this temporary interpreter.
  const safe = (v) =>
    !v ||
    ((v.value === undefined ||
      /^(?:https?:\/\/|\/?[A-Za-z0-9_.{}-])/.test(v.value)) &&
      !/[\r\n]/.test(v.value || ""));
  if (!safe(value) || !safe(base)) return null;
  return {
    kind: "http-symbolic",
    role: "client",
    method,
    value,
    base,
    resolution: "bounded source expression",
  };
}
