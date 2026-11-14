import path from "node:path";
import { createRequire } from "node:module";
import TreeSitter from "@vscode/tree-sitter-wasm";
import { id, sha } from "./sources.mjs";

const require = createRequire(import.meta.url);
const { Parser, Language } = TreeSitter;
const grammars = {
  ".cs": "c-sharp",
  ".c": "cpp",
  ".h": "cpp",
  ".cc": "cpp",
  ".cpp": "cpp",
  ".hpp": "cpp",
  ".js": "javascript",
  ".mjs": "javascript",
  ".jsx": "javascript",
  ".ts": "typescript",
  ".tsx": "tsx",
};
const types = new Set([
  "class_declaration",
  "struct_declaration",
  "interface_declaration",
  "record_declaration",
  "class_specifier",
  "struct_specifier",
]);
const functions = new Set([
  "method_declaration",
  "constructor_declaration",
  "local_function_statement",
  "function_declaration",
  "function_definition",
  "method_definition",
  "arrow_function",
  "function_expression",
]);
const calls = new Set(["invocation_expression", "call_expression"]);
const languages = new Map();
const localLinks = new WeakMap();
let initialized;
export const GRAPH_LIMITS = {
  nodes: 100000,
  edges: 200000,
  perFile: 5000,
  parseMilliseconds: 1000,
};
const identifier = (value) =>
  /^[\p{L}\p{N}_$@.:<>~ -]{1,200}$/u.test(value || "")
    ? value
    : "[dynamic or unnamed]";
function declarationName(node) {
  let name = node.childForFieldName("name");
  if (!name && node.parent?.type === "variable_declarator")
    name = node.parent.childForFieldName("name");
  let decl = node.childForFieldName("declarator");
  for (let n = 0; !name && decl && n < 8; n++) {
    if (
      ["identifier", "field_identifier", "qualified_identifier"].includes(
        decl.type,
      )
    ) {
      name = decl;
      break;
    }
    decl = decl.childForFieldName("declarator");
  }
  return identifier(name?.text);
}
export function createSourceGraph() {
  return {
    version: "source-graph-1",
    parser: "tree-sitter-wasm-0.3.1",
    nodes: [],
    edges: [],
    files: [],
    limits: GRAPH_LIMITS,
    coverage: {
      parsed: 0,
      syntaxErrors: 0,
      unsupported: 0,
      failed: 0,
      limited: 0,
    },
    limitations: [
      "Syntax graph, not a compiler-resolved call graph or runtime data flow.",
      "Call targets remain candidates; overloads, dependency injection, inheritance, macros and dynamic dispatch are not resolved.",
      "Repository and project containment never imply trust boundaries.",
      "File collection and graph limits may leave code unexamined; inspect both ledgers.",
    ],
  };
}
export async function addSourceGraph(graph, source, files, result, sourceRoot) {
  initialized ??= Parser.init();
  await initialized;
  const add = (node) => {
    if (graph.nodes.length >= GRAPH_LIMITS.nodes) return null;
    graph.nodes.push(node);
    return node;
  };
  const edge = (from, to, kind, basis = "syntax-supported") => {
    if (from && to && graph.edges.length < GRAPH_LIMITS.edges)
      graph.edges.push({
        id: id("graph-edge", from, to, kind),
        from,
        to,
        kind,
        basis,
      });
    else if (from && to) graph.coverage.edgeLimitReached = true;
  };
  const repo = add({
    id: id("graph-repo", source.name),
    kind: "repository",
    repository: source.name,
    name: source.name,
  });
  const interfacesByFile = new Map();
  const evidence = new Map(result.evidence.map((e) => [e.id, e]));
  for (const i of result.interfaces) {
    const e = evidence.get(i.evidence[0]);
    if (!e) continue;
    if (!interfacesByFile.has(e.path)) interfacesByFile.set(e.path, []);
    interfacesByFile.get(e.path).push({ item: i, evidence: e });
  }
  const fileNodes = new Map();
  if (!localLinks.has(graph))
    localLinks.set(graph, { files: new Map(), references: [] });
  const links = localLinks.get(graph);
  const localRoot =
    source.source !== "github" && sourceRoot
      ? path.resolve(sourceRoot, source.localPath || source.name)
      : null;
  for (const file of files) {
    const fileNode = add({
      id: id("graph-file", source.name, file.path),
      kind: "file",
      name: file.path,
      repository: source.name,
      path: file.path,
      line: 1,
      endLine: file.text.split("\n").length,
      blobSha256: file.hash,
    });
    if (!fileNode) {
      graph.coverage.limited++;
      continue;
    }
    fileNodes.set(file.path, fileNode);
    if (localRoot)
      links.files.set(path.resolve(localRoot, file.path), fileNode.id);
    edge(repo?.id, fileNode.id, "contains");
    const grammar = grammars[path.posix.extname(file.path).toLowerCase()];
    const entry = {
      repository: source.name,
      path: file.path,
      status: "unsupported-language",
      parser: grammar || null,
      symbols: 0,
      calls: 0,
    };
    graph.files.push(entry);
    const symbols = [],
      callSites = [];
    if (!grammar) graph.coverage.unsupported++;
    else {
      let parser, tree;
      try {
        if (!languages.has(grammar))
          languages.set(
            grammar,
            await Language.load(
              require.resolve(
                `@vscode/tree-sitter-wasm/wasm/tree-sitter-${grammar}.wasm`,
              ),
            ),
          );
        parser = new Parser();
        parser.setLanguage(languages.get(grammar));
        const deadline = Date.now() + GRAPH_LIMITS.parseMilliseconds;
        tree = parser.parse(file.text, null, {
          progressCallback: () => Date.now() > deadline,
        });
        if (!tree) throw new Error("parse limit");
        entry.status = tree.rootNode.hasError ? "syntax-errors" : "parsed";
        graph.coverage[tree.rootNode.hasError ? "syntaxErrors" : "parsed"]++;
        const stack = [
          { node: tree.rootNode, scope: fileNode.id, callable: null },
        ];
        let count = 0,
          visited = 0;
        while (stack.length) {
          if (
            count >= GRAPH_LIMITS.perFile ||
            graph.nodes.length >= GRAPH_LIMITS.nodes ||
            ++visited > 200000 ||
            Date.now() > deadline + 1000
          ) {
            entry.status = "graph-limit";
            graph.coverage.limited++;
            break;
          }
          const { node, scope, callable } = stack.pop();
          let nextScope = scope,
            nextCallable = callable;
          const location = {
            repository: source.name,
            path: file.path,
            line: node.startPosition.row + 1,
            endLine: node.endPosition.row + 1,
            start: node.startIndex,
            end: node.endIndex,
            blobSha256: file.hash,
          };
          if (types.has(node.type) || functions.has(node.type)) {
            const symbol = add({
              id: id(
                "graph-symbol",
                source.name,
                file.path,
                node.startIndex,
                node.type,
              ),
              kind: functions.has(node.type) ? "function" : "type",
              name: declarationName(node),
              parent: scope,
              ...location,
              basis: "syntax-supported declaration",
            });
            if (symbol) {
              count++;
              entry.symbols++;
              symbols.push(symbol);
              edge(scope, symbol.id, "declares");
              nextScope = symbol.id;
              if (symbol.kind === "function") nextCallable = symbol.id;
            }
          } else if (calls.has(node.type)) {
            const fn = node.childForFieldName("function");
            const name =
              fn?.childForFieldName("name") ||
              fn?.childForFieldName("property") ||
              fn?.childForFieldName("field");
            const callee = identifier(name?.text || fn?.text);
            const receiver =
              fn?.childForFieldName("expression") ||
              fn?.childForFieldName("object") ||
              fn?.childForFieldName("argument");
            const call = add({
              id: id("graph-call", source.name, file.path, node.startIndex),
              kind: "call",
              name: callee,
              receiver: identifier(receiver?.text || ""),
              unqualified:
                fn?.type === "identifier" ||
                /^this(?:\.|->)/.test(fn?.text || ""),
              parent: callable || scope,
              ...location,
              basis: "syntax-supported call site; target unresolved",
            });
            if (call) {
              count++;
              entry.calls++;
              callSites.push(call);
              edge(callable || scope, call.id, "contains-call");
            }
          }
          for (let n = node.namedChildCount - 1; n >= 0; n--)
            stack.push({
              node: node.namedChild(n),
              scope: nextScope,
              callable: nextCallable,
            });
        }
        const byId = new Map(symbols.map((s) => [s.id, s]));
        for (const call of callSites) {
          if (!call.unqualified) continue;
          const owner = byId.get(call.parent);
          const candidates = symbols.filter(
            (s) =>
              s.kind === "function" &&
              s.name === call.name &&
              s.parent === (owner?.parent || fileNode.id),
          );
          if (candidates.length === 1)
            edge(
              call.id,
              candidates[0].id,
              "candidate-call-target",
              "unique same-file enclosing-scope name; binding unverified",
            );
        }
      } catch {
        entry.status = "parse-failed-or-timed-out";
        graph.coverage.failed++;
      } finally {
        tree?.delete();
        parser?.delete();
      }
    }
    for (const { item, evidence: e } of interfacesByFile.get(file.path) || []) {
      const owner = Number.isInteger(e.offset)
        ? symbols
            .filter(
              (s) =>
                s.kind === "function" &&
                s.start <= e.offset &&
                s.end > e.offset,
            )
            .sort((a, b) => a.end - a.start - (b.end - b.start))[0]
        : null;
      const n = add({
        id: item.id,
        kind: "interface",
        name: item.operation,
        repository: source.name,
        path: file.path,
        line: e.line,
        endLine: e.line,
        blobSha256: file.hash,
        parent: owner?.id || fileNode.id,
        evidenceIds: item.evidence,
        basis: item.basis,
      });
      if (n)
        edge(
          n.parent,
          n.id,
          "contains-interface",
          owner
            ? "line-range association; enforcement unverified"
            : "same file; callable unresolved",
        );
    }
  }
  for (const dependency of result.dependencies) {
    const fileNode = fileNodes.get(dependency.path);
    const n = add({
      id: id(
        "graph-dependency",
        source.name,
        dependency.path,
        dependency.pointer,
        dependency.name,
      ),
      kind: "dependency",
      name: dependency.name,
      repository: source.name,
      path: dependency.path,
      pointer: dependency.pointer,
      line: 1,
      basis: dependency.basis,
    });
    if (n)
      edge(
        fileNode?.id,
        n.id,
        "declares-dependency",
        "source declaration; consumer and runtime binding unverified",
      );
    if (
      n &&
      localRoot &&
      dependency.pointer?.includes("ProjectReference") &&
      !dependency.name.includes("$(")
    )
      links.references.push({
        from: n.id,
        target: path.resolve(
          localRoot,
          path.posix.dirname(dependency.path),
          dependency.name.replaceAll("\\", "/"),
        ),
      });
  }
}
export function finishSourceGraph(graph) {
  const links = localLinks.get(graph);
  for (const reference of links?.references || []) {
    const to = links.files.get(reference.target);
    if (to && graph.edges.length < GRAPH_LIMITS.edges)
      graph.edges.push({
        id: id("project-reference", reference.from, to),
        from: reference.from,
        to,
        kind: "project-reference",
        basis:
          "literal project path names a collected file; build conditions and runtime use unverified",
      });
  }
  localLinks.delete(graph);
  const ids = new Set(graph.nodes.map((n) => n.id));
  graph.edges = graph.edges.filter((e) => ids.has(e.from) && ids.has(e.to));
  graph.fingerprint = sha(
    JSON.stringify({
      nodes: graph.nodes,
      edges: graph.edges,
      files: graph.files,
    }),
  );
  return graph;
}
export function graphContexts(graph) {
  const contexts = new Map();
  if (!graph) return contexts;
  const nodes = new Map(graph.nodes.map((n) => [n.id, n]));
  const byParent = new Map();
  for (const n of graph.nodes) {
    if (!byParent.has(n.parent)) byParent.set(n.parent, []);
    byParent.get(n.parent).push(n);
  }
  for (const n of graph.nodes.filter((n) => n.kind === "interface")) {
    const owner = nodes.get(n.parent);
    const peers = byParent.get(n.parent) || [];
    contexts.set(n.id, {
      graphFingerprint: graph.fingerprint,
      owner: owner
        ? {
            id: owner.id,
            kind: owner.kind,
            name: owner.name,
            path: owner.path,
            line: owner.line,
          }
        : null,
      calls:
        owner?.kind === "function"
          ? peers
              .filter((p) => p.kind === "call")
              .slice(0, 12)
              .map((p) => ({
                id: p.id,
                name: p.name,
                line: p.line,
                target: "unresolved",
              }))
          : [],
      nearbyInterfaceIds: peers
        .filter((p) => p.kind === "interface")
        .map((p) => p.id)
        .slice(0, 12),
      basis:
        "syntax and line association only; no call-target, control-enforcement or data-flow proof",
    });
  }
  return contexts;
}
