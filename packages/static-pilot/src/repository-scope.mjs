import { sha } from "./sources.mjs";
import { graphReader } from "./graph-store.mjs";
import { sourceScope } from "./architecture.mjs";

// Imports and candidate call edges support navigation. Parsed definitions are
// review subjects too, so files without routes are not silently omitted.
export const navigationOnly = (i) =>
  i.kind === "architecture" &&
  ["symbol-call", "import-binding"].includes(i.connection?.role);
export function resolveRepositoryScope(model, input) {
  const text = (v, n) => {
    if (typeof v !== "string" || !v.trim() || v.length > 240)
      throw Error("Invalid repository scope " + n);
    return v.trim();
  };
  if (
    !Array.isArray(input.repositories) ||
    !input.repositories.length ||
    input.repositories.length > 100 ||
    new Set(input.repositories).size !== input.repositories.length
  )
    throw Error("Select unique primary repository names");
  const repositories = input.repositories
    .map((r) => text(r, "repository"))
    .sort();
  if (new Set(repositories).size !== repositories.length)
    throw Error("Select unique primary repository names");
  for (const name of repositories)
    if (!model.sources.some((s) => s.name === name))
      throw Error("Repository not in saved graph: " + name);
  const definition = {
    kind: "repositories",
    title: text(input.title, "title"),
    profile: text(input.profile, "profile"),
    repositories,
  };
  const selected = new Set(repositories),
    records = model.interfaces.filter((i) => selected.has(i.repository));
  const interfaces = records.filter((i) => !navigationOnly(i));
  // No endpoint, production-only, file-name or 12-packet cutoff in repository scope.
  return {
    ...definition,
    id: sha(JSON.stringify(definition)).slice(0, 20),
    interfaceIds: interfaces.map((i) => i.id).sort(),
    operationGroups: interfaces.length,
    operations: [],
    supportingRepositories: model.sources
      .filter((s) => !selected.has(s.name))
      .map((s) => s.name),
    navigationRecords: records.length - interfaces.length,
  };
}
export function repositoryInventory(model, scope) {
  const selected = new Set(scope.repositories),
    disk = graphReader(model.sourceGraph);
  if (model.sourceGraph?.storage === "sqlite" && !disk)
    throw Error("Saved graph reader required for repository inventory");
  const graphFiles = disk
    ? [...disk.files(model.sourceGraph.generation)]
    : model.sourceGraph?.files || [];
  const collection = disk
    ? [...disk.inventoryEntries(model.sourceGraph.generation)]
    : model.sources.flatMap((s) =>
        (s.coverage?.entries || []).map((e) => ({ ...e, repository: s.name })),
      );
  const files = new Map(),
    evidence = new Map(model.evidence.map((e) => [e.id, e]));
  const add = (r) => {
    if (!selected.has(r.repository) || !r.path) return;
    const key = JSON.stringify([r.repository, r.path]);
    if (!files.has(key))
      files.set(key, {
        repository: r.repository,
        path: r.path,
        sourceScope: sourceScope(r.path),
        interfaceIds: [],
        navigationRecords: 0,
      });
    return files.get(key);
  };
  for (const r of collection) {
    const f = add(r);
    if (f) {
      f.collectionStatus = r.status;
      f.collectionReason = r.reason || null;
    }
  }
  for (const r of graphFiles) {
    const f = add(r);
    if (f) {
      f.parserStatus = r.status;
      f.parser = r.parser;
    }
  }
  for (const i of model.interfaces.filter((i) => selected.has(i.repository)))
    for (const eid of i.evidence) {
      const r = evidence.get(eid);
      if (!r) continue;
      const f = add(r);
      if (!f) continue;
      if (navigationOnly(i)) f.navigationRecords++;
      else if (!f.interfaceIds.includes(i.id)) f.interfaceIds.push(i.id);
    }
  const rows = [...files.values()].sort(
    (a, b) =>
      a.repository.localeCompare(b.repository) || a.path.localeCompare(b.path),
  );
  const gaps = [];
  for (const f of rows) {
    f.gaps = [];
    if (f.parserStatus && f.parserStatus !== "parsed")
      f.gaps.push("parser:" + f.parserStatus);
    if (
      f.collectionStatus &&
      !["inspected", "included", "read"].includes(f.collectionStatus)
    )
      f.gaps.push("collection:" + f.collectionStatus);
    if (!f.interfaceIds.length) f.gaps.push("no-security-surface-mapping");
    for (const reason of f.gaps)
      gaps.push({
        repository: f.repository,
        path: f.path,
        reason,
        detail:
          reason === "no-security-surface-mapping"
            ? "No identified interface or parsed definition maps this file to a review case. This is not a finding of no security relevance."
            : f.collectionReason ||
              "Review the source or collection/parser limitation before claiming this file assessed.",
      });
  }
  for (const s of model.sources.filter((s) => selected.has(s.name)))
    if (s.status !== "read" || s.coverage?.truncated)
      gaps.push({
        repository: s.name,
        path: null,
        reason: "repository-collection-incomplete",
        detail: "The saved source collection is incomplete.",
      });
  return {
    files: rows,
    gaps,
    repositories: scope.repositories.map((repository) => ({
      repository,
      files: rows.filter((f) => f.repository === repository).length,
      identifiedInterfaces: model.interfaces.filter(
        (i) => i.repository === repository && !navigationOnly(i),
      ).length,
      navigationRecords: model.interfaces.filter(
        (i) => i.repository === repository && navigationOnly(i),
      ).length,
      sourceCoverage: model.sources.find((s) => s.name === repository)
        ?.coverage,
      gapCount: gaps.filter((g) => g.repository === repository).length,
    })),
    interpretation:
      "Whole saved-file inventory for primary repositories. Navigation-only, unsupported and unmapped files remain explicit gaps, not implicitly reviewed. Supporting repositories remain searchable; their whole-repository coverage is not claimed.",
  };
}
