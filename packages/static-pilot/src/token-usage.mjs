import { randomUUID } from "node:crypto";

const count = (v) => (Number.isSafeInteger(v) && v >= 0 ? v : null);
const optional = (v) => (v === undefined ? 0 : count(v));
const sum = (...values) =>
  values.every((v) => v !== null) &&
  Number.isSafeInteger(values.reduce((a, b) => a + b, 0))
    ? values.reduce((a, b) => a + b, 0)
    : null;

// Only numeric usage fields are retained. No provider bodies or credentials.
export function providerUsage(data, provider) {
  let inputTokens, outputTokens, cacheReadTokens, cacheWriteTokens, totalTokens;
  if (provider === "gemini") {
    const u = data.usageMetadata || {};
    inputTokens = sum(
      count(u.promptTokenCount),
      optional(u.toolUsePromptTokenCount),
    );
    outputTokens = sum(
      count(u.candidatesTokenCount),
      optional(u.thoughtsTokenCount),
    );
    cacheReadTokens = optional(u.cachedContentTokenCount);
    cacheWriteTokens = null; // Gemini does not report cache creation in this response.
    totalTokens = count(u.totalTokenCount) ?? sum(inputTokens, outputTokens);
  } else {
    const u = data.usage || {};
    cacheReadTokens = optional(u.cache_read_input_tokens);
    cacheWriteTokens = optional(u.cache_creation_input_tokens);
    inputTokens = sum(count(u.input_tokens), cacheReadTokens, cacheWriteTokens);
    outputTokens = count(u.output_tokens);
    totalTokens = sum(inputTokens, outputTokens);
  }
  return {
    inputTokens,
    outputTokens,
    cacheReadTokens,
    cacheWriteTokens,
    totalTokens,
  };
}

export function ensureLedger(model) {
  model.usageLedger ||= {
    version: 1,
    legacyUnmetered: Boolean(
      model.aiReview && model.aiReview.status !== "skipped",
    ),
    attempts: [],
  };
  return model.usageLedger;
}
export function beginUsageRun(model) {
  const ledger = ensureLedger(model);
  interruptUsage(ledger);
  ledger.lastRunId = randomUUID();
  return ledger.lastRunId;
}
export function beginAttempt(model, config, packet, metadata = {}) {
  const ledger = ensureLedger(model);
  const attempt = {
    id: randomUUID(),
    runId: ledger.lastRunId,
    startedAt: new Date().toISOString(),
    endedAt: null,
    provider: config.provider,
    model: config.model,
    sourceRevision: model.modelRevision,
    batchId: metadata.batchId || "single-request",
    phase: metadata.phase || "single-request",
    repositories: [...new Set(packet.records.map((r) => r.repository))].sort(),
    retry: metadata.retry === true,
    status: "in-flight",
    usage: null,
  };
  ledger.attempts.push(attempt);
  return attempt;
}
export function finishAttempt(attempt, status) {
  attempt.status = status;
  attempt.endedAt = new Date().toISOString();
}
export function interruptUsage(ledger) {
  for (const a of ledger?.attempts || []) {
    if (a.status === "in-flight") finishAttempt(a, "interrupted");
  }
}
export function mergeUsage(previous, incoming, legacyUnmetered = false) {
  if (!previous && !incoming && !legacyUnmetered) return undefined;
  return {
    version: 1,
    legacyUnmetered: Boolean(
      legacyUnmetered || previous?.legacyUnmetered || incoming?.legacyUnmetered,
    ),
    lastRunId: incoming?.lastRunId || previous?.lastRunId,
    attempts: [
      ...new Map(
        [...(previous?.attempts || []), ...(incoming?.attempts || [])].map(
          (a) => [a.id, a],
        ),
      ).values(),
    ],
  };
}
function totals(attempts) {
  const result = {
    requests: attempts.length,
    reportedRequests: 0,
    unknownRequests: 0,
    failedRequests: 0,
    retries: 0,
    inputTokens: 0,
    outputTokens: 0,
    cacheReadTokens: 0,
    cacheWriteTokens: 0,
    totalTokens: 0,
  };
  for (const a of attempts) {
    if (a.usage?.totalTokens != null) result.reportedRequests++;
    else result.unknownRequests++;
    if (["failed", "interrupted"].includes(a.status)) result.failedRequests++;
    if (a.retry) result.retries++;
    for (const key of [
      "inputTokens",
      "outputTokens",
      "cacheReadTokens",
      "cacheWriteTokens",
      "totalTokens",
    ])
      result[key] += count(a.usage?.[key]) ?? 0;
  }
  return result;
}
export function usageSummary(ledger, legacyUnmetered = false) {
  const attempts = ledger?.attempts || [];
  const groups = new Map();
  for (const a of attempts) {
    const group =
      a.repositories.length === 1
        ? a.repositories[0]
        : "Shared cross-repository analysis";
    const key = JSON.stringify([
      a.repositories.length === 1 ? "repository" : "shared",
      group,
    ]);
    if (!groups.has(key))
      groups.set(key, {
        label: group,
        shared: a.repositories.length !== 1,
        attempts: [],
      });
    groups.get(key).attempts.push(a);
  }
  return {
    ...totals(attempts),
    recentAttempts: attempts.slice(-50).reverse(),
    legacyUnmetered: Boolean(legacyUnmetered || ledger?.legacyUnmetered),
    lastRun: totals(attempts.filter((a) => a.runId === ledger?.lastRunId)),
    groups: [...groups.values()].map((g) => ({
      label: g.label,
      shared: g.shared,
      ...totals(g.attempts),
    })),
  };
}
export function usageCsv(ledger) {
  const keys = [
    "id",
    "runId",
    "startedAt",
    "endedAt",
    "provider",
    "model",
    "sourceRevision",
    "batchId",
    "phase",
    "repositories",
    "retry",
    "status",
    "inputTokens",
    "outputTokens",
    "cacheReadTokens",
    "cacheWriteTokens",
    "totalTokens",
  ];
  const cell = (v) =>
    '"' +
    String(v ?? "unknown")
      .replace(/^[\s]*[=+@-]/, "'$&")
      .replaceAll('"', '""') +
    '"';
  return (
    "\uFEFF" +
    [
      keys,
      ...(ledger?.attempts || []).map((a) =>
        keys.map((k) =>
          k === "repositories"
            ? a.repositories.join("; ")
            : k.endsWith("Tokens")
              ? a.usage?.[k]
              : a[k],
        ),
      ),
    ]
      .map((row) => row.map(cell).join(","))
      .join("\r\n")
  );
}
