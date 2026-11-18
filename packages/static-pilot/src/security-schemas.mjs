// Provider-side shape constraints supplement, never replace, source/CWE validation.
const text = { type: "string" };
const list = (items) => ({ type: "array", items });
const object = (properties) => ({
  type: "object",
  properties,
  required: Object.keys(properties),
  additionalProperties: false,
});
const enumeration = (values) => ({ type: "string", enum: values });
const location = {
  recordId: text,
  startLine: { type: "integer" },
  endLine: { type: "integer" },
};
export const CWE_RESPONSE_SCHEMA = object({
  findings: list(
    object({
      cwe: { type: ["string", "null"] },
      kind: enumeration([
        "code-weakness",
        "control-gap",
        "excessive-authority",
        "attack-path",
        "recovery-gap",
        "security-design",
      ]),
      targetIds: list(text),
      title: text,
      explanation: text,
      preconditions: text,
      counterEvidence: text,
      remediation: text,
      locations: list(object(location)),
    }),
  ),
  limitations: list(text),
  targetReviews: list(
    object({
      targetId: text,
      status: enumeration([
        "reviewed",
        "needs-context",
        "not-applicable-to-packet",
      ]),
      rationale: text,
      locations: list(object(location)),
    }),
  ),
});
export const SECURITY_RESPONSE_SCHEMA = object({
  assessment: enumeration(["static-supported", "ruled-out", "needs-context"]),
  actorKind: enumeration([
    "external-attacker",
    "malicious-insider",
    "compromised-workload",
    "authorized-agent",
    "unknown",
  ]),
  actor: text,
  initialAccess: text,
  input: text,
  impact: text,
  trace: list(
    object({
      ...location,
      role: enumeration(["input", "transform", "control", "sink"]),
      reason: text,
    }),
  ),
  controls: list(object({ ...location, reason: text })),
  counterEvidence: text,
  missingEvidence: list(text),
  followUp: list(
    object({
      repository: text,
      path: text,
      line: { type: "integer" },
      reason: text,
    }),
  ),
  remediation: object(
    Object.fromEntries(
      [
        "codeFix",
        "interimControl",
        "residualRisk",
        "recovery",
        "owner",
        "approval",
        "validation",
        "rollback",
      ].map((k) => [k, text]),
    ),
  ),
  severityChangeConditions: text,
});
