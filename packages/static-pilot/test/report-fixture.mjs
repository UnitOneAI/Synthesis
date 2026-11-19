import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { analyze } from "../src/engine.mjs";
import { sha } from "../src/sources.mjs";
export async function reportFixture() {
  const dir = await fs.realpath(
    await fs.mkdtemp(path.join(os.tmpdir(), "synthesis-evidence-report-")),
  );
  const root = path.join(dir, "sources"),
    workspace = path.join(dir, "workspace");
  await fs.mkdir(path.join(root, "service"), { recursive: true });
  const code =
    '# <script>alert("source")</script>\nimport requests\nrequests.get("https://example.test", verify=False)\n# context\n';
  await fs.writeFile(path.join(root, "service", "app.py"), code);
  const manifest = {
    title: "Static review fixture",
    profile: "test",
    repositories: [{ name: "service" }],
  };
  const model = await analyze(manifest, { sourceRoot: root });
  const ref = {
    repository: "service",
    path: "app.py",
    line: 3,
    endLine: 3,
    blobSha256: sha(code),
    sourceScope: "production-candidate",
  };
  model.cweReview = {
    basedOnRevision: model.modelRevision,
    status: "completed",
    findings: [
      {
        id: "scan",
        ...ref,
        cwe: "CWE-295",
        title: "Certificate validation disabled",
        message: "Certificate verification is disabled.",
        status: "needs-review",
        recommendation: "Use certificate validation.",
      },
    ],
    repositories: [],
    rulePack: { rules: [] },
    tokens: 0,
  };
  model.cweModelReview = {
    basedOnRevision: model.modelRevision,
    status: "partial",
    findings: [
      {
        id: "model",
        cwe: "CWE-295",
        title: "Conditional certificate verification bypass",
        explanation: "Inspect effective TLS controls.",
        locations: [ref, { ...ref, path: "missing.py" }],
        status: "needs-review",
        remediation: "Verify certificates and hostnames.",
        counterEvidence: "Deployment configuration remains unknown.",
      },
    ],
    completedBatches: 1,
    totalBatches: 12,
    pendingBatches: 11,
    repositories: [],
    gaps: [],
    batches: [],
    plan: [],
  };
  return { dir, root, workspace, manifest, model, ref };
}
