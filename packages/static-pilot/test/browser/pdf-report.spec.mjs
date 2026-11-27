import { test, expect } from "@playwright/test";
import fs from "node:fs/promises";
import path from "node:path";
import { reportFixture } from "../report-fixture.mjs";
import { workspaceStore } from "../../src/workspace-store.mjs";
import { serve } from "../../src/server.mjs";

test("CWE PDF retains verified evidence; unrun STRIDE PDF does not present planning registers as results", async ({
  page,
  context,
}, testInfo) => {
  const f = await reportFixture();
  let app;
  const errors = [];
  try {
    const store = await workspaceStore(f.root, f.workspace);
    await store.save({ manifest: f.manifest, model: f.model });
    await store.close();
    app = await serve({
      sourceRoot: f.root,
      workspace: f.workspace,
      persist: true,
      port: 0,
      quiet: true,
    });
    await page.goto(app.url);
    await page
      .getByRole("button", { name: "Open saved graph", exact: true })
      .click();
    await page
      .getByRole("button", { name: "5 · CWE code review", exact: true })
      .click();
    const popupPromise = context.waitForEvent("page");
    await page
      .getByRole("button", { name: "CWE evidence · PDF", exact: true })
      .click();
    const report = await popupPromise;
    report.on("pageerror", (error) => errors.push(error.message));
    await expect(
      report.getByRole("button", { name: "Print / Save as PDF", exact: true }),
    ).toBeEnabled();
    expect(report.url()).not.toContain(app.token);
    await expect(
      report.getByRole("heading", { name: "CWE summary", exact: true }),
    ).toBeVisible();
    await expect(report.locator(".cwe-summary tbody tr").first()).toHaveText(
      "CWE-2952111",
    );
    await expect(report.locator(".code-line.cited").first()).toContainText(
      "verify=False",
    );
    await expect(report.locator("#report-content")).not.toContainText(
      "packets completed, 11 pending",
    );
    await expect(
      report.getByRole("heading", { name: "Finding index", exact: true }),
    ).toHaveCount(0);
    await expect(report.locator(".report-confidential")).toHaveText(
      "Confidential — Do not share",
    );
    await expect(report.getByAltText("UnitOne logo")).toBeVisible();
    await expect
      .poll(() =>
        report
          .getByAltText("UnitOne logo")
          .evaluate((img) => img.complete && img.naturalWidth > 0),
      )
      .toBe(true);
    const offlinePath = testInfo.outputPath("cwe-offline.html");
    const htmlResponse = await page.request.get(
      app.url.split("/#")[0] + "/api/export?format=cwe-evidence-html",
      { headers: { "X-Synthesis-Token": app.token } },
    );
    await fs.writeFile(offlinePath, await htmlResponse.text());
    const offline = await context.newPage();
    await offline.goto(
      (await import("node:url")).pathToFileURL(offlinePath).href,
    );
    await expect
      .poll(() =>
        offline
          .getByAltText("UnitOne logo")
          .evaluate((img) => img.complete && img.naturalWidth > 0),
      )
      .toBe(true);
    await expect(offline.locator(".report-confidential")).toHaveText(
      "Confidential — Do not share",
    );
    await offline.close();
    await expect(report.locator("#report-content")).toContainText(
      "Code evidence is unavailable",
    );
    expect(
      await report.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    ).toBe(true);
    await report.evaluate(() => {
      window.print = () => {
        window.printInvoked = true;
      };
    });
    await report
      .getByRole("button", { name: "Print / Save as PDF", exact: true })
      .click();
    expect(await report.evaluate(() => window.printInvoked)).toBe(true);
    const pdf = await report.pdf({
      path: testInfo.outputPath("cwe-evidence.pdf"),
      printBackground: true,
      preferCSSPageSize: true,
    });
    expect(pdf.subarray(0, 5).toString()).toBe("%PDF-");
    await report.screenshot({
      path: testInfo.outputPath("cwe-evidence.png"),
      fullPage: true,
    });
    await page
      .getByRole("button", { name: "3 · System model", exact: true })
      .click();
    await page
      .getByRole("button", { name: "Export review package", exact: true })
      .click();
    const threatPromise = context.waitForEvent("page");
    await page
      .getByRole("button", { name: "Threat model · PDF", exact: true })
      .click();
    const threat = await threatPromise;
    await expect(
      threat.getByRole("button", { name: "Print / Save as PDF", exact: true }),
    ).toBeEnabled();
    await expect(
      threat.getByRole("heading", {
        name: "No current STRIDE results",
        exact: true,
      }),
    ).toBeVisible();
    for (const name of [
      "Overall system DFD",
      "STRIDE matrix",
      "Threat register",
      "Supporting evidence",
    ])
      await expect(
        threat.getByRole("heading", { name, exact: true }),
      ).toHaveCount(0);
    await expect(threat.locator(".report-confidential")).toHaveText(
      "Confidential — Do not share",
    );
    await expect
      .poll(() =>
        threat
          .getByAltText("UnitOne logo")
          .evaluate((img) => img.complete && img.naturalWidth > 0),
      )
      .toBe(true);
    await threat.pdf({
      path: testInfo.outputPath("threat-model.pdf"),
      printBackground: true,
      preferCSSPageSize: true,
    });
    await report.close();
    await threat.close();
    expect(errors).toEqual([]);
  } finally {
    await app?.close();
    await fs.rm(f.dir, { recursive: true, force: true });
  }
});

test("partial STRIDE PDF exports saved scenarios, actors, boundaries and incomplete coverage directly from matrix", async ({
  page,
  context,
}, testInfo) => {
  const { GUIDANCE_HASH } = await import("../../src/analysis-guidance.mjs");
  const { SYSTEM_PROMPT } = await import("../../src/model-review.mjs");
  const { sha } = await import("../../src/sources.mjs");
  const { systemModel, editSystem } = await import(
    "../../src/system-model.mjs"
  );
  const f = await reportFixture();
  let app;
  try {
    delete f.model.cweReview;
    delete f.model.cweModelReview;
    const iid = f.model.interfaces[0].id,
      eid = f.model.evidence[0].id;
    let s = systemModel(f.model);
    expect(s.flows.length).toBeGreaterThan(0);
    f.model = editSystem(f.model, {
      revision: s.revision,
      action: "upsert",
      kind: "boundaries",
      record: {
        id: "user-abcdef0123456789",
        name: "Caller to service identity",
        dimension: "identity",
        before: "Untrusted caller",
        after: "Service principal",
        enforcement: "Identity checks require validation",
        flowIds: [s.flows[0].id],
        evidenceIds: [eid],
      },
    });
    f.model.aiReview = {
      status: "partial",
      promptHash: sha(SYSTEM_PROMPT),
      guidance: { hash: GUIDANCE_HASH },
      basedOnRevision: f.model.modelRevision,
      provider: "anthropic-gateway",
      model: "claude-opus-4-6-1",
      threats: [
        {
          id: "partial-threat-001",
          title: "Conditional caller identity bypass",
          category: "Spoofing",
          actor: "External untrusted caller",
          startingAccess: "Network access to the service",
          asset: "Service identity",
          scenario:
            "Caller-controlled identity may bypass an incomplete enforcement path.",
          prerequisites: "Accessible interface and missing identity check",
          controls: "Verify authentication and caller restrictions",
          mitigation: "Enforce trusted caller identity at the interface",
          interfaceIds: [iid],
          evidenceIds: [eid],
        },
      ],
      questions: [],
      connections: [],
      batches: [
        { id: "saved-packet", status: "completed", interfaceIds: [iid] },
      ],
      coverage: {
        completedBatches: 1,
        totalBatches: 4,
        pendingBatches: 3,
        failedBatches: 0,
        reviewedInterfaceIds: [iid],
        submittedInterfaces: 1,
        totalInterfaces: f.model.interfaces.length,
        omittedInterfaces: 0,
        excerptCount: 0,
        repositories: [],
      },
    };
    s = systemModel(f.model);
    f.model = editSystem(f.model, {
      revision: s.revision,
      action: "decision",
      subjectId: "partial-threat-001",
      state: "accepted",
      reviewer: "Security champion",
      rationale:
        "Static evidence and prerequisites reviewed; deployment remains unverified",
      owner: "Service team",
      severity: "medium",
    });
    s = systemModel(f.model);
    const threatReference = s.threats.find(
      (t) => t.id === "partial-threat-001",
    ).reference;
    const boundaryReference = s.boundaries.find(
      (b) => b.id === "user-abcdef0123456789",
    ).reference;
    const store = await workspaceStore(f.root, f.workspace);
    await store.save({ manifest: f.manifest, model: f.model });
    await store.close();
    app = await serve({
      sourceRoot: f.root,
      workspace: f.workspace,
      persist: true,
      port: 0,
      quiet: true,
    });
    await page.goto(app.url);
    await page
      .getByRole("button", { name: "Open saved graph", exact: true })
      .click();
    await page
      .getByRole("button", { name: "4 · STRIDE matrix", exact: true })
      .click();
    const button = page.getByRole("button", {
      name: "Export STRIDE review · PDF",
      exact: true,
    });
    await expect(button).toBeEnabled();
    await expect(page.locator("#workspace")).toContainText(
      "latest saved review snapshot",
    );
    // Export remains available while another packet is being reviewed; it reads saved state.
    await page.evaluate(() =>
      window.SynthesisWorkspace.setStatus({
        status: "running",
        mode: "review",
        inference: true,
        hasModel: true,
      }),
    );
    await expect(button).toBeEnabled();
    const opened = context.waitForEvent("page");
    await button.click();
    const report = await opened;
    await expect(
      report.getByRole("button", { name: "Print / Save as PDF", exact: true }),
    ).toBeEnabled();
    for (const name of [
      "Overall system DFD",
      "Threat actors linked to supported threats",
      "Trust boundaries linked to supported threats",
      "STRIDE matrix",
      "Threat details",
    ])
      await expect(
        report.getByRole("heading", { name, exact: true }),
      ).toBeVisible();
    const content = report.locator("#report-content");
    await expect(content).toContainText(
      "1 / 4 STRIDE packets completed; 0 failed; 3 pending",
    );
    await expect(content).toContainText("Partial STRIDE review");
    await expect(content).toContainText("No current individually supported threats");
    await expect(content).toContainText("Named connections below are static context");
    await expect(content).not.toContainText("Conditional caller identity bypass");
    await expect(content).toContainText("unresolved hypotheses are omitted");
    await expect(content).toContainText(threatReference);
    await expect(report.locator("article")).toHaveCount(0);
    const technical=await page.request.get(app.url.split('/#')[0]+'/api/export?format=threat-technical-html',{headers:{'X-Synthesis-Token':app.token}});
    expect(technical.ok()).toBeTruthy();
    expect(await technical.text()).toContain('Conditional caller identity bypass');
    const pdf = await report.pdf({
      path: testInfo.outputPath("partial-stride-review.pdf"),
      printBackground: true,
      preferCSSPageSize: true,
    });
    expect(pdf.subarray(0, 5).toString()).toBe("%PDF-");
    expect(pdf.length).toBeGreaterThan(5000);
    await report.close();
  } finally {
    await app?.close();
    await fs.rm(f.dir, { recursive: true, force: true });
  }
});

test("access filter carries from registers and matrix into partial PDF with mixed and unknown choices", async ({page,context}) => {
  const {GUIDANCE_HASH}=await import('../../src/analysis-guidance.mjs');
  const {SYSTEM_PROMPT}=await import('../../src/model-review.mjs');
  const {sha}=await import('../../src/sources.mjs');
  const f=await reportFixture();
  let app;
  try {
    const iface=f.model.interfaces[0], evidence=iface.evidence;
    f.model.aiReview={status:'partial',promptHash:sha(SYSTEM_PROMPT),guidance:{hash:GUIDANCE_HASH},basedOnRevision:f.model.modelRevision,
      coverage:{completedBatches:1,totalBatches:4,pendingBatches:3,failedBatches:0,reviewedInterfaceIds:[iface.id]},
      threats:['External attacker','Internal operator','External attacker or insider','API caller'].map((actor,n)=>({
        id:'filter-'+n,title:['External result','Internal result','Mixed result','Unresolved result'][n],
        category:'Tampering',actor,startingAccess:'Conditional access',asset:'Resource',scenario:'Conditional change',
        prerequisites:'Control absent',controls:'Check enforcement',mitigation:'Enforce permissions',interfaceIds:[iface.id],evidenceIds:evidence
      })),questions:[],connections:[],batches:[]};
    const store=await workspaceStore(f.root,f.workspace);
    await store.save({manifest:f.manifest,model:f.model});await store.close();
    app=await serve({sourceRoot:f.root,workspace:f.workspace,persist:true,port:0,quiet:true});
    await page.goto(app.url);
    await page.getByRole('button',{name:'Open saved graph',exact:true}).click();
    await page.getByRole('button',{name:'4 · STRIDE matrix',exact:true}).click();
    await page.getByLabel('Actor access',{exact:true}).selectOption('external');
    await page.getByLabel('Include unresolved access',{exact:true}).uncheck();
    await expect(page.locator('.ws-priority-panel')).not.toContainText('Internal result');
    await expect(page.locator('.ws-priority-panel')).not.toContainText('Unresolved result');
    await expect(page.locator('.ws-priority-panel')).toContainText('Mixed result');
    const popupPromise=context.waitForEvent('page');
    await page.getByRole('button',{name:'Export STRIDE review · PDF',exact:true}).click();
    const popup=await popupPromise;
    await expect(popup.locator('#report-status')).toContainText('Report ready');
    await expect(popup.locator('#report-content')).toContainText('T-FILTER-0');
    await expect(popup.locator('#report-content')).toContainText('T-FILTER-2');
    await expect(popup.locator('#report-content')).not.toContainText('T-FILTER-1');
    await expect(popup.locator('#report-content')).not.toContainText('T-FILTER-3');
    await expect(popup.locator('#report-content')).toContainText('1 / 4 STRIDE packets');
    await expect(popup.locator('#report-content')).not.toContainText('Scenarios identified; 0 scenarios');
    await expect(popup.locator('#report-content')).toContainText('Reviewed scope');
    await popup.close();
    await page.locator('.ws-tabs').getByRole('button',{name:'Threat actors',exact:true}).click();
    await expect(page.getByLabel('Actor access',{exact:true})).toHaveValue('external');
    await expect(page.locator('.ws-records')).not.toContainText('Internal operator');
    await page.getByLabel('Include unresolved access',{exact:true}).check();
    await expect(page.locator('.ws-records')).toContainText('API caller');
    await page.locator('.ws-tabs').getByRole('button',{name:'Threat register',exact:true}).click();
    await expect(page.locator('.ws-records')).not.toContainText('Internal result');
    await expect(page.locator('.ws-records')).toContainText('Unresolved result');
  } finally {await page.goto('about:blank');await app?.close();await fs.rm(f.dir,{recursive:true,force:true});}
});
