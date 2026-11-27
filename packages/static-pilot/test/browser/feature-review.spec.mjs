import {test,expect} from '@playwright/test';
import fs from 'node:fs/promises';
import {reportFixture} from '../report-fixture.mjs';
import {workspaceStore} from '../../src/workspace-store.mjs';
import {serve} from '../../src/server.mjs';
import {threatValidationKey,threatIssue} from '../../src/threat-validation-state.mjs';
import {sha} from '../../src/sources.mjs';
import {GUIDANCE_HASH} from '../../src/analysis-guidance.mjs';
import {SYSTEM_PROMPT} from '../../src/model-review.mjs';

test('feature scope preview and deployment answers preserve graph and paid review after restart',async({page})=>{
 const f=await reportFixture();let app;const errors=[];page.on('pageerror',e=>errors.push(e.message));
 const iface=f.model.interfaces.find(i=>i.direction==='outbound');
 const threat={id:'tls-path',title:'Conditional TLS interception',category:'Information Disclosure',actor:'Network intermediary',startingAccess:'Interception capability',asset:'Response data',scenario:'Intermediary can impersonate upstream when certificate verification is disabled',prerequisites:'Interception',controls:'verify=False',mitigation:'Enable verification',interfaceIds:[iface.id],evidenceIds:iface.evidence};
 f.model.aiReview={guidance:{hash:GUIDANCE_HASH},promptHash:sha(SYSTEM_PROMPT),status:'partial',basedOnRevision:f.model.modelRevision,mode:'source-excerpts',threats:[threat],connections:[],questions:[],batches:[],coverage:{completedBatches:1,totalBatches:2,pendingBatches:1,failedBatches:0,reviewedInterfaceIds:[iface.id]}};
 f.model.threatValidation={contextKey:threatValidationKey(f.model),entries:[{sourceId:threat.id,issueHash:sha(JSON.stringify(threatIssue(f.model,threat))),assessment:'static-supported',challengeCompleted:true,engineering:{conclusion:'An intermediary can impersonate the upstream under the stated access condition.',obligations:[],reviewerQuestions:[{question:'Can an untrusted intermediary intercept the upstream connection?',ifYes:'The interception prerequisite applies.',ifNo:'This intermediary lacks the stated access.'}]},remediation:{codeFix:'Enable certificate verification'},deploymentAssumptions:['An intermediary controls the path']}]};
 const original=JSON.stringify(f.model.aiReview),fingerprint=f.model.sourceGraph.fingerprint;
 const options={sourceRoot:f.root,workspace:f.workspace,persist:true,port:0,quiet:true};
 try {
  const store=await workspaceStore(f.root,f.workspace);await store.save({model:f.model,manifest:f.manifest});await store.close();
  app=await serve(options);
  const open=async()=>{await page.goto(app.url);await page.getByRole('button',{name:'Open saved graph',exact:true}).click();await page.getByRole('button',{name:'4 · STRIDE matrix',exact:true}).click();};
  await open();await page.getByRole('button',{name:'Select all',exact:true}).click();
  await page.locator('#ws-repo-depth').selectOption('security-features');
  await page.getByRole('button',{name:'Save repository scope',exact:true}).click();
  await expect(page.locator('#ws-repository-save-status')).toContainText('Scope saved');
  await page.getByRole('button',{name:'Preview saved scope',exact:true}).click();
  await expect(page.locator('#ws-scope-preview')).toContainText('Security-feature review');
  await page.getByText(/Deployment decisions for the reviewer/).click();
  const form=page.locator('[data-deployment-question]');await expect(form).toHaveCount(1);
  await form.locator('[name=answer]').selectOption('no');await form.locator('[name=reviewer]').fill('JCI reviewer');await form.locator('[name=rationale]').fill('The deployment uses an isolated upstream segment.');
  await form.getByRole('button',{name:'Save deployment answer'}).click();
  await page.getByText(/Deployment decisions for the reviewer/).click();
  await expect(page.locator('[data-deployment-question]')).toContainText('Recorded no by JCI reviewer');
  const read=()=>page.request.get(new URL(app.url).origin+'/api/model',{headers:{'X-Synthesis-Token':app.token}}).then(r=>r.json());
  const saved=await read();expect(saved.sourceGraph.fingerprint).toBe(fingerprint);delete saved.aiReview.staleReason;expect(JSON.stringify(saved.aiReview)).toBe(original);
  const unauthorized=await page.request.post(new URL(app.url).origin+'/api/threats/deployment-answer',{data:{}});expect(unauthorized.status()).toBe(401);
  await page.goto('about:blank');await app.close();app=await serve(options);await open();
  await expect(page.locator('#ws-repo-depth')).toHaveValue('security-features');
  await page.getByText(/Deployment decisions for the reviewer/).click();await expect(page.locator('[data-deployment-question]')).toContainText('Recorded no by JCI reviewer');
  expect(errors).toEqual([]);
 } finally {await page.goto('about:blank');await app?.close();await fs.rm(f.dir,{recursive:true,force:true});}
});
