import {test,expect} from '@playwright/test';import fs from 'node:fs/promises';
import {reportFixture} from '../report-fixture.mjs';import {workspaceStore} from '../../src/workspace-store.mjs';import {serve} from '../../src/server.mjs';
import {reviewAutomaticSections} from '../../src/automatic-section-run.mjs';import {verifiedStrideSource,prepareStrideEvidence} from '../../src/stride-evidence.mjs';import {modelConfig} from '../../src/model-review.mjs';import {REPOSITORY_CATEGORIES} from '../../src/repository-assessment-summary.mjs';
test('automatic section results expose complete six-category report and one-click run with no scope confirmation',async({page,context})=>{
 const f=await reportFixture();let app;const errors=[];page.on('pageerror',e=>errors.push(e.message));const config=modelConfig('anthropic','claude-opus-4-6',{ANTHROPIC_API_KEY:'synthetic'});
 try {
  const initial=structuredClone(f.model),source=await verifiedStrideSource(f.model,f.manifest,f.root);
  const send=async(_,req)=>{const p=JSON.parse(JSON.parse(req.body).messages[0].content);const value={summary:'Synthetic fixture only.',threats:[],connections:[],questions:[],explorationRequests:[],categoryReviews:REPOSITORY_CATEGORIES.map(category=>({category,status:'no-scenario-identified',interfaceIds:p.reviewUnit.primaryInterfaceIds,rationale:'Synthetic fixture reviewed.',citations:p.sourceContext.records.map(r=>({recordId:r.id,line:r.startLine,endLine:r.endLine,role:'context'})),threatIndexes:[],missingEvidence:[],deploymentConditions:[],remediation:''}))};return Response.json({stop_reason:'end_turn',content:[{type:'text',text:JSON.stringify(value)}],usage:{input_tokens:10,output_tokens:20}});};
  const runOptions={sourceRoot:f.root,verifiedSource:source,prepareBatch:b=>prepareStrideEvidence(b.packet,source),reviewCacheFile:f.dir+'/review-cache.sqlite'};
  await reviewAutomaticSections(f.model,f.manifest,config,new Map(),send,runOptions);
  f.model=initial;await reviewAutomaticSections(f.model,f.manifest,config,new Map(),async()=>{throw Error('Warm fixture must not call provider');},runOptions);
  const store=await workspaceStore(f.root,f.workspace);await store.save({model:f.model,manifest:f.manifest});await store.close();
  app=await serve({sourceRoot:f.root,workspace:f.workspace,persist:true,port:0,quiet:true,modelConfig:config});
  await page.goto(app.url);await page.getByRole('button',{name:'Open saved graph',exact:true}).click();await page.getByRole('button',{name:'4 · STRIDE matrix',exact:true}).click();
  await expect(page.locator('.ws-automatic-sections')).toContainText('1/1 sections complete');await expect(page.locator('.ws-automatic-sections')).toContainText('6/6 categories');await expect(page.locator('.ws-automatic-sections')).toContainText('1 local assessments reused');await expect(page.locator('.ws-automatic-sections')).toContainText('0 requests');
  const popupPromise=context.waitForEvent('page');await page.getByRole('button',{name:'Export section · PDF'}).click();const report=await popupPromise;await expect(report.locator('#report-content')).toContainText('Section static threat model complete');for(const c of REPOSITORY_CATEGORIES)await expect(report.locator('#report-content')).toContainText(c);await expect(report.locator('#print-report')).toBeEnabled();await report.close();
  let body;await page.route('**/api/review',async route=>{body=route.request().postDataJSON();await route.fulfill({status:202,contentType:'application/json',body:JSON.stringify({status:'ready'})});});
  await page.getByRole('button',{name:'Plan and run sections automatically'}).click();await expect.poll(()=>body?.reviewScope).toBe('sections');expect(body.runUntilComplete).toBe(true);expect(errors).toEqual([]);
 } finally {await page.goto('about:blank');await app?.close();await fs.rm(f.dir,{recursive:true,force:true});}
});
