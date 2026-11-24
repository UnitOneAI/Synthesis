import {test,expect} from '@playwright/test';
import fs from 'node:fs/promises';
import {reportFixture} from '../report-fixture.mjs';
import {workspaceStore} from '../../src/workspace-store.mjs';
import {serve} from '../../src/server.mjs';
import path from 'node:path';
import {analyze} from '../../src/engine.mjs';
import {sqliteSupported} from '../../src/graph-store.mjs';
test('saved-graph POC selector imports, previews and survives restart without changing the graph',async({page})=>{
 const f=await reportFixture();let app;
 try {
  f.model.interfaces[0].direction='inbound';
  const store=await workspaceStore(f.root,f.workspace);await store.save({model:f.model,manifest:f.manifest});await store.close();
  app=await serve({sourceRoot:f.root,workspace:f.workspace,persist:true,port:0,quiet:true});
  await page.goto(app.url);await page.getByRole('button',{name:'Open saved graph',exact:true}).click();await page.getByRole('button',{name:'4 · STRIDE matrix',exact:true}).click();
  await page.getByText('Advanced: select individual operations (JSON)',{exact:true}).click();
  await page.getByLabel('POC scope file').setInputFiles({name:'scope.json',mimeType:'application/json',buffer:Buffer.from('\uFEFF'+JSON.stringify({title:'External API pilot',profile:'Test network assumption',operations:[{repository:'service',pathContains:'app.py'}]}))});
  await page.getByRole('button',{name:'Save POC scope',exact:true}).click();
  await expect(page.locator('#ws-review-scope')).toHaveValue('poc');
  await page.getByRole('button',{name:'Preview saved scope',exact:true}).click();await expect(page.locator('#ws-scope-preview')).toContainText('system review units');await expect(page.locator('#ws-scope-preview')).not.toContainText('All selected primary subjects planned');
  const url=new URL(app.url), headers={'X-Synthesis-Token':app.token};
  const m=await (await page.request.get(url.origin+'/api/model',{headers})).json();expect(m.sourceGraph.fingerprint).toBe(f.model.sourceGraph.fingerprint);expect(m.pocScope.title).toBe('External API pilot');
  await app.close();app=await serve({sourceRoot:f.root,workspace:f.workspace,persist:true,port:0,quiet:true});
  const restored=await (await page.request.get(new URL(app.url).origin+'/api/model',{headers:{'X-Synthesis-Token':app.token}})).json();expect(restored.pocScope.id).toBe(m.pocScope.id);
 }finally{await page.goto('about:blank');await app?.close();await fs.rm(f.dir,{recursive:true,force:true});}
});
test('primary repositories save on the disk graph after export and restart without customer-specific names',async({page})=>{
 test.skip(!sqliteSupported(),'Supported SQLite required');
 const f=await reportFixture();let app;
 try{
  await fs.mkdir(f.workspace,{recursive:true});
  f.model=await analyze(f.manifest,{sourceRoot:f.root,graphDatabase:path.join(f.workspace,'graph.sqlite')});
  const store=await workspaceStore(f.root,f.workspace);await store.save({model:f.model,manifest:f.manifest});await store.close();
  app=await serve({sourceRoot:f.root,workspace:f.workspace,persist:true,graphStorage:'sqlite',port:0,quiet:true});
  await page.goto(app.url);await page.getByRole('button',{name:'Open saved graph',exact:true}).click();await page.getByRole('button',{name:'4 · STRIDE matrix',exact:true}).click();
  const exportOptions=await page.request.get(new URL(app.url).origin+'/api/graph-package-options',{headers:{'X-Synthesis-Token':app.token}});expect(exportOptions.status()).toBe(200);
  await page.locator('[data-primary-repo][value="service"]').check();await page.locator('#ws-repo-title').fill('Selected application');
  await page.getByRole('button',{name:'Save repository scope',exact:true}).click();await expect(page.locator('#ws-review-scope')).toHaveValue('poc');
  await page.getByRole('button',{name:'Preview saved scope',exact:true}).click();await expect(page.locator('#ws-scope-preview')).toContainText('system review units');await expect(page.locator('#ws-scope-preview')).toContainText('All selected primary subjects planned');
  const m=await (await page.request.get(new URL(app.url).origin+'/api/model',{headers:{'X-Synthesis-Token':app.token}})).json();
  expect(m.pocScope.kind).toBe('repositories');expect(m.pocScope.repositories).toEqual(['service']);expect(m.sourceGraph.fingerprint).toBe(f.model.sourceGraph.fingerprint);
  await app.close();app=await serve({sourceRoot:f.root,workspace:f.workspace,persist:true,graphStorage:'sqlite',port:0,quiet:true});
  await page.goto(app.url);await page.getByRole('button',{name:'Open saved graph',exact:true}).click();await page.getByRole('button',{name:'4 · STRIDE matrix',exact:true}).click();
  await expect(page.locator('[data-primary-repo][value="service"]')).toBeChecked();
  await page.getByRole('button',{name:'Preview saved scope',exact:true}).click();await expect(page.locator('#ws-scope-preview')).toContainText('All selected primary subjects planned');
 }finally{await page.goto('about:blank');await app?.close();await fs.rm(f.dir,{recursive:true,force:true});}
});

test('repository selection makes review roles explicit, protects drafts and submits the saved scope', async ({page}, testInfo) => {
 test.skip(!sqliteSupported(),'Supported SQLite required');
 const f=await reportFixture();let app;
 const {modelConfig}=await import('../../src/model-review.mjs');
 const config=modelConfig('anthropic-gateway','claude-opus-4-6-1',{CLAUDE_API_KEY:'test-only-key'},{baseUrl:'https://gateway.example/anthropic'});
 const errors=[];let builds=0,reviewRequest;
 try{
  const names=['application-portal',...Array.from({length:11},(_,i)=>`supporting-service-${String(i+1).padStart(2,'0')}`)];
  for(const name of names){await fs.mkdir(path.join(f.root,name));await fs.writeFile(path.join(f.root,name,'app.py'),'def action():\n    return 1\n');f.manifest.repositories.push({name});}
  await fs.mkdir(f.workspace,{recursive:true});
  f.model=await analyze(f.manifest,{sourceRoot:f.root,graphDatabase:path.join(f.workspace,'graph.sqlite')});
  const store=await workspaceStore(f.root,f.workspace);await store.save({model:f.model,manifest:f.manifest});await store.close();
  const options={sourceRoot:f.root,workspace:f.workspace,persist:true,graphStorage:'sqlite',port:0,quiet:true,modelConfig:config};
  app=await serve(options);
  page.on('pageerror',error=>errors.push(error.message));
  page.on('request',request=>{if(request.method()==='POST'&&request.url().endsWith('/api/analyze'))builds++;});
  const open=async()=>{await page.goto(app.url);await page.getByRole('button',{name:'Open saved graph',exact:true}).click();await page.getByRole('button',{name:'4 · STRIDE matrix',exact:true}).click();};
  await open();
  const panel=page.locator('.ws-repository-scope'), save=page.locator('#ws-save-repositories'), preview=page.locator('#ws-preview-scope'), run=page.locator('[data-start-review]');
  await expect(panel.getByRole('checkbox')).toHaveCount(13);
  await expect(save).toBeDisabled();
  await expect(page.locator('#ws-repository-count')).toContainText('0 of 13');
  // Clicking the name and using the keyboard must select that same row.
  await panel.locator('.ws-repository-name').filter({hasText:/^service$/}).click();
  const portal=panel.getByRole('checkbox',{name:'application-portal',exact:true});await portal.focus();await portal.press('Space');
  await expect(portal).toBeChecked();await expect(panel.getByRole('checkbox',{name:'service',exact:true})).toBeChecked();
  await expect(page.locator('#ws-repository-count')).toContainText('2 of 13 repositories selected for review · 11 available as supporting evidence');
  await expect(preview).toBeDisabled();await expect(run).toBeDisabled();
  await page.locator('#ws-repo-title').fill('Application API and portal');
  // A matrix redraw must not discard the pending selection or title.
  await page.getByLabel('Rows',{exact:true}).selectOption('flow');
  await expect(portal).toBeChecked();await expect(page.locator('#ws-repo-title')).toHaveValue('Application API and portal');
  const checkbox=await portal.boundingBox(), name=await panel.locator('.ws-repository-name').filter({hasText:/^application-portal$/}).boundingBox();
  expect(checkbox.x+checkbox.width).toBeLessThan(name.x);expect(Math.abs(checkbox.y+checkbox.height/2-name.y-name.height/2)).toBeLessThan(5);
  await page.route('**/api/poc-scope',route=>route.fulfill({status:400,contentType:'application/json',body:JSON.stringify({error:'Synthetic scope save failure'})}),{times:1});
  await save.click();await expect(page.locator('#message')).toContainText('Synthetic scope save failure');
  await expect(portal).toBeChecked();await expect(save).toBeEnabled();await expect(preview).toBeDisabled();
  let releaseSave;const saving=new Promise(resolve=>{releaseSave=resolve;});
  await page.route('**/api/poc-scope',async route=>{await saving;await route.continue();},{times:1});
  await save.click();await expect(save).toHaveText('Saving repository scope…');await expect(save).toBeDisabled();await expect(portal).toBeDisabled();
  releaseSave();await expect(save).toHaveText('Save repository scope');await expect(page.locator('#ws-review-scope')).toHaveValue('poc');
  await expect(page.locator('#ws-repository-saved')).toContainText('application-portal, service');
  await expect(page.locator('#ws-repository-save-status')).toContainText('Scope saved');
  await preview.click();await expect(page.locator('#ws-scope-preview')).toContainText('All selected primary subjects planned');
  const headers={'X-Synthesis-Token':app.token},base=new URL(app.url).origin;
  const plan=await(await page.request.get(base+'/api/system-review-plan?scope=poc',{headers})).json();
  expect(plan.scope.poc.repositories).toEqual(['application-portal','service']);expect(plan.scope.poc.supportingRepositories).toHaveLength(11);
  expect(plan.scope.repositoryInventory.files.every(file=>['application-portal','service'].includes(file.repository))).toBe(true);
  const saved=await(await page.request.get(base+'/api/model',{headers})).json();expect(saved.sources).toHaveLength(13);expect(saved.sourceGraph.fingerprint).toBe(f.model.sourceGraph.fingerprint);
  await panel.screenshot({path:testInfo.outputPath('repository-selection-desktop.png')});
  await page.setViewportSize({width:640,height:1000});await panel.screenshot({path:testInfo.outputPath('repository-selection-narrow.png')});
  const bounds=await portal.boundingBox(),text=await panel.locator('.ws-repository-name').filter({hasText:/^application-portal$/}).boundingBox();
  expect(bounds.x+bounds.width).toBeLessThan(text.x);expect(Math.abs(bounds.y+bounds.height/2-text.y-text.height/2)).toBeLessThan(5);
  expect(await panel.evaluate(el=>el.scrollWidth<=el.clientWidth)).toBe(true);
  await page.setViewportSize({width:1440,height:1000});
  await page.getByRole('button',{name:'Clear selection',exact:true}).click();await expect(save).toBeDisabled();await expect(run).toBeDisabled();
  await page.getByRole('button',{name:'Discard changes',exact:true}).click();await expect(portal).toBeChecked();await expect(run).toBeEnabled();
  await page.getByRole('button',{name:'Select all',exact:true}).click();await expect(panel.getByRole('checkbox',{checked:true})).toHaveCount(13);
  await page.getByRole('button',{name:'Discard changes',exact:true}).click();
  await page.route('**/api/review',route=>{reviewRequest=route.request().postDataJSON();return route.fulfill({status:400,contentType:'application/json',body:JSON.stringify({error:'Synthetic dispatch capture; no provider call'})});});
  await page.locator('#ws-review-workers').selectOption('4');await page.locator('#ws-until-complete').check();await run.click();
  await expect.poll(()=>reviewRequest?.reviewScope).toBe('poc');expect(reviewRequest.concurrency).toBe(4);expect(reviewRequest.runUntilComplete).toBe(true);
  await app.close();app=await serve(options);await open();await expect(portal).toBeChecked();await expect(page.locator('#ws-review-scope')).toHaveValue('poc');
  await preview.click();await expect(page.locator('#ws-scope-preview')).toContainText('All selected primary subjects planned');
  expect(builds).toBe(0);expect(errors).toEqual([]);
 }finally{await page.goto('about:blank');await app?.close();await fs.rm(f.dir,{recursive:true,force:true});}
});
