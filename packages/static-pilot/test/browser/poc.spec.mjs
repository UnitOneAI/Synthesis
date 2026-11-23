import {test,expect} from '@playwright/test';
import fs from 'node:fs/promises';
import {reportFixture} from '../report-fixture.mjs';
import {workspaceStore} from '../../src/workspace-store.mjs';
import {serve} from '../../src/server.mjs';
test('saved-graph POC selector imports, previews and survives restart without changing the graph',async({page})=>{
 const f=await reportFixture();let app;
 try {
  f.model.interfaces[0].direction='inbound';
  const store=await workspaceStore(f.root,f.workspace);await store.save({model:f.model,manifest:f.manifest});await store.close();
  app=await serve({sourceRoot:f.root,workspace:f.workspace,persist:true,port:0,quiet:true});
  await page.goto(app.url);await page.getByRole('button',{name:'Open saved graph',exact:true}).click();await page.getByRole('button',{name:'4 · STRIDE matrix',exact:true}).click();
  await page.getByText('Scoped POC · choose operations from the saved graph',{exact:true}).click();
  await page.getByLabel('POC scope file').setInputFiles({name:'scope.json',mimeType:'application/json',buffer:Buffer.from('\uFEFF'+JSON.stringify({title:'External API pilot',profile:'Test network assumption',operations:[{repository:'service',pathContains:'app.py'}]}))});
  await page.getByRole('button',{name:'Save POC scope',exact:true}).click();
  await expect(page.locator('#ws-review-scope')).toHaveValue('poc');
  await page.getByRole('button',{name:'Preview system scope',exact:true}).click();await expect(page.locator('#ws-scope-preview')).toContainText('system review units');
  const url=new URL(app.url), headers={'X-Synthesis-Token':app.token};
  const m=await (await page.request.get(url.origin+'/api/model',{headers})).json();expect(m.sourceGraph.fingerprint).toBe(f.model.sourceGraph.fingerprint);expect(m.pocScope.title).toBe('External API pilot');
  await app.close();app=await serve({sourceRoot:f.root,workspace:f.workspace,persist:true,port:0,quiet:true});
  const restored=await (await page.request.get(new URL(app.url).origin+'/api/model',{headers:{'X-Synthesis-Token':app.token}})).json();expect(restored.pocScope.id).toBe(m.pocScope.id);
 }finally{await page.goto('about:blank');await app?.close();await fs.rm(f.dir,{recursive:true,force:true});}
});
test('primary repositories are selectable without customer-specific names',async({page})=>{
 const f=await reportFixture();let app;
 try{
  const store=await workspaceStore(f.root,f.workspace);await store.save({model:f.model,manifest:f.manifest});await store.close();
  app=await serve({sourceRoot:f.root,workspace:f.workspace,persist:true,port:0,quiet:true});
  await page.goto(app.url);await page.getByRole('button',{name:'Open saved graph',exact:true}).click();await page.getByRole('button',{name:'4 · STRIDE matrix',exact:true}).click();
  await page.locator('[data-primary-repo][value="service"]').check();await page.locator('#ws-repo-title').fill('Selected application');
  await page.getByRole('button',{name:'Save repository scope',exact:true}).click();await expect(page.locator('#ws-review-scope')).toHaveValue('poc');
  await page.getByRole('button',{name:'Preview system scope',exact:true}).click();await expect(page.locator('#ws-scope-preview')).toContainText('system review units');
  const m=await (await page.request.get(new URL(app.url).origin+'/api/model',{headers:{'X-Synthesis-Token':app.token}})).json();
  expect(m.pocScope.kind).toBe('repositories');expect(m.pocScope.repositories).toEqual(['service']);expect(m.sourceGraph.fingerprint).toBe(f.model.sourceGraph.fingerprint);
 }finally{await page.goto('about:blank');await app?.close();await fs.rm(f.dir,{recursive:true,force:true});}
});
