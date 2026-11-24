import {test,expect} from '@playwright/test';
import fs from 'node:fs/promises';
import {reportFixture} from '../report-fixture.mjs';
import {workspaceStore} from '../../src/workspace-store.mjs';
import {serve} from '../../src/server.mjs';
import {modelConfig} from '../../src/model-review.mjs';

test('initial ready status reaches every view when a deferred view script loads slowly',async({page})=>{
 const f=await reportFixture();let app;const statuses=[];
 try{
  const store=await workspaceStore(f.root,f.workspace);await store.save({model:f.model,manifest:f.manifest});await store.close();
  const config=modelConfig('anthropic-gateway','claude-opus-4-6-1',{CLAUDE_API_KEY:'test-only-key'},{baseUrl:'https://gateway.example/anthropic'});
  app=await serve({sourceRoot:f.root,workspace:f.workspace,persist:true,port:0,quiet:true,modelConfig:config});
  // Deliberately delay the view download: app startup must wait for it, rather
  // than dropping the one initial status event through optional chaining.
  await page.route('**/cwe.js',async route=>{const response=await route.fetch();await new Promise(resolve=>setTimeout(resolve,500));await route.fulfill({response});});
  await page.route('**/api/status',async route=>{statuses.push(await page.evaluate(()=>Boolean(window.SynthesisWorkspace&&window.SynthesisCwe&&window.SynthesisExploration)));await route.continue();});
  await page.goto(app.url);await page.getByRole('button',{name:'Open saved graph',exact:true}).click();
  await page.getByRole('button',{name:'5 · CWE code review',exact:true}).click();
  await expect(page.locator('#cwe-model-run')).toBeEnabled();await expect(page.locator('#security-run')).toBeEnabled();
  await page.getByRole('button',{name:'4 · STRIDE matrix',exact:true}).click();await expect(page.locator('[data-start-review]')).toBeEnabled();
  expect(statuses.length).toBeGreaterThan(0);expect(statuses.every(Boolean)).toBe(true);
 }finally{await page.goto('about:blank');await app?.close();await fs.rm(f.dir,{recursive:true,force:true});}
});
