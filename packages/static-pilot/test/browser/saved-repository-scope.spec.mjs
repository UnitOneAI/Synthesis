import {test,expect} from '@playwright/test';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {serve} from '../../src/server.mjs';

test('existing repository review saves scope, previews, exports and reopens without losing paid results',async({page,context},testInfo)=>{
 const input=process.env.SYNTHESIS_VALIDATION_WORKSPACE,sourceRoot=process.env.SYNTHESIS_VALIDATION_SOURCE_ROOT;
 test.skip(!input||!sourceRoot,'Set an offline validation workspace and source root');
 test.setTimeout(120000);
 const snapshot=JSON.parse(await fs.readFile(path.join(input,'snapshot.json'),'utf8'));
 test.skip(snapshot.data.model.pocScope?.kind!=='repositories','Requires a saved repository review');
 const workspace=await fs.mkdtemp(path.join(os.tmpdir(),'synthesis-saved-scope-ui-'));
 let app,reviewRequests=0,builds=0;const errors=[];
 try{
  await fs.copyFile(path.join(input,'snapshot.json'),path.join(workspace,'snapshot.json'));
  await fs.copyFile(path.join(input,'graph.sqlite'),path.join(workspace,'graph.sqlite'));
  const options={sourceRoot,workspace,persist:true,graphStorage:'sqlite',port:0,quiet:true};
  app=await serve(options);
  page.on('pageerror',error=>errors.push(error.message));
  page.on('request',request=>{if(request.method()==='POST'&&request.url().endsWith('/api/review'))reviewRequests++;if(request.method()==='POST'&&request.url().endsWith('/api/analyze'))builds++;});
  const readModel=async()=>await(await page.request.get(new URL(app.url).origin+'/api/model',{headers:{'X-Synthesis-Token':app.token}})).json();
  const initial=await readModel();
  const open=async()=>{await page.goto(app.url);await page.getByRole('button',{name:'Open saved graph',exact:true}).click();await page.getByRole('button',{name:'4 · STRIDE matrix',exact:true}).click();};
  await open();
  for(const name of initial.pocScope.repositories)await expect(page.locator('.ws-repository-scope').getByRole('checkbox',{name,exact:true})).toBeChecked();
  await page.request.get(new URL(app.url).origin+'/api/graph-package-options',{headers:{'X-Synthesis-Token':app.token}});
  await page.getByRole('button',{name:'Save repository scope',exact:true}).click();
  await expect(page.locator('#ws-repository-save-status')).toContainText('Scope saved');
  await page.getByRole('button',{name:'Preview saved scope',exact:true}).click();
  await expect(page.locator('#ws-scope-preview')).toContainText('All selected primary subjects planned');
  const saved=await readModel();expect(saved.aiReview).toEqual(initial.aiReview);expect(saved.sourceGraph.fingerprint).toBe(initial.sourceGraph.fingerprint);
  await page.locator('.ws-repository-scope').screenshot({path:testInfo.outputPath('saved-repository-scope.png')});
  const popup=context.waitForEvent('page');await page.getByRole('button',{name:'Export STRIDE review · PDF',exact:true}).click();const report=await popup;
  await expect(report.locator('#report-status')).toContainText('Report ready');
  for(const category of ['Spoofing','Tampering','Repudiation','Information Disclosure','Denial of Service','Elevation of Privilege'])await expect(report.locator('#report-content')).toContainText(category);
  const pdf=await report.pdf({path:testInfo.outputPath('saved-threat-model.pdf'),printBackground:true,preferCSSPageSize:true});expect(pdf.subarray(0,5).toString()).toBe('%PDF-');await report.close();
  await app.close();app=await serve(options);await open();
  await expect(page.locator('#ws-review-scope')).toHaveValue('poc');
  await page.getByRole('button',{name:'Preview saved scope',exact:true}).click();await expect(page.locator('#ws-scope-preview')).toContainText('All selected primary subjects planned');
  expect((await readModel()).aiReview).toEqual(initial.aiReview);expect(reviewRequests).toBe(0);expect(builds).toBe(0);expect(errors).toEqual([]);
 }finally{await page.goto('about:blank');await app?.close();await fs.rm(workspace,{recursive:true,force:true});}
});
