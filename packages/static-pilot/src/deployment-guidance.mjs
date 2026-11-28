import { sha } from './sources.mjs';
import { redact } from './model-review.mjs';

// Imported statements are declared intent, never observed deployment. No files,
// URLs or commands in a profile are opened or executed.
export function validateDeploymentGuidance(input, model) {
  const fail=message=>{throw Error('Deployment guidance: '+message);};
  if(!input||Buffer.byteLength(JSON.stringify(input))>32768)fail('use a JSON profile under 32 KiB');
  const text=(v,max=1600)=>{if(typeof v!=='string'||!v.trim()||v.length>max)fail('bounded nonempty text required');return redact(v.trim());};
  if(!Array.isArray(input.repositories)||input.repositories.length>100)fail('provide a bounded repository list');
  const repositories=[...new Set(input.repositories)];
  if(!repositories.length||repositories.some(r=>!model.sources.some(s=>s.name===r)))fail('name at least one loaded repository');
  if(!['protected-deployment','authorized-user-or-peer','exposure-deviation'].includes(input.mode))fail('choose a supported analysis mode');
  if(!Array.isArray(input.statements)||!input.statements.length||input.statements.length>12)fail('provide 1–12 cited guide statements');
  const statements=input.statements.map(s=>({area:['exposure','caller','execution','data','transport'].includes(s.area)?s.area:fail('invalid statement area'),statement:text(s.statement),reference:text(s.reference,400)}));
  const profile={version:1,title:text(input.title,200),document:text(input.document,300),documentVersion:text(input.documentVersion,100),
    mode:input.mode,repositories:repositories.sort(),statements,
    basis:'Declared guidance; installation applicability and effective enforcement are unverified.'};
  return {...profile,id:sha(JSON.stringify(profile)).slice(0,24)};
}
export function guidanceForRepositories(model, repositories) {
  const state=model.deploymentContext;
  const profile=state?.guidanceProfiles?.find(p=>p.id===state.activeGuidanceId);
  if(!profile||!profile.repositories.some(r=>repositories.includes(r)))return null;
  const scenarioFocus={'protected-deployment':'Assess the recommended protected deployment while checking for bypasses and contradictory bindings.','authorized-user-or-peer':'Assess ordinary authenticated users and compromised peers inside the permitted environment; do not equate them with administrators.','exposure-deviation':'Assess a departure from the guide. Cite supporting configuration or label the departure hypothetical; do not assert exposure from a hypothetical.'}[profile.mode];
  return {...profile,scenarioFocus,instruction:'Treat these cited guide statements as intended deployment, not controls proven active. Trace corresponding routing, identity and configuration; investigate contradictory or bypass paths. External means outside the stated boundary, not necessarily internet. A protected baseline does not rule out authenticated users or compromised peers. An exposure deviation is hypothetical until source/configuration or a reviewer declaration supports it.'};
}
