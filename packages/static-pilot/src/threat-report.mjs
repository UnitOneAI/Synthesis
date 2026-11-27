import { systemModel } from './system-model.mjs';
import { systemPrintReport } from './system-exports.mjs';
import { sourceWindow } from './graph-package.mjs';
import { accessFilter, matchesAccess } from './threat-access.mjs';

// Report-time source retrieval is local, hash-checked and bounded. It makes no
// model calls and never alters paid assessments or runtime/deployment claims.
export async function threatDecisionReport(model,manifest,root,options={}) {
  const filter=accessFilter(options.accessScope,options.includeUnresolved);
  const threats=systemModel(model,{matrix:false}).threats.filter(t=>t.outcome?.kind==='supported'&&matchesAccess(t,filter.scope,filter.includeUnresolved));
  const snippets={};let remaining=64,characters=256*1024;
  for(const threat of threats) {
    const obligations=threat.validation?.engineering?.obligations || [];
    const order=['applicable-controls','entry','sensitive-operation','path-binding'];
    const refs=threat.sourceConclusion?.citations || [...obligations].sort((a,b)=>order.indexOf(a.kind)-order.indexOf(b.kind)).flatMap(o=>o.citations || []);
    const unique=[...new Map(refs.map(r=>[JSON.stringify([r.repository,r.path,r.blobSha256,r.startLine,r.endLine]),r])).values()];
    const entries=[];
    for(const ref of unique.slice(0,options.technical?4:2)) {
      if(remaining<=0||characters<=0){entries.push({gap:'Report snippet budget reached. Open the cited source in the workspace.'});break;}
      remaining--;
      try {
        const w=await sourceWindow({...ref,line:ref.startLine},manifest,root);
        const lines=w.lines.filter(l=>l.line>=Math.max(1,ref.startLine-2)&&l.line<=ref.endLine+2).slice(0,options.technical?48:24);
        const bytes=JSON.stringify(lines).length;
        if(bytes>characters){entries.push({gap:'Report snippet size budget reached.'});break;}
        characters-=bytes;
        entries.push({...ref,lines,limited:ref.endLine>(lines.at(-1)?.line||0),basis:'Hash matches the saved source file; cited lines are evidence, not runtime verification.'});
      } catch(error) {entries.push({...ref,gap:'Source unavailable for this saved decision: '+error.message+'. Revalidate before relying on current-source applicability.'});}
    }
    if(unique.length>(options.technical?4:2))entries.push({gap:`${unique.length-(options.technical?4:2)} additional cited ranges remain in the evidence table and technical export.`});
    snippets[threat.id]=entries;
  }
  return systemPrintReport(model,{...options,snippets});
}
