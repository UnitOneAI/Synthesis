import {sourceScope} from './architecture.mjs';
// Static candidate retrieval. A declaration is not proof that a control applies.
const caches = new WeakMap();
export function controlSymbols(text) {
  const value = String(text);
  const identifiers = value.match(/\b[A-Za-z_][A-Za-z0-9_]*\b/g) || [];
  // Private helpers and acronym-prefixed types carry control/serialization logic too.
  const named = identifiers.filter(n => /[A-Za-z0-9]_[A-Za-z0-9]|^_[A-Za-z]|[a-z][A-Z]|[A-Z]{2,}[a-z]/.test(n));
  const attributes = [...value.matchAll(/\[\s*([A-Za-z_]\w*)/g)].map(m=>m[1]);
  const framework = ['Authorize','AuthorizeAttribute','AllowAnonymous','Startup','Program','Configure','ConfigureServices','Authentication','Authorization','Depends'].filter(n=>new RegExp('\\b'+n+'\\b').test(value));
  named.sort((a,b)=>Number(/auth|key|policy|permission|access|guard|filter|principal/i.test(b))-Number(/auth|key|policy|permission|access|guard|filter|principal/i.test(a)));
  return [...new Set([...attributes,...framework,...named])].filter(s=>s.length>=3 && s.length<=100).slice(0,24);
}
export async function controlContext(source, seeds, text = '') {
  let cache = caches.get(source); if (!cache) {cache=new Map();caches.set(source,cache);}
  const repositories = new Set(seeds.map(s=>s.repository));
  const bootstrap = seeds.some(s=>/\.py$/i.test(s.path)) ? ['create_app','lifespan','setup_rate_limiting'] : ['Startup','Program','ConfigureServices'];
  // Exact controls from the reviewed code precede generic framework candidates.
  // An interface declaration alone cannot establish the implementing control.
  const explicit = controlSymbols(text);
  const names = [...new Set([...bootstrap,...explicit.flatMap(n=>/^I[A-Z]/.test(n)?[n,n.slice(1)]:[n]), 'Authorize','AuthorizeAttribute','AllowAnonymous','Startup','Program','RootController','ConfigureServices','AddAuthorization','UseAuthentication','UseAuthorization'])].slice(0,40);
  const references=[], searches=[];
  for (const symbol of names) {
    let result=cache.get(symbol);
    if (!result) {
      const nodes=[]; let after='';
      for(let page=0;page<4;page++) { const r=source.search(symbol,after);nodes.push(...r.items);after=r.next;if(!after)break; }
      result={nodes,truncated:Boolean(after)};cache.set(symbol,result);
    }
    const matches=result.nodes.filter(n=>n.kind==='file' || n.name===symbol || n.name?.endsWith('.'+symbol) || n.name?.endsWith('::'+symbol));
    const near = n => seeds.some(s=>{const parent=s.path.split(/\/(?:Controllers|controllers|routes)\//)[0];const directory=parent===s.path?s.path.slice(0,Math.max(0,s.path.lastIndexOf('/'))):parent;return s.repository===n.repository && (!directory || n.path.startsWith(directory+'/'));});
    const definition=n=>['function','class','method','type'].includes(n.kind);
    matches.sort((a,b)=>Number(definition(b))-Number(definition(a)) || Number(sourceScope(a.path)!=='production-candidate')-Number(sourceScope(b.path)!=='production-candidate') || Number(near(b))-Number(near(a)) || Number(repositories.has(b.repository))-Number(repositories.has(a.repository)) || Number(a.kind==='file')-Number(b.kind==='file'));
    searches.push({symbol,matches:matches.length,truncated:result.truncated,interpretation:'Indexed name/path matches only; zero matches do not establish absence'});
    const production=matches.filter(n=>sourceScope(n.path)==='production-candidate');
    const relevantScope=seeds.every(s=>sourceScope(s.path)==='production-candidate') && production.length ? production : matches;
    const relevant= relevantScope.some(definition) ? relevantScope.filter(definition) : relevantScope;
    for(const n of relevant.slice(0,3)) if(!references.some(r=>r.repository===n.repository && r.path===n.path && Math.abs(r.line-(n.line||1))<20))
      references.push({repository:n.repository,path:n.path,line:n.line||1,basis:bootstrap.includes(symbol)?'application-registration-candidate':'control-candidate; applicability unproven'});
  }
  // Registration methods often name a requirement or handler that is not named
  // at the route. Follow one bounded hop from hash-checked candidate code, using
  // the existing graph index rather than scanning all repositories again.
  const discovered=[];
  for (const ref of references.filter(r=>repositories.has(r.repository)).slice(0,6)) {
    if (!source.window) break;
    try {
      const window=await source.window(ref);
      for(const symbol of controlSymbols(window.code || '').filter(n=>/Requirement|Handler|Policy|Permission|Access|Authorize/.test(n))) {
        if(names.includes(symbol) || discovered.includes(symbol)) continue;
        discovered.push(symbol);
        if(discovered.length>=12) break;
      }
    } catch { /* Candidate reads do not establish absence; final retrieval reports failures. */ }
    if(discovered.length>=12) break;
  }
  for(const symbol of discovered) {
    const result=source.search(symbol);
    const matches=result.items.filter(n=>n.name===symbol || n.name?.endsWith('.'+symbol) || n.name?.endsWith('::'+symbol));
    searches.push({symbol,matches:matches.length,truncated:Boolean(result.next),basis:'identifier from candidate source; binding unproven'});
    for(const n of matches.slice(0,2)) if(!references.some(r=>r.repository===n.repository && r.path===n.path && Math.abs(r.line-(n.line||1))<20))
      references.splice(Math.min(6,references.length),0,{repository:n.repository,path:n.path,line:n.line||1,basis:'control implementation candidate; registration and applicability require assessment'});
  }
  return {references:references.slice(0,12),searches,omitted:Math.max(0,references.length-12),basis:'Named control, implementation and registration candidates, not verified enforcement; absent index matches do not prove absent controls'};
}
