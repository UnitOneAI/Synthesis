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
  const names = [...new Set([...bootstrap,...controlSymbols(text), 'Authorize','AuthorizeAttribute','AllowAnonymous','Startup','Program','RootController','ConfigureServices','AddAuthorization','UseAuthentication','UseAuthorization'])].slice(0,32);
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
    matches.sort((a,b)=>Number(sourceScope(a.path)!=='production-candidate')-Number(sourceScope(b.path)!=='production-candidate') || Number(near(b))-Number(near(a)) || Number(repositories.has(b.repository))-Number(repositories.has(a.repository)) || Number(a.kind==='file')-Number(b.kind==='file'));
    searches.push({symbol,matches:matches.length,truncated:result.truncated});
    for(const n of matches.slice(0,3)) if(!references.some(r=>r.repository===n.repository && r.path===n.path && Math.abs(r.line-(n.line||1))<20))
      references.push({repository:n.repository,path:n.path,line:n.line||1,basis:'control-candidate; applicability unproven'});
  }
  return {references:references.slice(0,12),searches,omitted:Math.max(0,references.length-12),basis:'Named control and framework candidates, not verified enforcement'};
}
