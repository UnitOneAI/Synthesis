import { graphReader } from "./graph-store.mjs";
import { sourceWindow, verifiedSourceFile } from "./graph-package.mjs";
import { id } from "./sources.mjs";
import { sourceScope } from "./architecture.mjs";
export class InvestigationSource {
  constructor(model, manifest, root) {
    this.model = model;
    this.manifest = manifest;
    this.root = root;
    this.graph = model.sourceGraph;
    this.disk = graphReader(this.graph);
    this.generation = this.graph?.generation;
    if (this.graph?.storage === "sqlite" && !this.disk)
      throw Error("Saved source graph reader unavailable");
    this.selected = new Set(
      manifest.repositories
        .filter((r) => r.selected !== false)
        .map((r) => r.name),
    );
    this.memoryNodes = this.graph?.nodes || [];
    this.byId = new Map(this.memoryNodes.map((n) => [n.id, n]));
  }
  nodes(options = {}) {
    if (this.disk) return [...this.disk.nodes(this.generation, options)];
    return this.memoryNodes
      .filter(
        (n) =>
          (!options.kind || n.kind === options.kind) &&
          (!options.repository || n.repository === options.repository) &&
          (!options.path || n.path === options.path) &&
          (!options.after || n.id > options.after),
      )
      .sort((a, b) => a.id.localeCompare(b.id))
      .slice(0, options.limit || 100);
  }
  node(nid) {
    const n = this.disk
      ? this.disk.node(this.generation, nid)
      : this.byId.get(nid);
    return n && this.selected.has(n.repository) ? n : null;
  }
  file(repository, path) {
    if (!this.selected.has(repository)) return null;
    return this.nodes({ kind: "file", repository, path, limit: 1 })[0] || null;
  }
  files(repository, after = "") {
    const rows = this.nodes({ kind: "file", repository, after, limit: 33 });
    return {
      items: rows.slice(0, 32),
      next: rows.length > 32 ? rows[31].id : null,
    };
  }
  search(symbol, after = "") {
    let rows, next;
    if (this.disk) {
      const page = this.disk.page(this.generation, {
        search: symbol,
        after,
        limit: 32,
      });
      rows = page.items;
      next = page.next;
    } else {
      const matched = this.memoryNodes
        .filter(
          (n) =>
            n.id > after &&
            `${n.name || ""} ${n.path || ""}`
              .toLowerCase()
              .includes(symbol.toLowerCase()),
        )
        .sort((a, b) => a.id.localeCompare(b.id));
      rows = matched.slice(0, 32);
      next = matched.length > 32 ? rows.at(-1).id : null;
    }
    return {
      items: rows.filter((n) => this.selected.has(n.repository) && n.path),
      next,
    };
  }
  edges(nid, after = "") {
    if (this.disk)
      return this.disk.incidentPage(this.generation, nid, { after, limit: 32 });
    const rows = (this.graph.edges || [])
      .filter((e) => (e.from === nid || e.to === nid) && e.id > after)
      .sort((a, b) => a.id.localeCompare(b.id));
    return {
      items: rows.slice(0, 32),
      next: rows.length > 32 ? rows[31].id : null,
    };
  }
  async window(ref) {
    const f = this.file(ref.repository, ref.path);
    if (!f || (ref.blobSha256 && ref.blobSha256 !== f.blobSha256))
      throw Error("source-not-in-current-index");
    const w = await sourceWindow(
      { ...ref, blobSha256: f.blobSha256 },
      this.manifest,
      this.root,
    );
    return {
      id: id(
        "investigation-record",
        w.repository,
        w.path,
        w.blobSha256,
        w.startLine,
        w.endLine,
      ),
      ...w,
      sourceScope: sourceScope(w.path),
      code: w.lines.map((l) => `${l.line}: ${l.text}`).join("\n"),
    };
  }
  async functionWindow(ref) {
    if(['class','type'].includes(ref.kind))return this.window(ref);
    const line=ref.line || 1;
    const nodes=this.nodes({kind:'function',repository:ref.repository,path:ref.path,limit:129});
    const candidates=nodes.filter(n=>Number.isInteger(n.endLine) && n.endLine>=line && n.line<=line+4)
      .sort((a,b)=>Math.abs(a.line-line)-Math.abs(b.line-line));
    const n=candidates[0];
    if(nodes.length>128 || (candidates[1] && Math.abs(n.line-line)===Math.abs(candidates[1].line-line)))return {...await this.window(ref),functionContext:{complete:false,reason:nodes.length>128?'function-index-page-limit':'ambiguous-function-owner'}};
    if(!n)return this.window(ref);
    const first=Math.min(line,n.line),last=n.endLine;
    if(last-first+1>200)return {...await this.window(ref),functionContext:{name:n.name,startLine:first,endLine:last,complete:false,reason:'function-exceeds-200-line-window'}};
    const lines=[];let seed;
    for(let cursor=first;cursor<=last;cursor+=80){
      const w=await this.window({...ref,line:cursor+20});seed ||= w;
      lines.push(...w.lines.filter(l=>l.line>=cursor && l.line<=Math.min(cursor+79,last)));
    }
    if(lines.length!==last-first+1)throw Error('source-function-range-incomplete');
    return {...seed,id:id('function-evidence',seed.repository,seed.path,seed.blobSha256,first,last),startLine:first,endLine:last,lines,code:lines.map(l=>`${l.line}: ${l.text}`).join('\n'),functionContext:{name:n.name,startLine:first,endLine:last,complete:true}};
  }
  // Fallback only for exact requested implementations missing from the symbol
  // index. Searches saved, selected files, never arbitrary model-supplied paths.
  async findImplementation(symbols, seeds = [], {maxFiles=64,maxBytes=2*1024*1024} = {}) {
    const names=[...new Set(symbols)].filter(s=>/^[A-Za-z_]\w{2,99}(?:\.[A-Za-z_]\w{0,99}){0,2}$/.test(s)).slice(0,12);
    if(!names.length)return {references:[],searchedFiles:0,bytes:0,limited:false,failures:[]};
    const repositories=[...new Set([...seeds.map(s=>s.repository),...this.selected])].filter(r=>this.selected.has(r));
    const candidates=[];let limited=false;
    // Search named paths before the bounded general inventory. Otherwise a
    // relevant control file beyond the first page would never be considered.
    for(const symbol of names) {
      const found=this.search(symbol);limited ||= Boolean(found.next);
      for(const node of found.items) {
        const file=node.kind==='file'?node:this.file(node.repository,node.path);
        if(file)candidates.push(file);
      }
    }
    for(const seed of seeds) {const file=this.file(seed.repository,seed.path);if(file)candidates.push(file);}
    for(const repository of repositories) {
      const rows=this.nodes({kind:'file',repository,limit:257});limited ||= rows.length>256;
      candidates.push(...rows.slice(0,256).filter(n=>/\.(cs|py|[cm]?[jt]sx?|java|go|rb|php|cpp|cc|c|h)$/i.test(n.path)));
    }
    const rank=n=>seeds.some(s=>s.repository===n.repository&&s.path===n.path)?0:
      names.some(s=>n.path.toLowerCase().includes(s.replace(/^I(?=[A-Z])/,'').toLowerCase()))?1:
      seeds.some(s=>s.repository===n.repository)?2:3;
    candidates.sort((a,b)=>rank(a)-rank(b)||a.repository.localeCompare(b.repository)||a.path.localeCompare(b.path));
    const references=[],failures=[];let searchedFiles=0,bytes=0;
    for(const n of [...new Map(candidates.filter(n=>/\.(cs|py|[cm]?[jt]sx?|java|go|rb|php|cpp|cc|c|h)$/i.test(n.path)).map(n=>[n.repository+'\0'+n.path,n])).values()]) {
      if(searchedFiles>=maxFiles||bytes>=maxBytes){limited=true;break;}
      searchedFiles++;
      try {
        const file=await verifiedSourceFile(n,this.manifest,this.root);
        bytes+=file.bytes;if(bytes>maxBytes){limited=true;break;}
        for(const symbol of names) {
          // A text match is a candidate, never proof of a call or control binding.
          const escaped=symbol.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
          const localMember=symbol.includes('.')&&seeds.some(s=>s.repository===n.repository&&s.path===n.path);
          const pattern=new RegExp('\\b'+(localMember?'[A-Za-z_]\\w*\\.'+symbol.split('.').at(-1):escaped)+'\\b');
          const matches=file.lines.flatMap((text,index)=>pattern.test(text)?[index+1]:[]).slice(0,4);
          for(const line of matches) if(!references.some(r=>r.repository===n.repository&&r.path===n.path&&r.line===line))
            references.push({repository:n.repository,path:n.path,line,blobSha256:n.blobSha256,symbol,required:true,basis:'hash-checked indexed text candidate; binding unproven'});
        }
      } catch(error) { failures.push({repository:n.repository,path:n.path,reason:error.message}); }
      if(references.length>=16){limited=true;break;}
    }
    return {references:references.slice(0,16),searchedFiles,bytes,limited,failures,
      interpretation:'Bounded identifier/member search in indexed source; local receiver aliases are candidates, not proven bindings. No match does not establish an absent control.'};
  }
  catalog(records) {
    const map = new Map();
    let omitted = false;
    for (const r of records) {
      const nodes = this.nodes({
        repository: r.repository,
        path: r.path,
        limit: 129,
      });
      if (nodes.length > 128) omitted = true;
      for (const n of nodes.slice(0, 128))
        if (n.line >= r.startLine && n.line <= r.endLine)
          map.set(n.id, {
            id: n.id,
            kind: n.kind,
            name: n.name,
            repository: n.repository,
            path: n.path,
            line: n.line,
          });
    }
    return {
      nodes: [...map.values()].slice(0, 128),
      omitted: omitted || map.size > 128,
    };
  }
}
