// Lossless wire representation. Validation and saved evidence retain the original
// records; shared text never broadens a record's allowed citation range.
export const EVIDENCE_TRANSPORT_VERSION = 'shared-source-text-1';
export const EVIDENCE_TRANSPORT_PROMPT = '\nSOURCE TEXT ENCODING: evidenceText contains numbered source segments shared by records with the same repository, file and hash. A record with textRef reads its source lines from that block, ONLY within its own startLine/endLine. Cite the original record id, never a textRef/block id. Do not infer that unsupplied lines or another record\'s wider range were reviewed. All other packet fields and evidence rules are unchanged.';

function sourceLines(r) {
  if(r && (Object.hasOwn(r,'textRef')||Object.hasOwn(r,'textFields')))return null;
  if (!r || !r.id || !r.repository || !r.path || !r.blobSha256 || !Number.isSafeInteger(r.startLine) || !Number.isSafeInteger(r.endLine)) return null;
  if(Object.hasOwn(r,'lines')&&!Array.isArray(r.lines)||Object.hasOwn(r,'code')&&typeof r.code!=='string')return null;
  let lines;
  if (Array.isArray(r.lines)) {
    if(r.lines.some(l=>!l||typeof l!=='object'||Object.keys(l).some(k=>!['line','text'].includes(k))))return null;
    lines=r.lines;
  } else if (typeof r.code==='string') {
    lines=r.code.split('\n').map(l=>{const m=/^(\d+): (.*)$/.exec(l);return m?{line:Number(m[1]),text:m[2]}:null;});
  } else return null;
  if(!lines.length || lines.some((l,i)=>!l||!Number.isSafeInteger(l.line)||typeof l.text!=='string'||l.text.includes('\n')||l.line!==r.startLine+i)||lines.at(-1).line!==r.endLine)return null;
  if(typeof r.code==='string'&&r.code!==lines.map(l=>`${l.line}: ${l.text}`).join('\n'))return null;
  return lines;
}

export function compactEvidence(packet) {
  const originalBytes=Buffer.byteLength(JSON.stringify(packet));
  if(Object.hasOwn(packet,'evidenceText') || Object.hasOwn(packet,'evidenceEncoding') || [...(packet.records || []),...(packet.sourceContext?.records || [])].some(r=>r&&(Object.hasOwn(r,'textRef')||Object.hasOwn(r,'textFields'))))return {packet,metrics:{originalBytes,wireBytes:originalBytes,removedBytes:0,records:0}};
  const copy=structuredClone(packet),groups=new Map(),records=[];
  for(const r of [...(copy.records || []),...(copy.sourceContext?.records || [])]) {
    const lines=sourceLines(r);if(!lines)continue;
    const key=JSON.stringify([r.repository,r.path,r.blobSha256]);
    if(!groups.has(key))groups.set(key,{id:'text-'+groups.size,repository:r.repository,path:r.path,blobSha256:r.blobSha256,lines:new Map(),records:[],conflict:false});
    const g=groups.get(key);
    for(const l of lines){if(g.lines.has(l.line)&&g.lines.get(l.line)!==l.text)g.conflict=true;g.lines.set(l.line,l.text);}
    g.records.push(r);
  }
  const blocks=[];
  for(const g of groups.values()) {
    if(g.conflict)continue;
    const segments=[];let segment;
    for(const [line,text] of [...g.lines].sort((a,b)=>a[0]-b[0])) {
      if(!segment || line!==segment.last+1){segment={startLine:line,last:line,text};segments.push(segment);}else{segment.text+='\n'+text;segment.last=line;}
    }
    blocks.push({id:g.id,repository:g.repository,path:g.path,blobSha256:g.blobSha256,segments:segments.map(({last,...s})=>s)});
    for(const r of g.records){r.textRef=g.id;r.textFields=['lines','code'].filter(k=>Object.hasOwn(r,k));delete r.lines;delete r.code;records.push(r);}
  }
  if(!records.length)return {packet,metrics:{originalBytes,wireBytes:originalBytes,removedBytes:0,records:0}};
  copy.evidenceEncoding=EVIDENCE_TRANSPORT_VERSION;copy.evidenceText=blocks;
  const wireBytes=Buffer.byteLength(JSON.stringify(copy));
  // Avoid introducing another representation for negligible savings. Include
  // the wire instruction itself in the threshold (at least five percent net).
  if(originalBytes-wireBytes-Buffer.byteLength(EVIDENCE_TRANSPORT_PROMPT)<originalBytes*0.05)return {packet,metrics:{originalBytes,wireBytes:originalBytes,removedBytes:0,records:0}};
  return {packet:copy,metrics:{originalBytes,wireBytes,removedBytes:originalBytes-wireBytes,records:records.length}};
}

export function expandEvidence(packet) {
  if(packet.evidenceEncoding!==EVIDENCE_TRANSPORT_VERSION)return structuredClone(packet);
  const copy=structuredClone(packet),blocks=new Map(copy.evidenceText.map(b=>[b.id,b]));
  for(const r of [...(copy.records || []),...(copy.sourceContext?.records || [])]) {
    if(!r.textRef)continue;
    const b=blocks.get(r.textRef);
    if(!b||b.repository!==r.repository||b.path!==r.path||b.blobSha256!==r.blobSha256)throw Error('Evidence text ownership mismatch');
    const lines=b.segments.flatMap(s=>s.text.split('\n').map((text,i)=>({line:s.startLine+i,text}))).filter(l=>l.line>=r.startLine&&l.line<=r.endLine);
    if(lines.length!==r.endLine-r.startLine+1||lines.some((l,i)=>l.line!==r.startLine+i))throw Error('Evidence text range incomplete');
    if(r.textFields.includes('lines'))r.lines=lines;
    if(r.textFields.includes('code'))r.code=lines.map(l=>`${l.line}: ${l.text}`).join('\n');
    delete r.textRef;delete r.textFields;
  }
  delete copy.evidenceEncoding;delete copy.evidenceText;return copy;
}
