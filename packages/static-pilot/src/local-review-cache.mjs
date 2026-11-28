import {DatabaseSync} from 'node:sqlite';
import {lstatSync,chmodSync,realpathSync} from 'node:fs';
import path from 'node:path';
import {sha,within} from './sources.mjs';

export const LOCAL_REVIEW_CACHE_VERSION='validated-section-response-1';
export function stableJson(v){return JSON.stringify(v,(_,x)=>x&&typeof x==='object'&&!Array.isArray(x)?Object.fromEntries(Object.keys(x).sort().map(k=>[k,x[k]])):x);}
export function cacheableReview(review) {
  if(review?.batchVersion==='section-threat-batch-1')return Array.isArray(review.results)&&review.results.length>0&&review.results.every(r=>!r.error&&cacheableReview(r.review));
  if(review?.assessment)return ['static-supported','ruled-out'].includes(review.assessment)&&!review.decisionReviewRequired&&!review.evidenceGaps?.length&&!review.missingEvidence?.length&&!review.engineering?.obligations?.some(o=>o.status==='missing');
  return review?.categoryReviews?.length===6&&review.categoryReviews.every(c=>['supported-conditional','ruled-out','no-scenario-identified'].includes(c.status)&&!c.missingEvidence?.length);
}
export class LocalReviewCache {
  constructor(file,{sourceRoot,maxEntries=1000,maxBytes=64*1024*1024,maxItemBytes=1024*1024}={}) {
    if([maxEntries,maxBytes,maxItemBytes].some(n=>!Number.isSafeInteger(n)||n<1))throw Error('Invalid review cache limits');
    const parent=realpathSync(path.dirname(file));
    if(sourceRoot&&within(realpathSync(sourceRoot),parent))throw Error('Review cache must be outside source repositories');
    for(const f of [file,file+'-journal',file+'-wal',file+'-shm'])try{if(lstatSync(f).isSymbolicLink())throw Error('Review cache cannot be a symbolic link');}catch(e){if(e.code!=='ENOENT')throw e;}
    this.maxEntries=maxEntries;this.maxBytes=maxBytes;this.maxItemBytes=maxItemBytes;
    this.stats={hits:0,misses:0,invalid:0,writes:0,evictions:0,errors:0};
    this.db=new DatabaseSync(file);chmodSync(file,0o600);
    this.db.exec('PRAGMA journal_mode=DELETE; PRAGMA busy_timeout=3000; PRAGMA auto_vacuum=FULL; CREATE TABLE IF NOT EXISTS responses (key TEXT PRIMARY KEY,payload TEXT NOT NULL,digest TEXT NOT NULL,bytes INTEGER NOT NULL,used INTEGER NOT NULL);');
  }
  get(key) {
    const row=this.db.prepare('SELECT payload,digest,bytes FROM responses WHERE key=?').get(key);
    if(!row){this.stats.misses++;return null;}
    try{if(row.bytes>this.maxItemBytes||Buffer.byteLength(row.payload)!==row.bytes||sha(row.payload)!==row.digest)throw Error('Corrupt cache');return JSON.parse(row.payload);}catch{this.reject(key);this.stats.misses++;return null;}
  }
  accept(key){this.stats.hits++;this.db.prepare('UPDATE responses SET used=? WHERE key=?').run(Date.now(),key);}
  reject(key){this.stats.invalid++;this.db.prepare('DELETE FROM responses WHERE key=?').run(key);}
  put(key,value) {
    const payload=JSON.stringify(value),bytes=Buffer.byteLength(payload);if(bytes>this.maxItemBytes||bytes>this.maxBytes)return;
    this.db.prepare('INSERT OR REPLACE INTO responses VALUES (?,?,?,?,?)').run(key,payload,sha(payload),bytes,Date.now());this.stats.writes++;
    let size=this.db.prepare('SELECT COUNT(*) n,COALESCE(SUM(bytes),0) bytes FROM responses').get();
    while(size.n>this.maxEntries||size.bytes>this.maxBytes){const old=this.db.prepare('SELECT key,bytes FROM responses ORDER BY used,key LIMIT 1').get();this.db.prepare('DELETE FROM responses WHERE key=?').run(old.key);size.n--;size.bytes-=old.bytes;this.stats.evictions++;}
  }
  close(){this.db?.close();this.db=null;}
}
