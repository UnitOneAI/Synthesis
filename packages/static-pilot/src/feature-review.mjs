import { sha } from './sources.mjs';
import { REPOSITORY_CATEGORIES } from './repository-assessment-summary.mjs';

// A projection, not another mutable coverage ledger. Each primary subject is
// counted once in each category, even when it appears in multiple packets.
export function featureReviewSummary(model, system) {
  const review=model.aiReview;
  const ids=new Set(review?.scope?.poc?.interfaceIds || review?.scope?.interfaceIds || []);
  const evidence=new Map(model.evidence.map(e=>[e.id,e]));
  const groups=new Map();
  for(const i of model.interfaces.filter(i=>ids.has(i.id))) {
    const path=i.evidence.map(id=>evidence.get(id)?.path).find(Boolean)||'Unmapped source';
    const key=JSON.stringify([i.repository,i.component,path]);
    if(!groups.has(key))groups.set(key,{id:sha(key).slice(0,16),repository:i.repository,
      name:system.components.find(c=>c.id===i.component)?.name || i.repository,path,interfaceIds:[]});
    groups.get(key).interfaceIds.push(i.id);
  }
  const stale=!review || review.status==='stale' || (review.basedOnRevision&&review.basedOnRevision!==model.modelRevision);
  const assessments=new Map();
  if(!stale)for(const batch of review.batches || [])for(const category of batch.review?.categoryReviews || [])
    for(const id of category.interfaceIds || []) {
      const key=id+'\0'+category.category;
      if(!assessments.has(key))assessments.set(key,[]);
      assessments.get(key).push({batchStatus:batch.status,...category});
    }
  const threats=(system.threats || []).filter(t=>t.origin==='analysis'&&t.reviewState!=='stale');
  const features=[...groups.values()].map(group=>{
    const members=new Set(group.interfaceIds);
    const related=threats.filter(t=>t.interfaceIds?.some(id=>members.has(id)));
    const categories=REPOSITORY_CATEGORIES.map(category=>{
      const counts={decided:0,incomplete:0,pending:0};
      for(const id of members) {
        const results=assessments.get(id+'\0'+category) || [];
        const subjectThreats=related.filter(t=>t.interfaceIds?.includes(id)&&t.categories?.includes(category));
        if(!results.length || results.some(r=>r.batchStatus!=='completed'))counts.pending++;
        else if(results.some(r=>r.status==='evidence-gap') || subjectThreats.some(t=>!['supported','ruled-out'].includes(t.outcome?.kind)))counts.incomplete++;
        else counts.decided++;
      }
      return {category,total:members.size,...counts,state:stale?'stale':counts.decided===members.size?'decision available':counts.incomplete?'incomplete code':counts.decided?'partial':'not reviewed'};
    });
    return {...group,categories,threatIds:related.map(t=>t.id),supported:related.filter(t=>t.outcome?.kind==='supported').length,
      ruledOut:related.filter(t=>t.outcome?.kind==='ruled-out').length,
      actorIds:[...new Set(related.flatMap(t=>t.actorIds||[]))],boundaryIds:[...new Set(related.flatMap(t=>t.boundaryIds||[]))],
      complete:!stale&&categories.every(c=>c.decided===c.total)};
  });
  return {features,complete:features.length>0&&features.every(f=>f.complete),stale,
    interpretation:'Feature groups organize source operations; they do not prove a shared policy. Each subject/category requires a cited result and every returned scenario a settled code decision. Deployment acceptance is separate.'};
}
