import {repositoryAssessmentSummary} from './repository-assessment-summary.mjs';
import {actorAccess, threatAccess} from './threat-access.mjs';
import { threatAssessment } from './threat-validation-state.mjs';
import { sourceScope } from "./architecture.mjs";

// Display references never replace saved IDs or enter review fingerprints.
export function addReviewPresentation(s, model) {
  for (const [kind, prefix] of [
    ["threats", "T"],
    ["boundaries", "TB"],
    ["flows", "F"],
  ]) {
    const counts = new Map();
    for (const r of s[kind]) {
      const key = r.id.slice(0, 8).toUpperCase();
      counts.set(key, (counts.get(key) || 0) + 1);
    }
    for (const r of s[kind])
      r.reference = `${prefix}-${(counts.get(r.id.slice(0, 8).toUpperCase()) > 1 ? r.id : r.id.slice(0, 8)).toUpperCase()}`;
  }
  for (const a of s.actors || []) a.access = actorAccess(a);
  const actors = new Map((s.actors || []).map(a => [a.id, a]));
  for (const t of s.threats) t.access = threatAccess(t, actors);
  const evidence = new Map(model.evidence.map((e) => [e.id, e]));
  const interfaces = new Map((model.interfaces || []).map((i) => [i.id, i]));
  const nodes = new Map([...s.components, ...s.entities].map((n) => [n.id, n]));
  const flows = new Map(s.flows.map((f) => [f.id, f]));
  const sourceThreats=new Map((model.aiReview?.threats||[]).map(t=>[t.id,t]));
  const sourceBatches=new Map((model.aiReview?.batches||[]).filter(b=>b.status==='completed').map(b=>[b.id,b]));
  for (const b of s.boundaries)
    b.crossings = (b.flowIds || [])
      .map((id) => flows.get(id))
      .filter(Boolean)
      .map((f) => ({
        id: f.id,
        reference: f.reference,
        from: nodes.get(f.source)?.name || f.source,
        to: nodes.get(f.target)?.name || f.target,
        basis: f.basis,
        reviewState: f.reviewState,
      }));
  for (const t of s.threats) {
    if (t.origin === "review checklist") continue;
    const refs = (t.evidenceIds || [])
      .map((id) => evidence.get(id))
      .filter(Boolean);
    const scopes = [...new Set(refs.map((e) => sourceScope(e.path)))];
    t.sourceScopes = scopes;
    t.metadataOnly = model.aiReview?.mode === 'metadata' || /metadata.only/i.test(JSON.stringify(t.analysisQuality?.gaps || [])) || Boolean(
      t.interfaceIds?.length &&
        t.interfaceIds.every(
          (id) =>
            interfaces.get(id)?.kind === "architecture" &&
            interfaces.get(id)?.connection?.role !== "symbol-call",
        ),
    );
    t.boundaryLinkBasis = t.candidateFlowIds?.length
      ? "Candidate boundaries associated through shared interfaces. Some flow peers remain unresolved; access, crossing relevance and enforcement are assumptions requiring review."
      : "Boundaries associated through shared interfaces; verify relevance to this scenario.";
    const reasons = [];
    let rank = 3,
      label = "Establish context";
    const severity = !t.decision?.stale ? t.decision?.severity : null;
    if (t.reviewState === "stale") {
      rank = 5;
      label = "Revalidate";
      reasons.push("The source or review decision is stale.");
    } else if (
      ["rejected", "not-applicable", "risk-accepted"].includes(t.reviewState)
    ) {
      rank = 5;
      label = "Decision recorded";
      reasons.push(`Reviewer disposition: ${t.reviewState}.`);
    } else if (
      scopes.length &&
      scopes.every((x) => x !== "production-candidate")
    ) {
      rank = 4;
      label = "Verify applicability";
      reasons.push(
        "Citations are confined to test or generated/vendor code; establish deployment applicability.",
      );
    } else if (severity && severity !== "unassessed") {
      rank = ["high", "critical"].includes(severity)
        ? 0
        : severity === "medium"
          ? 2
          : 3;
      label = rank === 0 ? "Review first" : "Review next";
      reasons.push(`Reviewer-assessed severity: ${severity}.`);
    } else if (t.metadataOnly) {
      rank = 3;
      label = "Establish code path";
      reasons.push(
        "Citations support architecture or import references only; the claimed implementation and caller path are not established.",
      );
    } else if (scopes.includes("production-candidate")) {
      const authority = t.categories.some((c) =>
        ["Spoofing", "Elevation of Privilege"].includes(c),
      );
      rank = authority ? 1 : 2;
      label = authority ? "Review first" : "Review next";
      reasons.push(
        "Citations include production-candidate source; deployed exposure is unverified.",
      );
      reasons.push(
        authority
          ? "The scenario concerns identity or privilege misuse."
          : "Assess the stated impact and prerequisites against effective controls.",
      );
    } else reasons.push("No usable source citations establish applicability.");
    const argument = [t.name,t.scenario,t.analysis?.impact,t.prerequisites,t.controls].join(' ');
    t.followUpKind = /if (?:the )?(?:fallback |handler |code )?(?:handler )?(?:were |is )?(?:modified|changed)|would need to be changed|future (?:code )?change/i.test(argument)
      ? 'Change-regression / hardening'
      : refs.some(r=>/(?:package-lock|yarn.lock|packages.lock|package.json)/i.test(r.path)) && /known.vulnerab|outdated|supply.chain|dependency/i.test(t.name) && !/CVE-\d{4}-\d+/i.test(argument)
        ? 'Dependency / build review obligation' : null;
    if (t.followUpKind && !severity) {rank=4;label=t.followUpKind;reasons.push('Preserved follow-up; not a demonstrated current exploitable path.');}
    t.validation = threatAssessment(model, t.id);
    const sourceThreat=sourceThreats.get(t.id);
    const sourceBatch=sourceBatches.get(sourceThreat?.batchId);
    const categoryAssessment=sourceBatch?.review?.categoryReviews?.find(c=>t.categories.includes(c.category));
    if(categoryAssessment && t.reviewState!=='stale'){
      t.categoryAssessment={...categoryAssessment,citations:categoryAssessment.citations.map(c=>({...c,...sourceBatch.evidenceContext?.records?.find(r=>r.id===c.recordId),line:c.line,endLine:c.endLine}))};
      if(model.aiReview.mode==='source-excerpts'&&t.categoryAssessment.citations.some(c=>refs.some(r=>c.repository===r.repository&&c.path===r.path&&c.line<=r.line&&c.endLine>=r.line)))t.metadataOnly=false;
      if(categoryAssessment.status==='supported-conditional'&&rank<4){rank=1;label='Conditional concern — source assessment';reasons.unshift(categoryAssessment.rationale);}
      if(categoryAssessment.status==='ruled-out'){rank=5;label='Category ruled out with cited counterevidence';reasons.unshift(categoryAssessment.rationale);}
    }
    if (t.validation.assessment === 'ruled-out') { rank = 5; label = 'Counterevidence found'; reasons.unshift('A separate source assessment found a control that rules out this stated path; reviewer confirmation is still required.'); }
    else if (t.validation.assessment === 'static-supported' && rank < 4) { rank = Math.min(rank, 1); label = 'Source-supported concern'; reasons.unshift('Separate assessment cites input and sink evidence; deployed exploitability remains unverified.'); }
    // Actor selection is a scenario hypothesis, not attribution or proof of access.
    const selectedActors = (t.actorIds || []).map(id => actors.get(id)).filter(Boolean);
    const entrySteps = (t.validation.trace || []).filter(step => step.role === 'input');
    t.actorRationale = {
      profiles: selectedActors.map(a => `${a.name}: ${a.startingAccess || 'Initial access not established'}`).join('; ') || 'Actor profile not established',
      whyInScope: t.prerequisites || 'No access prerequisite recorded; establish it before relying on this scenario.',
      entryEvidence: entrySteps.map(step => `${step.repository} / ${step.path}:${step.line} — ${step.reason}`).join('; ') || 'No independently assessed entry-point citation. Scenario source references alone do not establish actor access.',
      proposedPath: (t.analysis?.attackSteps || []).join(' → ') || 'No attack path recorded.',
      interpretation: 'This profile represents a capability relevant to the stated path. It is not evidence of an actual attacker, malicious intent, or deployed reachability. Legitimate users become part of a threat scenario only under the stated misuse or compromise conditions.',
    };
    if(!entrySteps.length && t.categoryAssessment?.citations.some(c=>c.role==='input'))t.actorRationale.entryEvidence=t.categoryAssessment.citations.filter(c=>c.role==='input').map(c=>`${c.repository} / ${c.path}:${c.line}–${c.endLine} — category source assessment; deployed access unverified`).join('; ');
    const conclusion = model.sourceConclusions?.[t.id];
    if (conclusion?.issueHash && conclusion.issueHash === t.validation.issueHash &&
        conclusion.contextKey === t.validation.contextKey &&
        conclusion.citations.every(c => t.validation.evidence?.some(r =>
          r.repository === c.repository && r.path === c.path && r.blobSha256 === c.blobSha256 &&
          r.startLine <= c.startLine && r.endLine >= c.endLine)) && t.reviewState !== "stale") {
      t.sourceConclusion = conclusion;
      if (conclusion.status === "conditional") {
        rank = 0;
        label = "Conditional threat with cited evidence";
        reasons.unshift(conclusion.statement);
      }
    }
    t.reviewPriority = {
      rank,
      label,
      reasons,
      interpretation:
        "Review order, not a vulnerability severity or confirmation of exploitability.",
    };
    t.evidenceStatus = t.metadataOnly
      ? "Architecture references only; implementation path unverified"
      : t.analysisQuality?.status === "incomplete"
        ? "Limited analysis context"
        : "Source-referenced scenario; exploitability unverified";
  }
  const review = model.aiReview,
    coverage = review?.coverage;
  s.analysisStatus = {
    state:
      review?.status === "stale"
        ? "stale"
        : !review
          ? "not-analyzed"
          : coverage?.completedBatches
            ? coverage.pendingBatches || coverage.failedBatches
              ? "partially-analyzed"
              : "analyzed"
            : review.status === "failed"
              ? "failed"
              : "not-analyzed",
    completed: coverage?.completedBatches || 0,
    pending: coverage?.pendingBatches || 0,
    failed: coverage?.failedBatches || 0,
    total: coverage?.totalBatches || 0,
  };
  s.repositoryAssessment = repositoryAssessmentSummary(review);
  if(s.repositoryAssessment && !s.repositoryAssessment.stale && s.analysisStatus.state==='analyzed' && !s.repositoryAssessment.complete) s.analysisStatus.state='partially-analyzed';
  const failed = new Set(
    (review?.batches || [])
      .filter((b) => b.status === "failed")
      .flatMap((b) => b.interfaceIds || []),
  );
  const threatById = new Map(s.threats.map((t) => [t.id, t]));
  const categoryIndex=new Map();
  for(const b of sourceBatches.values())for(const c of b.review?.categoryReviews||[])for(const id of c.interfaceIds){const key=JSON.stringify([c.category,id]);if(!categoryIndex.has(key))categoryIndex.set(key,[]);categoryIndex.get(key).push(c);}
  const primaryScope=new Set(review?.scope?.poc?.interfaceIds||[]);
  for (const row of s.matrix || [])
    for (const cell of row.cells) {
      const scenarios = cell.threatIds.map(id => threatById.get(id)).filter(t => t && t.origin !== 'review checklist');
      cell.questionCount = scenarios.filter(t => t.metadataOnly).length;
      cell.scenarioCount = scenarios.length - cell.questionCount;
      const hasFailed = row.interfaceIds.some((id) => failed.has(id));
      cell.analysisStatus =
        review?.status === "stale"
          ? "stale"
          : row.interfaceIds.length &&
              row.reviewedInterfaces === row.interfaceIds.length
            ? cell.scenarioCount
              ? "scenarios-identified"
              : cell.questionCount ? "context-required" : "analyzed-no-scenario"
            : row.reviewedInterfaces
              ? "partially-analyzed"
              : hasFailed
                ? "failed"
                : "not-analyzed";
      if(s.repositoryAssessment && review?.status!=='stale'){
        const selected=row.interfaceIds.filter(id=>primaryScope.has(id));
        const assessments=[...new Set(selected.flatMap(id=>categoryIndex.get(JSON.stringify([cell.category,id]))||[]))];
        const accounted=new Set(assessments.flatMap(c=>c.interfaceIds));
        cell.analysisStatus=!selected.length?'outside-scope':selected.some(id=>!accounted.has(id))?'partially-analyzed':assessments.some(c=>c.status==='evidence-gap')?'evidence-gap':assessments.some(c=>c.status==='supported-conditional')?'scenarios-identified':assessments.every(c=>c.status==='ruled-out')?'ruled-out':'analyzed-no-scenario';
      }
      cell.analysisLabel = {
        'outside-scope':'Supporting context — outside primary scope',
        'evidence-gap':'Reviewed — evidence gap',
        'ruled-out':'Reviewed — cited counterevidence',
        stale: "Stale analysis",
        "scenarios-identified": "Scenarios identified",
        "context-required": "Architecture questions — code evidence needed",
        "analyzed-no-scenario": "Analyzed — no scenario identified",
        "partially-analyzed": "Partially analyzed",
        failed: "Analysis failed",
        "not-analyzed": "Not analyzed",
      }[cell.analysisStatus];
      cell.failedEvidence = hasFailed;
      cell.scenarioReferences = cell.threatIds
        .map((id) => threatById.get(id))
        .filter((t) => t && t.origin !== "review checklist" && !t.metadataOnly)
        .map((t) => t.reference);
    }
  return s;
}
