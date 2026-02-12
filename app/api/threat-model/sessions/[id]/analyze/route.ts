import { NextRequest, NextResponse } from "next/server";
import { v4 as uuidv4 } from "uuid";
import {
  getSession,
  updateSession,
  createThreat,
  createMitigation,
  createDesignReview,
} from "@/lib/db";
import { analyzeRepo } from "@/lib/threat-engine/repo-analyzer";
import {
  generateThreats,
  generateThreatsFromDocument,
  type Framework,
} from "@/lib/threat-engine/threat-generator";
import { generateDFD } from "@/lib/threat-engine/dfd-generator";
import {
  generateDesignEnhancements,
  generatePreCodeRisks,
  generateContextLayer,
} from "@/lib/threat-engine/design-review-engine";
import { calculateRiskRating } from "@/lib/threat-engine/owasp-risk-engine";

// POST /api/threat-model/sessions/:id/analyze — Trigger analysis pipeline
export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const session = getSession(id);

  if (!session) {
    return NextResponse.json(
      { error: "Session not found" },
      { status: 404 }
    );
  }

  if (session.status !== "Processing") {
    return NextResponse.json(
      { error: "Session is not in Processing status" },
      { status: 400 }
    );
  }

  // Run analysis asynchronously — return immediately
  // The frontend will poll GET /sessions/:id for status updates
  runAnalysisPipeline(id, session.source, session.source_ref, session.framework).catch(
    (error) => {
      console.error(`Analysis pipeline failed for session ${id}:`, error);
      updateSession(id, { status: "Failed" });
    }
  );

  return NextResponse.json({
    status: "Processing",
    message: "Analysis pipeline started",
  });
}

async function runAnalysisPipeline(
  sessionId: string,
  source: string,
  sourceRef: string,
  framework: string
) {
  try {
    const frameworkType = (framework || "STRIDE") as Framework;

    if (source === "github-repo") {
      await analyzeGitHubRepo(sessionId, sourceRef, frameworkType);
    } else {
      await analyzeDesignDoc(sessionId, sourceRef, frameworkType);
    }
  } catch (error) {
    console.error(`Pipeline error for session ${sessionId}:`, error);
    updateSession(sessionId, { status: "Failed" });
    throw error;
  }
}

async function analyzeGitHubRepo(
  sessionId: string,
  repoUrl: string,
  framework: Framework
) {
  // Step 1: Clone and analyze repo
  console.log(`[${sessionId}] Step 1: Analyzing repo ${repoUrl}`);
  const analysis = await analyzeRepo(repoUrl, sessionId);

  // Step 2: Generate DFD
  console.log(`[${sessionId}] Step 2: Generating DFD`);
  const dfdMermaid = generateDFD(analysis);
  updateSession(sessionId, { dfd_mermaid: dfdMermaid });

  // Step 3: Generate threats via LLM
  console.log(`[${sessionId}] Step 3: Generating threats`);
  const generatedThreats = await generateThreats(analysis, framework);

  // Step 4: Persist threats and mitigations
  const shortId = sessionId.split("-").pop() || sessionId.slice(-8);
  console.log(`[${sessionId}] Step 4: Persisting ${generatedThreats.length} threats`);
  for (let i = 0; i < generatedThreats.length; i++) {
    const gt = generatedThreats[i];
    const threatId = `TC-${shortId}-${String(i + 1).padStart(3, "0")}`;

    const riskRating = calculateRiskRating(gt.owaspLikelihood, gt.owaspImpact);

    createThreat({
      id: threatId,
      sessionId,
      title: gt.title,
      strideCategory: gt.strideCategory,
      severity: riskRating.riskSeverity === "Note" ? "Low" : riskRating.riskSeverity,
      threatSource: gt.threatSource,
      prerequisites: gt.prerequisites,
      threatAction: gt.threatAction,
      threatImpact: gt.threatImpact,
      impactedAssets: gt.impactedAssets,
      trustBoundary: gt.trustBoundary,
      assumptions: gt.assumptions,
      relatedCve: gt.relatedCve,
      owaspLikelihoodScore: riskRating.likelihoodScore,
      owaspImpactScore: riskRating.impactScore,
      owaspRiskLevel: riskRating.riskSeverity,
      owaspFactors: JSON.stringify({
        likelihood: riskRating.likelihood,
        impact: riskRating.impact,
      }),
    });

    // Persist mitigations
    for (let j = 0; j < gt.mitigations.length; j++) {
      const mit = gt.mitigations[j];
      const mitId = `MIT-${shortId}-${String(i + 1).padStart(3, "0")}-${String(j + 1).padStart(2, "0")}`;

      createMitigation({
        id: mitId,
        threatId,
        description: mit.description,
        status: "Proposed",
        codeFile: mit.codeFile,
        codeLine: mit.codeLine,
        codeOriginal: mit.codeOriginal,
        codeFixed: mit.codeFixed,
      });
    }
  }

  // Step 5: Update session status
  const description = `Threat model for ${repoUrl}. Analyzed ${analysis.components.length} components, ${analysis.dataFlows.length} data flows, ${analysis.securityFindings.length} security findings. Generated ${generatedThreats.length} threats.`;
  updateSession(sessionId, {
    status: "Review",
    description,
  });

  console.log(`[${sessionId}] Analysis complete — ${generatedThreats.length} threats generated`);
}

async function analyzeDesignDoc(
  sessionId: string,
  docRef: string,
  framework: Framework
) {
  console.log(`[${sessionId}] Analyzing design document: ${docRef}`);

  // Read document content from session
  const session = getSession(sessionId);
  const docContent = session?.document_content || `Design document: ${docRef}`;
  const frameworkType = framework;

  // Phase 1: Run threat generation, design enhancements, and pre-code risks in parallel
  console.log(`[${sessionId}] Phase 1: Generating threats, enhancements, and risks`);
  const [generatedThreats, enhancements, risks] = await Promise.all([
    generateThreatsFromDocument(docContent, docRef, frameworkType),
    generateDesignEnhancements(docContent, docRef, frameworkType),
    generatePreCodeRisks(docContent, docRef, frameworkType),
  ]);

  // Phase 2: Generate context layer (depends on Phase 1 results)
  console.log(`[${sessionId}] Phase 2: Generating context layer`);
  const threatSummary = generatedThreats.map(t => ({
    title: t.title,
    strideCategory: t.strideCategory,
    severity: t.severity,
  }));
  const contextLayer = await generateContextLayer(
    docContent,
    docRef,
    threatSummary,
    enhancements,
    risks
  );

  // Persist threats and mitigations
  const shortId = sessionId.split("-").pop() || sessionId.slice(-8);
  console.log(`[${sessionId}] Persisting ${generatedThreats.length} threats`);
  for (let i = 0; i < generatedThreats.length; i++) {
    const gt = generatedThreats[i];
    const threatId = `TC-${shortId}-${String(i + 1).padStart(3, "0")}`;

    const riskRating = calculateRiskRating(gt.owaspLikelihood, gt.owaspImpact);

    createThreat({
      id: threatId,
      sessionId,
      title: gt.title,
      strideCategory: gt.strideCategory,
      severity: riskRating.riskSeverity === "Note" ? "Low" : riskRating.riskSeverity,
      threatSource: gt.threatSource,
      prerequisites: gt.prerequisites,
      threatAction: gt.threatAction,
      threatImpact: gt.threatImpact,
      impactedAssets: gt.impactedAssets,
      trustBoundary: gt.trustBoundary,
      assumptions: gt.assumptions,
      owaspLikelihoodScore: riskRating.likelihoodScore,
      owaspImpactScore: riskRating.impactScore,
      owaspRiskLevel: riskRating.riskSeverity,
      owaspFactors: JSON.stringify({
        likelihood: riskRating.likelihood,
        impact: riskRating.impact,
      }),
    });

    for (let j = 0; j < gt.mitigations.length; j++) {
      const mit = gt.mitigations[j];
      const mitId = `MIT-${shortId}-${String(i + 1).padStart(3, "0")}-${String(j + 1).padStart(2, "0")}`;

      createMitigation({
        id: mitId,
        threatId,
        description: mit.description,
        status: "Proposed",
      });
    }
  }

  // Persist design reviews
  createDesignReview({
    id: `DE-${shortId}`,
    sessionId,
    type: "enhancement",
    content: JSON.stringify(enhancements),
  });
  createDesignReview({
    id: `DR-${shortId}`,
    sessionId,
    type: "risk",
    content: JSON.stringify(risks),
  });
  createDesignReview({
    id: `CL-${shortId}`,
    sessionId,
    type: "context-layer",
    content: contextLayer,
  });

  // Update session status
  updateSession(sessionId, {
    status: "Review",
    description: `Threat model from design document: ${docRef}`,
  });

  console.log(`[${sessionId}] Design doc analysis complete — ${generatedThreats.length} threats generated`);
}
