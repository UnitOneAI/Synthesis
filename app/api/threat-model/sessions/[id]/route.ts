import { NextRequest, NextResponse } from "next/server";
import {
  getFullSession,
  getSession,
  updateSession,
  listThreats,
  listMitigations,
  getDesignReviews,
} from "@/lib/db";
import { computeInsightsFromDb } from "@/lib/threat-engine/insight-engine";

// GET /api/threat-model/sessions/:id — Full session with threats, DFD, insights
export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;
    const session = getFullSession(id);

    if (!session) {
      return NextResponse.json(
        { error: "Session not found" },
        { status: 404 }
      );
    }

    // Compute insights
    const threats = listThreats(id);
    const insights = computeInsightsFromDb(threats, (threatId) =>
      listMitigations(threatId)
    );

    // Compute design review data if applicable
    let designReview = undefined;
    if (session.source === "design-doc") {
      const reviews = getDesignReviews(id);
      const enhancementReview = reviews.find((r) => r.type === "enhancement");
      const riskReview = reviews.find((r) => r.type === "risk");
      const contextLayerReview = reviews.find((r) => r.type === "context-layer");
      designReview = {
        enhancements: enhancementReview
          ? JSON.parse(enhancementReview.content)
          : [],
        risks: riskReview ? JSON.parse(riskReview.content) : [],
        contextLayer: contextLayerReview ? contextLayerReview.content : null,
      };
    }

    // Format threats for frontend compatibility
    const formattedThreats = session.threats.map((t) => ({
      id: t.id,
      title: t.title,
      stride: t.stride_category,
      severity: t.severity,
      status: t.status,
      threatStatement: {
        actor: t.threat_source,
        prerequisites: t.prerequisites || "",
        action: t.threat_action,
        asset: t.impacted_assets?.[0] || "",
        impact: t.threat_impact,
      },
      trustBoundary: t.trust_boundary,
      assumptions: t.assumptions || [],
      mitigations: (t.mitigations || []).map((m) => ({
        id: m.id,
        description: m.description,
        status: m.status,
        codeSnippet: m.code_file
          ? {
              file: m.code_file,
              line: m.code_line || 0,
              original: m.code_original || "",
              fixed: m.code_fixed || "",
            }
          : undefined,
        jiraTicket: m.jira_key
          ? {
              key: m.jira_key,
              summary: m.jira_summary || "",
              status: m.jira_status || "To Do",
            }
          : undefined,
      })),
      relatedCVE: t.related_cve || undefined,
    }));

    return NextResponse.json({
      id: session.id,
      name: session.name,
      description: session.description,
      source: session.source,
      sourceRef: session.source_ref,
      createdAt: session.created_at,
      status: session.status,
      framework: session.framework,
      dataFlowDiagram: session.dfd_mermaid || "",
      threats: formattedThreats,
      stats: session.stats,
      insights,
      designReview,
    });
  } catch (error) {
    console.error("Failed to get session:", error);
    return NextResponse.json(
      { error: "Failed to get session" },
      { status: 500 }
    );
  }
}

// PATCH /api/threat-model/sessions/:id — Update session
export async function PATCH(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;
    const session = getSession(id);

    if (!session) {
      return NextResponse.json(
        { error: "Session not found" },
        { status: 404 }
      );
    }

    const body = await request.json();
    updateSession(id, {
      name: body.name,
      description: body.description,
      status: body.status,
    });

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error("Failed to update session:", error);
    return NextResponse.json(
      { error: "Failed to update session" },
      { status: 500 }
    );
  }
}
