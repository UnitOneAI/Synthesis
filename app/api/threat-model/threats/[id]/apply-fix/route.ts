import { NextRequest, NextResponse } from "next/server";
import {
  getThreat,
  updateThreat,
  getMitigation,
  updateMitigation,
  getSession,
  listMitigations,
} from "@/lib/db";
import { applyFix } from "@/lib/threat-engine/git-service";

// POST /api/threat-model/threats/:id/apply-fix — Apply code fix and create PR
export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id: threatId } = await params;
    const threat = getThreat(threatId);

    if (!threat) {
      return NextResponse.json(
        { error: "Threat not found" },
        { status: 404 }
      );
    }

    const body = await request.json();
    const { mitigationId } = body;

    // Find the mitigation with the code fix
    let mitigation;
    if (mitigationId) {
      mitigation = getMitigation(mitigationId);
    } else {
      // Find first mitigation with code
      const mitigations = listMitigations(threatId);
      mitigation = mitigations.find(
        (m) => m.code_file && m.code_original && m.code_fixed
      );
    }

    if (!mitigation) {
      return NextResponse.json(
        { error: "No mitigation with code fix found for this threat" },
        { status: 400 }
      );
    }

    if (!mitigation.code_file || !mitigation.code_original || !mitigation.code_fixed) {
      return NextResponse.json(
        { error: "This mitigation does not have a code fix (document-based threat)" },
        { status: 400 }
      );
    }

    // Get the session to find the repo URL
    const session = getSession(threat.session_id);
    if (!session) {
      return NextResponse.json(
        { error: "Session not found" },
        { status: 404 }
      );
    }

    if (session.source !== "github-repo") {
      return NextResponse.json(
        { error: "Apply Fix is only available for GitHub repo sources" },
        { status: 400 }
      );
    }

    // Apply the fix via GitHub API
    const result = await applyFix(
      session.source_ref,
      threatId,
      threat.title,
      mitigation.code_file,
      mitigation.code_original,
      mitigation.code_fixed
    );

    if (result.success) {
      // Update mitigation status
      updateMitigation(mitigation.id, { status: "Implemented" });

      // Update threat status to Mitigated
      updateThreat(threatId, { status: "Mitigated" });

      return NextResponse.json({
        success: true,
        prUrl: result.prUrl,
        branch: result.branch,
        commitSha: result.commitSha,
        threatStatus: "Mitigated",
        mitigationStatus: "Implemented",
      });
    } else {
      return NextResponse.json(
        {
          success: false,
          error: result.error,
        },
        { status: 422 }
      );
    }
  } catch (error) {
    console.error("Failed to apply fix:", error);
    return NextResponse.json(
      { error: "Failed to apply fix" },
      { status: 500 }
    );
  }
}
