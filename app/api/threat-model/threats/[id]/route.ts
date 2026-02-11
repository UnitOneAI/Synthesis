import { NextRequest, NextResponse } from "next/server";
import { getThreat, updateThreat } from "@/lib/db";

// PATCH /api/threat-model/threats/:id — Update threat status/severity
export async function PATCH(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;
    const threat = getThreat(id);

    if (!threat) {
      return NextResponse.json(
        { error: "Threat not found" },
        { status: 404 }
      );
    }

    const body = await request.json();
    const updates: Partial<{ status: string; severity: string }> = {};

    if (body.status) {
      const validStatuses = [
        "Identified",
        "In Progress",
        "Mitigated",
        "Accepted",
      ];
      if (!validStatuses.includes(body.status)) {
        return NextResponse.json(
          { error: `Invalid status. Must be one of: ${validStatuses.join(", ")}` },
          { status: 400 }
        );
      }
      updates.status = body.status;
    }

    if (body.severity) {
      const validSeverities = ["Critical", "High", "Medium", "Low"];
      if (!validSeverities.includes(body.severity)) {
        return NextResponse.json(
          { error: `Invalid severity. Must be one of: ${validSeverities.join(", ")}` },
          { status: 400 }
        );
      }
      updates.severity = body.severity;
    }

    updateThreat(id, updates);

    return NextResponse.json({
      success: true,
      id,
      ...updates,
    });
  } catch (error) {
    console.error("Failed to update threat:", error);
    return NextResponse.json(
      { error: "Failed to update threat" },
      { status: 500 }
    );
  }
}
