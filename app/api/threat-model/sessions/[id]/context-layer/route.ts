import { NextRequest, NextResponse } from "next/server";
import { getSession, getDesignReviews } from "@/lib/db";

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const session = getSession(id);
  if (!session) {
    return NextResponse.json({ error: "Session not found" }, { status: 404 });
  }

  const reviews = getDesignReviews(id, "context-layer");
  if (!reviews.length) {
    return NextResponse.json(
      { error: "No context layer available" },
      { status: 404 }
    );
  }

  const filename = `${session.name.replace(/[^a-zA-Z0-9-_]/g, "_")}_security_context.md`;

  return new Response(reviews[0].content, {
    headers: {
      "Content-Type": "text/markdown",
      "Content-Disposition": `attachment; filename="${filename}"`,
    },
  });
}
