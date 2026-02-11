import { NextResponse } from "next/server";
import { getDb } from "@/lib/db";

export async function GET() {
  try {
    const db = getDb();
    const repos = db.prepare(`
      SELECT source_ref as repoUrl,
        COUNT(*) as sessionCount,
        MAX(created_at) as lastAnalyzed,
        SUM(CASE WHEN status = 'Review' OR status = 'Complete' THEN 1 ELSE 0 END) as completedCount
      FROM sessions
      WHERE source = 'github-repo'
      GROUP BY source_ref
      ORDER BY MAX(created_at) DESC
    `).all();
    return NextResponse.json(repos);
  } catch (error) {
    console.error("Failed to list repositories:", error);
    return NextResponse.json({ error: "Failed to list repositories" }, { status: 500 });
  }
}
