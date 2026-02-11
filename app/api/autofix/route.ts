import { NextResponse } from "next/server";
import { getDb } from "@/lib/db";

export async function GET() {
  try {
    const db = getDb();
    const fixes = db.prepare(`
      SELECT m.id, m.threat_id, m.description, m.status, m.code_file, m.code_line, m.code_original, m.code_fixed,
             t.title as threat_title, t.severity, t.session_id,
             s.name as session_name, s.source, s.source_ref
      FROM mitigations m
      JOIN threats t ON m.threat_id = t.id
      JOIN sessions s ON t.session_id = s.id
      ORDER BY s.created_at DESC, t.session_id,
               CASE m.status WHEN 'Proposed' THEN 0 WHEN 'Implemented' THEN 1 ELSE 2 END,
               CASE t.severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END
    `).all();
    return NextResponse.json(fixes);
  } catch (error) {
    console.error("Failed to list autofix items:", error);
    return NextResponse.json({ error: "Failed to list autofix items" }, { status: 500 });
  }
}
