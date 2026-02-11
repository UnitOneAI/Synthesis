import { NextRequest, NextResponse } from "next/server";
import { v4 as uuidv4 } from "uuid";
import {
  createSession,
  listSessions,
  getSessionStats,
  listThreats,
} from "@/lib/db";
import { extractTextFromFile } from "@/lib/threat-engine/document-parser";

// GET /api/threat-model/sessions — List all sessions with stats
export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const projectId = searchParams.get("projectId") || undefined;

    const sessions = listSessions(projectId);

    const sessionsWithStats = sessions.map((s) => ({
      id: s.id,
      name: s.name,
      description: s.description,
      source: s.source,
      sourceRef: s.source_ref,
      createdAt: s.created_at,
      status: s.status,
      framework: s.framework,
      projectId: s.project_id,
      stats: getSessionStats(s.id),
    }));

    return NextResponse.json(sessionsWithStats);
  } catch (error) {
    console.error("Failed to list sessions:", error);
    return NextResponse.json(
      { error: "Failed to list sessions" },
      { status: 500 }
    );
  }
}

// POST /api/threat-model/sessions — Create a new session
export async function POST(request: NextRequest) {
  try {
    let name: string | undefined;
    let source: string | undefined;
    let sourceRef: string | undefined;
    let framework: string | undefined;
    let projectId: string | undefined;
    let description = "";
    let documentContent: string | undefined;

    const contentType = request.headers.get("content-type") || "";
    if (contentType.includes("multipart/form-data")) {
      const formData = await request.formData();
      name = formData.get("name") as string | undefined;
      source = formData.get("source") as string | undefined;
      sourceRef = formData.get("sourceRef") as string | undefined;
      framework = formData.get("framework") as string | undefined;
      projectId = formData.get("projectId") as string | undefined;
      description = (formData.get("description") as string) || "";

      const file = formData.get("file") as File | null;
      if (file) {
        documentContent = await extractTextFromFile(
          Buffer.from(await file.arrayBuffer()),
          file.name
        );
        if (!sourceRef) {
          sourceRef = file.name;
        }
      }
    } else {
      const body = await request.json();
      name = body.name;
      source = body.source;
      sourceRef = body.sourceRef;
      framework = body.framework;
      projectId = body.projectId;
      description = body.description || "";
      documentContent = body.documentContent;
    }

    if (!name || !source || !sourceRef) {
      return NextResponse.json(
        { error: "name, source, and sourceRef are required" },
        { status: 400 }
      );
    }

    if (source !== "design-doc" && source !== "github-repo") {
      return NextResponse.json(
        { error: "source must be 'design-doc' or 'github-repo'" },
        { status: 400 }
      );
    }

    const id = `tm-${uuidv4().split("-")[0]}`;

    const session = createSession({
      id,
      name,
      description,
      source,
      sourceRef,
      framework: framework || "STRIDE",
      projectId: projectId || undefined,
      documentContent,
    });

    return NextResponse.json(
      {
        id: session.id,
        name: session.name,
        source: session.source,
        sourceRef: session.source_ref,
        status: session.status,
        framework: session.framework,
        createdAt: session.created_at,
      },
      { status: 201 }
    );
  } catch (error) {
    console.error("Failed to create session:", error);
    return NextResponse.json(
      { error: "Failed to create session" },
      { status: 500 }
    );
  }
}
