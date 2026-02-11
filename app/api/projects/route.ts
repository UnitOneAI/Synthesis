import { NextRequest, NextResponse } from "next/server";
import { v4 as uuidv4 } from "uuid";
import { createProject, listProjects } from "@/lib/db";

// GET /api/projects — List all projects
export async function GET() {
  try {
    const projects = listProjects();
    return NextResponse.json(
      projects.map((p) => ({
        id: p.id,
        name: p.name,
        description: p.description,
        createdAt: p.created_at,
        updatedAt: p.updated_at,
      }))
    );
  } catch (error) {
    console.error("Failed to list projects:", error);
    return NextResponse.json(
      { error: "Failed to list projects" },
      { status: 500 }
    );
  }
}

// POST /api/projects — Create a new project
export async function POST(request: NextRequest) {
  try {
    const body = await request.json();

    if (!body.name) {
      return NextResponse.json(
        { error: "name is required" },
        { status: 400 }
      );
    }

    const id = `proj-${uuidv4().split("-")[0]}`;
    const project = createProject({
      id,
      name: body.name,
      description: body.description || "",
    });

    return NextResponse.json(
      {
        id: project.id,
        name: project.name,
        description: project.description,
        createdAt: project.created_at,
        updatedAt: project.updated_at,
      },
      { status: 201 }
    );
  } catch (error) {
    console.error("Failed to create project:", error);
    return NextResponse.json(
      { error: "Failed to create project" },
      { status: 500 }
    );
  }
}
