import { NextRequest, NextResponse } from "next/server";
import { getSettings, upsertSetting, maskSecret } from "@/lib/db";

// GET /api/settings — List all settings (secrets masked)
export async function GET() {
  try {
    const settings = getSettings();
    const masked = settings.map((s) => ({
      key: s.key,
      value: s.is_secret ? maskSecret(s.value) : s.value,
      category: s.category,
      isSecret: !!s.is_secret,
      updatedAt: s.updated_at,
    }));
    return NextResponse.json(masked);
  } catch (error) {
    console.error("Failed to list settings:", error);
    return NextResponse.json(
      { error: "Failed to list settings" },
      { status: 500 }
    );
  }
}

// PUT /api/settings — Bulk upsert settings
export async function PUT(request: NextRequest) {
  try {
    const body = await request.json();
    const { settings } = body;

    if (!Array.isArray(settings)) {
      return NextResponse.json(
        { error: "settings must be an array" },
        { status: 400 }
      );
    }

    for (const s of settings) {
      if (!s.key || !s.value || !s.category) {
        continue;
      }
      upsertSetting({
        key: s.key,
        value: s.value,
        category: s.category,
        isSecret: s.isSecret ?? false,
      });
    }

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error("Failed to upsert settings:", error);
    return NextResponse.json(
      { error: "Failed to upsert settings" },
      { status: 500 }
    );
  }
}
