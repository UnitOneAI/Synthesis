import { NextRequest, NextResponse } from "next/server";
import { upsertSetting, deleteSetting, getSetting, maskSecret } from "@/lib/db";

// PATCH /api/settings/[key] — Update single setting
export async function PATCH(
  request: NextRequest,
  { params }: { params: Promise<{ key: string }> }
) {
  try {
    const { key } = await params;
    const body = await request.json();

    if (!body.value || !body.category) {
      return NextResponse.json(
        { error: "value and category are required" },
        { status: 400 }
      );
    }

    upsertSetting({
      key,
      value: body.value,
      category: body.category,
      isSecret: body.isSecret ?? false,
    });

    const updated = getSetting(key);
    if (!updated) {
      return NextResponse.json({ error: "Setting not found" }, { status: 404 });
    }

    return NextResponse.json({
      key: updated.key,
      value: updated.is_secret ? maskSecret(updated.value) : updated.value,
      category: updated.category,
      isSecret: !!updated.is_secret,
      updatedAt: updated.updated_at,
    });
  } catch (error) {
    console.error("Failed to update setting:", error);
    return NextResponse.json(
      { error: "Failed to update setting" },
      { status: 500 }
    );
  }
}

// DELETE /api/settings/[key] — Delete single setting
export async function DELETE(
  _request: NextRequest,
  { params }: { params: Promise<{ key: string }> }
) {
  try {
    const { key } = await params;
    deleteSetting(key);
    return NextResponse.json({ success: true });
  } catch (error) {
    console.error("Failed to delete setting:", error);
    return NextResponse.json(
      { error: "Failed to delete setting" },
      { status: 500 }
    );
  }
}
