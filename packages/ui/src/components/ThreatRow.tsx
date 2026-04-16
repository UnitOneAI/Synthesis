"use client"

import { Issue } from "../types"
import { ChevronRight, FileCode } from "lucide-react"
import { SeverityBadge, StrideBadge } from "./badges"
import { cleanTitle } from "../lib/constants"
import { getStrideCategory, parseDescription } from "../lib/parse"

// Compact, scannable row. Opens ThreatDetailPanel on click.
export function ThreatRow({ issue, onOpen }: { issue: Issue; onOpen: () => void }) {
  const stride = getStrideCategory(issue)
  const parsed = issue.description ? parseDescription(issue.description) : null
  const title = cleanTitle(issue.title)

  return (
    <button
      type="button"
      onClick={onOpen}
      className="w-full text-left px-4 py-3 flex items-center gap-4 border-b hover:bg-muted/50 transition-colors"
    >
      <div className="flex items-center gap-2 shrink-0">
        <StrideBadge stride={stride} />
        <SeverityBadge severity={issue.severity} />
      </div>

      <div className="flex-1 min-w-0">
        <p className="font-medium text-sm truncate">{title}</p>
        {parsed?.threatStatement && (
          <p className="text-xs text-muted-foreground truncate mt-0.5">
            {parsed.threatStatement}
          </p>
        )}
      </div>

      {issue.location?.file_path && (
        <div className="hidden md:flex items-center gap-1.5 text-xs text-muted-foreground font-mono shrink-0 max-w-[280px] truncate">
          <FileCode className="h-3 w-3 shrink-0" />
          <span className="truncate">
            {issue.location.file_path}
            {issue.location.line_start ? `:${issue.location.line_start}` : ""}
          </span>
        </div>
      )}

      <ChevronRight className="h-4 w-4 text-muted-foreground shrink-0" />
    </button>
  )
}
