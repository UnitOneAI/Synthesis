"use client"

import { FileCode } from "lucide-react"

interface CodeDiffProps {
  filePath?: string
  lineStart?: number
  original?: string
  fixed?: string
  unified?: string
}

// Inline diff viewer. Accepts either:
//  - original + fixed (raw code blocks)
//  - unified (a unified-diff string with @@ hunks and +/- lines)
// Mirrors Synthesis's CodeDiff component styling.
export function CodeDiff({ filePath, lineStart = 1, original, fixed, unified }: CodeDiffProps) {
  const lines = unified ? parseUnified(unified) : buildLines(original, fixed, lineStart)

  if (lines.length === 0) return null

  return (
    <div className="rounded-lg border border-border bg-muted/30 overflow-hidden font-mono text-sm">
      {filePath && (
        <div className="flex items-center gap-2 px-4 py-2 bg-muted border-b border-border">
          <FileCode className="h-3.5 w-3.5 text-muted-foreground" />
          <span className="text-muted-foreground text-xs">{filePath}</span>
        </div>
      )}
      <div className="overflow-x-auto">
        {lines.map((line, i) => (
          <DiffLine key={i} {...line} />
        ))}
      </div>
    </div>
  )
}

interface Line {
  kind: "remove" | "add" | "context" | "hunk"
  lineNo?: number
  text: string
}

function DiffLine({ kind, lineNo, text }: Line) {
  if (kind === "hunk") {
    return (
      <div className="px-4 py-1 bg-blue-500/5 text-blue-700 text-xs border-b border-blue-200/40">
        {text}
      </div>
    )
  }
  const cls =
    kind === "remove"
      ? "bg-red-500/5 border-l-4 border-red-400"
      : kind === "add"
      ? "bg-green-500/5 border-l-4 border-green-400"
      : "border-l-4 border-transparent"
  const marker = kind === "remove" ? "-" : kind === "add" ? "+" : " "
  const markerCls =
    kind === "remove"
      ? "text-red-600 bg-red-500/10"
      : kind === "add"
      ? "text-green-600 bg-green-500/10"
      : "text-muted-foreground"
  const textCls =
    kind === "remove" ? "text-red-800" : kind === "add" ? "text-green-800" : ""

  return (
    <div className={`flex ${cls}`}>
      <span className="w-12 text-right pr-2 text-xs text-muted-foreground bg-muted/40 border-r border-border/50 select-none py-0.5">
        {lineNo ?? ""}
      </span>
      <span className={`w-6 text-center ${markerCls} select-none py-0.5`}>{marker}</span>
      <pre className={`flex-1 px-2 py-0.5 whitespace-pre ${textCls}`}>{text || " "}</pre>
    </div>
  )
}

function buildLines(original?: string, fixed?: string, lineStart = 1): Line[] {
  const out: Line[] = []
  const origLines = (original || "").split("\n")
  const fixedLines = (fixed || "").split("\n")

  if (original !== undefined && fixed !== undefined) {
    out.push({
      kind: "hunk",
      text: `@@ -${lineStart},${origLines.length} +${lineStart},${fixedLines.length} @@`,
    })
  }

  if (original) {
    origLines.forEach((text, i) => {
      if (i === origLines.length - 1 && text === "") return
      out.push({ kind: "remove", lineNo: lineStart + i, text })
    })
  }
  if (fixed) {
    fixedLines.forEach((text, i) => {
      if (i === fixedLines.length - 1 && text === "") return
      out.push({ kind: "add", lineNo: lineStart + i, text })
    })
  }
  return out
}

function parseUnified(raw: string): Line[] {
  const out: Line[] = []
  let oldNo = 0
  let newNo = 0
  for (const rawLine of raw.split("\n")) {
    if (rawLine.startsWith("@@")) {
      const match = rawLine.match(/@@\s*-(\d+)(?:,\d+)?\s*\+(\d+)(?:,\d+)?\s*@@/)
      if (match) {
        oldNo = parseInt(match[1], 10)
        newNo = parseInt(match[2], 10)
      }
      out.push({ kind: "hunk", text: rawLine })
    } else if (rawLine.startsWith("+++") || rawLine.startsWith("---")) {
      // skip file headers
    } else if (rawLine.startsWith("+")) {
      out.push({ kind: "add", lineNo: newNo++, text: rawLine.slice(1) })
    } else if (rawLine.startsWith("-")) {
      out.push({ kind: "remove", lineNo: oldNo++, text: rawLine.slice(1) })
    } else if (rawLine.length > 0) {
      out.push({ kind: "context", lineNo: newNo, text: rawLine.startsWith(" ") ? rawLine.slice(1) : rawLine })
      oldNo++
      newNo++
    }
  }
  return out
}

// Heuristic: does this text look like a unified diff?
export function looksLikeUnifiedDiff(text: string): boolean {
  return /^@@\s*-\d+/m.test(text) || /^---\s/m.test(text)
}
