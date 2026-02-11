"use client"

import { FileCode } from "lucide-react"

export function CodeDiff({
  original,
  fixed,
  filePath,
  lineStart,
}: {
  original: string
  fixed: string
  filePath: string
  lineStart: number
}) {
  const originalLines = original.split("\n")
  const fixedLines = fixed.split("\n")

  return (
    <div className="rounded-lg border border-border bg-muted/30 overflow-hidden font-mono text-sm">
      {/* File Header */}
      <div className="flex items-center gap-2 px-4 py-2 bg-muted border-b border-border">
        <FileCode className="size-4 text-muted-foreground" />
        <span className="text-muted-foreground">{filePath}</span>
      </div>

      {/* Diff Header */}
      <div className="px-4 py-2 bg-blue-50 text-blue-700 text-xs border-b border-border">
        @@ -{lineStart},{originalLines.length} +{lineStart},{fixedLines.length}{" "}
        @@
      </div>

      {/* Code Content */}
      <div className="overflow-x-auto">
        {/* Original Code (Removed) */}
        {originalLines.map((line, i) => (
          <div
            key={`old-${filePath}-${lineStart}-${i}`}
            className="flex bg-red-50/50 border-l-4 border-red-400"
          >
            <span className="w-12 px-2 py-0.5 text-xs text-muted-foreground bg-red-100/50 text-right select-none border-r border-red-200">
              {lineStart + i}
            </span>
            <span className="w-8 px-2 py-0.5 text-red-600 bg-red-100/50 text-center select-none">
              -
            </span>
            <pre className="flex-1 px-3 py-0.5 text-red-800 whitespace-pre">
              {line}
            </pre>
          </div>
        ))}

        {/* Fixed Code (Added) */}
        {fixedLines.map((line, i) => (
          <div
            key={`new-${filePath}-${lineStart}-${i}`}
            className="flex bg-green-50/50 border-l-4 border-green-400"
          >
            <span className="w-12 px-2 py-0.5 text-xs text-muted-foreground bg-green-100/50 text-right select-none border-r border-green-200">
              {lineStart + i}
            </span>
            <span className="w-8 px-2 py-0.5 text-green-600 bg-green-100/50 text-center select-none">
              +
            </span>
            <pre className="flex-1 px-3 py-0.5 text-green-800 whitespace-pre">
              {line}
            </pre>
          </div>
        ))}
      </div>
    </div>
  )
}
