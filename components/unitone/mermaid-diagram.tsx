"use client"

import { useEffect, useRef, useState } from "react"

interface MermaidDiagramProps {
  chart: string
  className?: string
}

export function MermaidDiagram({ chart, className }: MermaidDiagramProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  const [svg, setSvg] = useState<string>("")
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!chart) return

    let cancelled = false

    async function renderMermaid() {
      try {
        // Dynamic import to avoid SSR issues
        const mermaid = (await import("mermaid")).default

        mermaid.initialize({
          startOnLoad: false,
          theme: "neutral",
          securityLevel: "strict",
          flowchart: {
            useMaxWidth: true,
            htmlLabels: true,
            curve: "basis",
            padding: 15,
          },
          themeVariables: {
            primaryColor: "#dbeafe",
            primaryTextColor: "#1e40af",
            primaryBorderColor: "#3b82f6",
            lineColor: "#6b7280",
            secondaryColor: "#dcfce7",
            tertiaryColor: "#fef3c7",
            fontSize: "14px",
          },
        })

        const id = `mermaid-${Date.now()}`
        const { svg: renderedSvg } = await mermaid.render(id, chart)

        if (!cancelled) {
          setSvg(renderedSvg)
          setError(null)
        }
      } catch (e) {
        if (!cancelled) {
          console.error("Mermaid render error:", e)
          setError("Failed to render diagram")
        }
      }
    }

    renderMermaid()

    return () => {
      cancelled = true
    }
  }, [chart])

  if (error) {
    return (
      <div className={`p-6 bg-muted/30 rounded-lg border border-border ${className || ""}`}>
        <p className="text-sm text-muted-foreground">{error}</p>
        <pre className="mt-3 text-xs font-mono bg-muted p-3 rounded overflow-x-auto">
          {chart}
        </pre>
      </div>
    )
  }

  if (!svg) {
    return (
      <div className={`p-6 bg-muted/30 rounded-lg border border-border flex items-center justify-center min-h-[200px] ${className || ""}`}>
        <div className="size-6 rounded-full border-2 border-primary border-t-transparent animate-spin" />
      </div>
    )
  }

  return (
    <div
      ref={containerRef}
      className={`p-4 bg-muted/10 rounded-lg border border-border overflow-x-auto ${className || ""}`}
      dangerouslySetInnerHTML={{ __html: svg }}
    />
  )
}
