"use client"

import { useEffect, useRef, useState } from "react"
import { Network } from "lucide-react"

export function DataFlowDiagram({
  mermaid: mermaidSource,
  theme,
}: {
  mermaid: string
  theme?: "light" | "dark"
}) {
  const ref = useRef<HTMLDivElement>(null)
  const [error, setError] = useState<string | null>(null)

  const resolvedTheme =
    theme ??
    (typeof window !== "undefined" && document.documentElement.classList.contains("dark")
      ? "dark"
      : "light")

  useEffect(() => {
    let cancelled = false
    async function render() {
      if (!ref.current) return
      try {
        const m = (await import("mermaid")).default
        m.initialize({
          startOnLoad: false,
          theme: resolvedTheme === "dark" ? "dark" : "default",
          securityLevel: "strict",
          flowchart: { curve: "basis", htmlLabels: true },
        })
        const id = `dfd-${Math.random().toString(36).slice(2)}`
        const { svg } = await m.render(id, mermaidSource)
        if (!cancelled && ref.current) {
          ref.current.innerHTML = svg
          setError(null)
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to render diagram")
        }
      }
    }
    render()
    return () => {
      cancelled = true
    }
  }, [mermaidSource, resolvedTheme])

  return (
    <section>
      <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
        <Network className="h-4 w-4 text-primary" />
        Data Flow Diagram
      </h3>
      <div className="border rounded-lg p-4 bg-muted/20 overflow-x-auto">
        {error ? (
          <div className="text-sm text-muted-foreground">
            <p className="font-medium text-destructive mb-2">Could not render diagram</p>
            <p className="text-xs mb-2">{error}</p>
            <details>
              <summary className="cursor-pointer text-xs">Show raw mermaid source</summary>
              <pre className="text-xs bg-muted p-2 rounded mt-2 whitespace-pre-wrap">
                {mermaidSource}
              </pre>
            </details>
          </div>
        ) : (
          <div
            ref={ref}
            className="flex justify-center [&_svg]:max-w-full [&_svg]:h-auto"
          />
        )}
      </div>
    </section>
  )
}
