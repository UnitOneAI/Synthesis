"use client"

import { useState } from "react"
import { CheckCircle2, ExternalLink, Loader2, Zap } from "lucide-react"
import { Button } from "@/components/ui/button"

interface ApplyFixButtonProps {
  threatId: string
  mitigationId: string
  hasCodeFix: boolean
  isRepoSource: boolean
  onApplied?: (result: {
    prUrl?: string
    branch?: string
    threatStatus: string
  }) => void
}

export function ApplyFixButton({
  threatId,
  mitigationId,
  hasCodeFix,
  isRepoSource,
  onApplied,
}: ApplyFixButtonProps) {
  const [state, setState] = useState<
    "idle" | "loading" | "success" | "error"
  >("idle")
  const [prUrl, setPrUrl] = useState<string | null>(null)
  const [errorMessage, setErrorMessage] = useState<string | null>(null)

  if (!hasCodeFix || !isRepoSource) {
    return null
  }

  async function handleApplyFix() {
    setState("loading")
    setErrorMessage(null)

    try {
      const response = await fetch(
        `/api/threat-model/threats/${threatId}/apply-fix`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ mitigationId }),
        }
      )

      const data = await response.json()

      if (data.success) {
        setState("success")
        setPrUrl(data.prUrl || null)
        onApplied?.({
          prUrl: data.prUrl,
          branch: data.branch,
          threatStatus: "Mitigated",
        })
      } else {
        setState("error")
        setErrorMessage(data.error || "Failed to apply fix")
      }
    } catch (e) {
      setState("error")
      setErrorMessage("Network error — could not apply fix")
    }
  }

  if (state === "success") {
    return (
      <div className="flex items-center gap-2">
        <div className="flex items-center gap-1.5 text-green-600 text-sm">
          <CheckCircle2 className="size-4" />
          <span>Fix Applied</span>
        </div>
        {prUrl && (
          <a
            href={prUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1 text-xs text-primary hover:underline"
          >
            View PR
            <ExternalLink className="size-3" />
          </a>
        )}
      </div>
    )
  }

  if (state === "error") {
    return (
      <div className="space-y-2">
        <p className="text-xs text-red-600">{errorMessage}</p>
        <Button
          variant="outline"
          size="sm"
          className="gap-1 text-xs bg-transparent"
          onClick={handleApplyFix}
        >
          <Zap className="size-3" />
          Retry Fix
        </Button>
      </div>
    )
  }

  return (
    <Button
      variant="default"
      size="sm"
      className="gap-1.5 bg-primary hover:bg-primary/90"
      onClick={handleApplyFix}
      disabled={state === "loading"}
    >
      {state === "loading" ? (
        <>
          <Loader2 className="size-3 animate-spin" />
          Applying Fix...
        </>
      ) : (
        <>
          <Zap className="size-3" />
          Apply Fix
        </>
      )}
    </Button>
  )
}
