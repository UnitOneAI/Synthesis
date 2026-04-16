"use client"

import { useState } from "react"
import { Zap, Check, Loader2 } from "lucide-react"
import { Button } from "../primitives"

// UI-only Apply Fix button. Preserves the Synthesis visual pattern so this
// can be wired to the autofix queue endpoint (`POST /autofix-queue`) later
// without changing surrounding layout. The onApply callback is optional.
export function ApplyFixButton({
  onApply,
  disabled,
}: {
  onApply?: () => Promise<void> | void
  disabled?: boolean
}) {
  const [state, setState] = useState<"idle" | "loading" | "applied" | "error">("idle")
  const [message, setMessage] = useState<string | null>(null)

  async function handleClick() {
    if (state === "loading" || !onApply) {
      if (!onApply) {
        // No handler wired — surface a hint but keep button clickable for demo.
        setMessage("Fix queueing not yet wired")
        return
      }
    }
    setState("loading")
    try {
      await onApply!()
      setState("applied")
    } catch (err) {
      setState("error")
      setMessage(err instanceof Error ? err.message : "Failed to apply fix")
    }
  }

  if (state === "applied") {
    return (
      <div className="inline-flex items-center gap-2 text-sm text-green-700">
        <Check className="h-4 w-4" />
        Fix applied
      </div>
    )
  }

  return (
    <div className="flex items-center gap-3">
      <Button
        size="sm"
        onClick={handleClick}
        disabled={disabled || state === "loading"}
      >
        {state === "loading" ? (
          <>
            <Loader2 className="h-3.5 w-3.5 mr-2 animate-spin" />
            Applying...
          </>
        ) : (
          <>
            <Zap className="h-3.5 w-3.5 mr-2" />
            Apply Fix
          </>
        )}
      </Button>
      {message && <span className="text-xs text-muted-foreground">{message}</span>}
    </div>
  )
}
