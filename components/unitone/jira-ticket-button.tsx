"use client"

import { useState } from "react"
import { ExternalLink, Loader2, Plus, AlertCircle } from "lucide-react"
import { Button } from "@/components/ui/button"
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip"

interface JiraTicketButtonProps {
  threatId: string
  mitigationId?: string
  jiraConfigured: boolean
  existingJiraKey?: string
  existingJiraUrl?: string
  onCreated?: (jiraKey: string, jiraUrl: string) => void
}

export function JiraTicketButton({
  threatId,
  mitigationId,
  jiraConfigured,
  existingJiraKey,
  existingJiraUrl,
  onCreated,
}: JiraTicketButtonProps) {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [jiraKey, setJiraKey] = useState(existingJiraKey || null)
  const [jiraUrl, setJiraUrl] = useState(existingJiraUrl || null)

  async function handleCreate() {
    setLoading(true)
    setError(null)
    try {
      const res = await fetch(`/api/threat-model/threats/${threatId}/jira`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mitigationId }),
      })

      if (!res.ok) {
        const data = await res.json()
        throw new Error(data.error || "Failed to create ticket")
      }

      const data = await res.json()
      setJiraKey(data.jiraKey)
      setJiraUrl(data.jiraUrl)
      onCreated?.(data.jiraKey, data.jiraUrl)
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to create ticket")
    } finally {
      setLoading(false)
    }
  }

  // Already has a Jira ticket
  if (jiraKey && jiraUrl) {
    return (
      <Button
        variant="outline"
        size="sm"
        className="gap-1 text-xs bg-transparent"
        asChild
      >
        <a href={jiraUrl} target="_blank" rel="noopener noreferrer">
          <span className="font-mono text-primary">{jiraKey}</span>
          <ExternalLink className="size-3" />
        </a>
      </Button>
    )
  }

  // Not configured
  if (!jiraConfigured) {
    return (
      <TooltipProvider>
        <Tooltip>
          <TooltipTrigger asChild>
            <Button
              variant="outline"
              size="sm"
              className="gap-1 text-xs bg-transparent opacity-50 cursor-not-allowed"
              disabled
            >
              <Plus className="size-3" />
              Create Jira Ticket
            </Button>
          </TooltipTrigger>
          <TooltipContent>
            <p>Configure Jira in Settings</p>
          </TooltipContent>
        </Tooltip>
      </TooltipProvider>
    )
  }

  // Error state
  if (error) {
    return (
      <div className="flex items-center gap-2">
        <Button
          variant="outline"
          size="sm"
          className="gap-1 text-xs bg-transparent text-red-600 border-red-200"
          onClick={handleCreate}
        >
          <AlertCircle className="size-3" />
          Retry
        </Button>
        <span className="text-xs text-red-500">{error}</span>
      </div>
    )
  }

  return (
    <Button
      variant="outline"
      size="sm"
      className="gap-1 text-xs bg-transparent"
      onClick={handleCreate}
      disabled={loading}
    >
      {loading ? (
        <Loader2 className="size-3 animate-spin" />
      ) : (
        <Plus className="size-3" />
      )}
      Create Jira Ticket
    </Button>
  )
}
