"use client"

import { ExternalLink, Plus } from "lucide-react"
import { Button } from "../primitives"

// UI-only Jira ticket button. Synthesis's version posts to
// /api/threat-model/threats/{id}/jira — UnitoneController doesn't expose
// that endpoint yet, so this shell mirrors the "not configured" state
// from Synthesis (disabled with tooltip).
export function JiraTicketButton({
  existingKey,
  existingUrl,
  configured,
}: {
  existingKey?: string
  existingUrl?: string
  configured?: boolean
}) {
  if (existingKey && existingUrl) {
    return (
      <Button
        variant="outline"
        size="sm"
        asChild
        className="font-mono"
      >
        <a href={existingUrl} target="_blank" rel="noopener noreferrer">
          {existingKey}
          <ExternalLink className="h-3 w-3 ml-1" />
        </a>
      </Button>
    )
  }

  return (
    <Button
      variant="outline"
      size="sm"
      disabled
      title={configured ? "Create Jira ticket" : "Configure Jira in Settings"}
    >
      <Plus className="h-3.5 w-3.5 mr-1" />
      Create Jira Ticket
    </Button>
  )
}
