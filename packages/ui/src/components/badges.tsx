"use client"

import { Badge } from "../primitives"
import { Severity } from "../types"
import { SEVERITY_COLORS, getStrideColor, getStrideLabel } from "../lib/constants"

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <Badge
      variant="outline"
      className={`${SEVERITY_COLORS[severity]} text-xs uppercase font-semibold`}
    >
      {severity}
    </Badge>
  )
}

export function StrideBadge({ stride }: { stride: string }) {
  return (
    <Badge variant="outline" className={`${getStrideColor(stride)} text-xs font-semibold`}>
      {getStrideLabel(stride)}
    </Badge>
  )
}
