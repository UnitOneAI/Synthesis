"use client"

import { Filter } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover"

interface ThreatFiltersProps {
  filterSeverity: string[]
  filterStatus: string[]
  filterStride: string[]
  onFilterSeverityChange: (values: string[]) => void
  onFilterStatusChange: (values: string[]) => void
  onFilterStrideChange: (values: string[]) => void
}

const SEVERITIES = ["Critical", "High", "Medium", "Low"]
const STATUSES = ["Identified", "In Progress", "Mitigated", "Accepted"]
const STRIDE_CATEGORIES = [
  "Spoofing",
  "Tampering",
  "Repudiation",
  "Information Disclosure",
  "Denial of Service",
  "Elevation of Privilege",
]

function CheckboxGroup({
  label,
  options,
  selected,
  onChange,
}: {
  label: string
  options: string[]
  selected: string[]
  onChange: (values: string[]) => void
}) {
  function toggle(value: string) {
    if (selected.includes(value)) {
      onChange(selected.filter((v) => v !== value))
    } else {
      onChange([...selected, value])
    }
  }

  return (
    <div className="space-y-2">
      <div className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
        {label}
      </div>
      {options.map((option) => (
        <label
          key={option}
          className="flex items-center gap-2 text-sm cursor-pointer"
        >
          <Checkbox
            checked={selected.includes(option)}
            onCheckedChange={() => toggle(option)}
          />
          <span>{option}</span>
        </label>
      ))}
    </div>
  )
}

export function ThreatFilters({
  filterSeverity,
  filterStatus,
  filterStride,
  onFilterSeverityChange,
  onFilterStatusChange,
  onFilterStrideChange,
}: ThreatFiltersProps) {
  const activeCount =
    filterSeverity.length + filterStatus.length + filterStride.length

  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button variant="outline" size="sm" className="gap-1.5 bg-transparent">
          <Filter className="size-3.5" />
          Filter
          {activeCount > 0 && (
            <Badge className="size-5 p-0 flex items-center justify-center text-[10px]">
              {activeCount}
            </Badge>
          )}
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-72 p-4" align="end">
        <div className="space-y-4">
          <CheckboxGroup
            label="Severity"
            options={SEVERITIES}
            selected={filterSeverity}
            onChange={onFilterSeverityChange}
          />
          <CheckboxGroup
            label="Status"
            options={STATUSES}
            selected={filterStatus}
            onChange={onFilterStatusChange}
          />
          <CheckboxGroup
            label="STRIDE Category"
            options={STRIDE_CATEGORIES}
            selected={filterStride}
            onChange={onFilterStrideChange}
          />
          {activeCount > 0 && (
            <Button
              variant="ghost"
              size="sm"
              className="w-full text-xs"
              onClick={() => {
                onFilterSeverityChange([])
                onFilterStatusChange([])
                onFilterStrideChange([])
              }}
            >
              Clear All Filters
            </Button>
          )}
        </div>
      </PopoverContent>
    </Popover>
  )
}
