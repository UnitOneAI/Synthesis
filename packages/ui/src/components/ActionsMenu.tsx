"use client"

import { useEffect, useRef, useState } from "react"
import { ChevronDown } from "lucide-react"
import { Button } from "../primitives"

// Minimal dropdown menu (no shadcn DropdownMenu primitive available in this
// codebase). Matches the Synthesis "Actions" dropdown behavior: open on
// click, close on outside-click or Escape.
export function ActionsMenu({
  items,
  label = "Actions",
}: {
  items: { label: string; onClick: () => void; disabled?: boolean }[]
  label?: string
}) {
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    function handleKey(e: KeyboardEvent) {
      if (e.key === "Escape") setOpen(false)
    }
    if (open) {
      document.addEventListener("mousedown", handleClick)
      document.addEventListener("keydown", handleKey)
    }
    return () => {
      document.removeEventListener("mousedown", handleClick)
      document.removeEventListener("keydown", handleKey)
    }
  }, [open])

  return (
    <div ref={ref} className="relative">
      <Button variant="outline" size="sm" onClick={() => setOpen(!open)}>
        {label}
        <ChevronDown className="h-3.5 w-3.5 ml-1" />
      </Button>
      {open && (
        <div className="absolute right-0 bottom-full mb-1 w-56 bg-popover border rounded-md shadow-lg py-1 z-10">
          {items.map((item, idx) => (
            <button
              key={idx}
              onClick={() => {
                item.onClick()
                setOpen(false)
              }}
              disabled={item.disabled}
              className="w-full text-left px-3 py-1.5 text-sm hover:bg-muted disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {item.label}
            </button>
          ))}
        </div>
      )}
    </div>
  )
}
