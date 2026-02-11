"use client"

import { useState } from "react"
import { Eye, EyeOff } from "lucide-react"
import { Button } from "@/components/ui/button"

interface SecureInputProps {
  value: string
  onChange: (value: string) => void
  placeholder?: string
  masked?: boolean
}

export function SecureInput({ value, onChange, placeholder, masked = false }: SecureInputProps) {
  const [visible, setVisible] = useState(false)

  return (
    <div className="relative flex items-center">
      <input
        type={visible ? "text" : "password"}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="w-full px-3 py-2 pr-10 rounded-md border border-input bg-background text-sm focus:outline-none focus:ring-2 focus:ring-ring"
      />
      <Button
        type="button"
        variant="ghost"
        size="sm"
        className="absolute right-1 size-7 p-0"
        onClick={() => setVisible(!visible)}
      >
        {visible ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
      </Button>
    </div>
  )
}
