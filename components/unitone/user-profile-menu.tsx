"use client"

import { useEffect, useState } from "react"
import Link from "next/link"
import { Settings, LogOut, User } from "lucide-react"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"

export function UserProfileMenu() {
  const [profile, setProfile] = useState<{ name: string; email: string }>({
    name: "",
    email: "",
  })

  useEffect(() => {
    async function loadProfile() {
      try {
        const res = await fetch("/api/settings")
        if (res.ok) {
          const settings = await res.json()
          const name = settings.find((s: { key: string }) => s.key === "profile_name")?.value || ""
          const email = settings.find((s: { key: string }) => s.key === "profile_email")?.value || ""
          setProfile({ name, email })
        }
      } catch {
        // Use defaults
      }
    }
    loadProfile()
  }, [])

  const initials = profile.name
    ? profile.name
        .split(" ")
        .map((n) => n[0])
        .join("")
        .toUpperCase()
        .slice(0, 2)
    : "U"

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button
          type="button"
          className="size-8 rounded-full bg-primary flex items-center justify-center text-primary-foreground text-sm font-medium hover:opacity-90 transition-opacity"
        >
          {initials}
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-56">
        <DropdownMenuLabel>
          <div className="flex flex-col space-y-1">
            <p className="text-sm font-medium">{profile.name || "User"}</p>
            {profile.email && (
              <p className="text-xs text-muted-foreground">{profile.email}</p>
            )}
          </div>
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuItem asChild>
          <Link href="/settings" className="flex items-center gap-2 cursor-pointer">
            <Settings className="size-4" />
            Settings
          </Link>
        </DropdownMenuItem>
        <DropdownMenuItem asChild>
          <Link href="/settings" className="flex items-center gap-2 cursor-pointer">
            <User className="size-4" />
            Profile
          </Link>
        </DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem className="flex items-center gap-2 text-red-600 cursor-pointer">
          <LogOut className="size-4" />
          Sign Out
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
