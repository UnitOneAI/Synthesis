"use client"

import React, { createContext, useCallback, useContext, useEffect, useState } from "react"

import {
  Code2,
  LayoutDashboard,
  Search,
  Settings,
  Shield,
  ShieldAlert,
  Users,
  Zap,
} from "lucide-react"
import Image from "next/image"
import Link from "next/link"
import { usePathname } from "next/navigation"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { ProjectSwitcher } from "@/components/unitone/project-switcher"
import { UserProfileMenu } from "@/components/unitone/user-profile-menu"

// Project context for sharing selected project across the app
export const ProjectContext = createContext<{
  projectId: string | null
  setProjectId: (id: string | null) => void
}>({ projectId: null, setProjectId: () => {} })

export function useProject() {
  return useContext(ProjectContext)
}

export function ProjectProvider({ children }: { children: React.ReactNode }) {
  const [projectId, setProjectId] = useState<string | null>(null)
  return (
    <ProjectContext.Provider value={{ projectId, setProjectId }}>
      {children}
    </ProjectContext.Provider>
  )
}

const navItems = [
  { icon: LayoutDashboard, label: "Feed", href: "/" },
  { icon: Zap, label: "AutoFix Queue", href: "/autofix", badgeKey: "autofix" },
  { icon: ShieldAlert, label: "Threat Modeling", href: "/threat-modeling" },
  { icon: Code2, label: "Repositories", href: "/repositories" },
  { icon: Shield, label: "Compliance", href: "/compliance" },
  { icon: Users, label: "Team Settings", href: "/team" },
]

export function AppSidebar() {
  const pathname = usePathname()
  const { projectId, setProjectId } = useProject()
  const [autofixCount, setAutofixCount] = useState(0)

  const loadAutofixCount = useCallback(async () => {
    try {
      const res = await fetch("/api/autofix")
      if (res.ok) {
        const items = await res.json()
        const pending = items.filter((i: { status: string }) => i.status === "Proposed")
        setAutofixCount(pending.length)
      }
    } catch {
      // Silently fail
    }
  }, [])

  useEffect(() => {
    loadAutofixCount()
  }, [loadAutofixCount])

  return (
    <aside className="w-64 bg-sidebar text-sidebar-foreground flex flex-col shrink-0">
      {/* Logo */}
      <div className="p-4 flex items-center gap-3">
        <Image
          src="/images/logo-color-only.png"
          alt="Unitone Logo"
          width={36}
          height={36}
          className="rounded"
        />
        <span className="text-lg font-semibold text-white">Unitone</span>
      </div>

      {/* Project Switcher */}
      <div className="px-3 py-2">
        <ProjectSwitcher
          selectedProjectId={projectId}
          onProjectChange={setProjectId}
        />
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 py-4">
        <ul className="space-y-1">
          {navItems.map((item) => {
            const isActive = pathname === item.href
            return (
              <li key={item.label}>
                <Link
                  href={item.href}
                  className={`w-full flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors ${
                    isActive
                      ? "bg-sidebar-accent text-sidebar-accent-foreground"
                      : "text-sidebar-foreground/70 hover:bg-sidebar-accent/50 hover:text-sidebar-accent-foreground"
                  }`}
                >
                  <item.icon className="size-4" />
                  <span className="flex-1 text-left">{item.label}</span>
                  {item.badgeKey === "autofix" && autofixCount > 0 && (
                    <Badge className="bg-primary text-primary-foreground text-xs">
                      {autofixCount}
                    </Badge>
                  )}
                </Link>
              </li>
            )
          })}
        </ul>
      </nav>

      {/* Bottom Settings */}
      <div className="p-3 border-t border-sidebar-border">
        <Link
          href="/settings"
          className="w-full flex items-center gap-3 px-3 py-2 rounded-md text-sm text-sidebar-foreground/70 hover:bg-sidebar-accent/50 hover:text-sidebar-accent-foreground transition-colors"
        >
          <Settings className="size-4" />
          <span>Settings</span>
        </Link>
      </div>
    </aside>
  )
}

export function AppHeader({ title, children }: { title: string; children?: React.ReactNode }) {
  return (
    <header className="h-14 border-b border-border flex items-center justify-between px-6 bg-card shrink-0">
      <div className="flex items-center gap-4">
        <h1 className="text-lg font-semibold">{title}</h1>
        {children}
      </div>
      <div className="flex items-center gap-3">
        <Button variant="outline" size="sm" className="gap-2 bg-transparent">
          <Search className="size-4" />
          Search
        </Button>
        <UserProfileMenu />
      </div>
    </header>
  )
}
