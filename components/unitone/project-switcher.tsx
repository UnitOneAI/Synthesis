"use client"

import { useEffect, useState } from "react"
import { ChevronDown, FolderKanban, Plus } from "lucide-react"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"

interface Project {
  id: string
  name: string
  description: string
}

interface ProjectSwitcherProps {
  selectedProjectId: string | null
  onProjectChange: (projectId: string | null) => void
}

export function ProjectSwitcher({
  selectedProjectId,
  onProjectChange,
}: ProjectSwitcherProps) {
  const [projects, setProjects] = useState<Project[]>([])

  useEffect(() => {
    async function load() {
      try {
        const res = await fetch("/api/projects")
        if (res.ok) {
          setProjects(await res.json())
        }
      } catch {
        // Use empty list
      }
    }
    load()
  }, [])

  const selectedProject = projects.find((p) => p.id === selectedProjectId)

  async function handleNewProject() {
    const name = prompt("Project name:")
    if (!name) return
    try {
      const res = await fetch("/api/projects", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name }),
      })
      if (res.ok) {
        const project = await res.json()
        setProjects((prev) => [project, ...prev])
        onProjectChange(project.id)
      }
    } catch {
      // Handle error
    }
  }

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          variant="ghost"
          className="w-full justify-between text-sidebar-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground"
        >
          <div className="flex flex-col items-start text-left">
            <span className="text-xs text-sidebar-foreground/60">Project</span>
            <span className="text-sm truncate max-w-[160px]">
              {selectedProject?.name || "All Projects"}
            </span>
          </div>
          <ChevronDown className="size-4 opacity-50" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-56">
        <DropdownMenuItem onClick={() => onProjectChange(null)}>
          <FolderKanban className="size-4 mr-2" />
          All Projects
        </DropdownMenuItem>
        {projects.length > 0 && <DropdownMenuSeparator />}
        {projects.map((project) => (
          <DropdownMenuItem
            key={project.id}
            onClick={() => onProjectChange(project.id)}
          >
            <FolderKanban className="size-4 mr-2" />
            <span className="truncate">{project.name}</span>
          </DropdownMenuItem>
        ))}
        <DropdownMenuSeparator />
        <DropdownMenuItem onClick={handleNewProject}>
          <Plus className="size-4 mr-2" />
          New Project
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
