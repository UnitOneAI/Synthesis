"use client"

import { useCallback, useEffect, useState } from "react"
import {
  Calendar,
  Code2,
  ExternalLink,
  GitBranch,
  Loader2,
  Shield,
} from "lucide-react"
import Link from "next/link"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { ScrollArea } from "@/components/ui/scroll-area"
import { AppHeader, AppSidebar, ProjectProvider } from "@/components/unitone/app-sidebar"

interface RepoItem {
  repoUrl: string
  sessionCount: number
  lastAnalyzed: string
  completedCount: number
}

function formatDate(dateStr: string) {
  return new Date(dateStr).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
  })
}

function parseRepoName(url: string): string {
  try {
    const cleaned = url.replace(/\.git$/, "").replace(/\/$/, "")
    const match = cleaned.match(/github\.com\/([^/]+\/[^/]+)/)
    if (match) return match[1]
    // Fallback: return last two path segments
    const parts = cleaned.split("/").filter(Boolean)
    if (parts.length >= 2) return `${parts[parts.length - 2]}/${parts[parts.length - 1]}`
    return url
  } catch {
    return url
  }
}

export default function RepositoriesPage() {
  const [repos, setRepos] = useState<RepoItem[]>([])
  const [loading, setLoading] = useState(true)

  const loadRepos = useCallback(async () => {
    setLoading(true)
    try {
      const res = await fetch("/api/repositories")
      if (res.ok) {
        setRepos(await res.json())
      }
    } catch {
      // Use defaults
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    loadRepos()
  }, [loadRepos])

  return (
    <ProjectProvider>
      <div className="flex h-screen bg-background">
        <AppSidebar />
        <main className="flex-1 flex flex-col overflow-hidden">
          <AppHeader title="Repositories">
            <Badge variant="secondary" className="gap-1 text-xs">
              <Code2 className="size-3" />
              GitHub
            </Badge>
          </AppHeader>

          <ScrollArea className="flex-1 overflow-hidden">
            <div className="p-6 max-w-4xl">
              {loading ? (
                <div className="flex items-center justify-center py-16">
                  <Loader2 className="size-6 animate-spin text-muted-foreground" />
                </div>
              ) : repos.length === 0 ? (
                <Card className="py-12">
                  <CardContent className="text-center">
                    <Code2 className="size-10 text-muted-foreground mx-auto mb-3" />
                    <h4 className="font-semibold mb-1">No repositories analyzed yet</h4>
                    <p className="text-sm text-muted-foreground">
                      Create a threat model session from a GitHub repo to see it here.
                    </p>
                  </CardContent>
                </Card>
              ) : (
                <div className="space-y-3">
                  {repos.map((repo) => (
                    <Card key={repo.repoUrl}>
                      <CardContent className="py-4 px-6">
                        <div className="flex items-start justify-between gap-4">
                          <div className="flex items-start gap-3 min-w-0">
                            <div className="size-9 rounded bg-gray-900 dark:bg-gray-700 flex items-center justify-center shrink-0 mt-0.5">
                              <GitBranch className="size-4 text-white" />
                            </div>
                            <div className="min-w-0">
                              <div className="flex items-center gap-2">
                                <h3 className="font-semibold truncate">
                                  {parseRepoName(repo.repoUrl)}
                                </h3>
                                <a
                                  href={repo.repoUrl}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="text-muted-foreground hover:text-foreground transition-colors shrink-0"
                                >
                                  <ExternalLink className="size-3.5" />
                                </a>
                              </div>
                              <p className="text-xs text-muted-foreground truncate mt-0.5">
                                {repo.repoUrl}
                              </p>
                              <div className="flex items-center gap-4 mt-2">
                                <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                                  <Shield className="size-3" />
                                  <span>
                                    {repo.sessionCount} session{repo.sessionCount !== 1 ? "s" : ""}
                                  </span>
                                </div>
                                <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                                  <Calendar className="size-3" />
                                  <span>{formatDate(repo.lastAnalyzed)}</span>
                                </div>
                                {repo.completedCount > 0 && (
                                  <Badge variant="secondary" className="text-[10px] px-1.5 py-0">
                                    {repo.completedCount} completed
                                  </Badge>
                                )}
                              </div>
                            </div>
                          </div>
                          <div className="flex items-center gap-2 shrink-0">
                            <Link href="/threat-modeling">
                              <Button variant="outline" size="sm" className="gap-1.5 bg-transparent text-xs">
                                <Shield className="size-3" />
                                View Sessions
                              </Button>
                            </Link>
                            <Button variant="outline" size="sm" className="gap-1.5 bg-transparent text-xs" disabled>
                              <GitBranch className="size-3" />
                              Re-analyze
                            </Button>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              )}
            </div>
          </ScrollArea>
        </main>
      </div>
    </ProjectProvider>
  )
}
