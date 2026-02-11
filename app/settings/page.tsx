"use client"

import { useCallback, useEffect, useState } from "react"
import {
  Check,
  ChevronDown,
  FolderKanban,
  Github,
  Key,
  Loader2,
  Pencil,
  Plus,
  Settings,
  Sparkles,
  Trash2,
  User,
  X,
} from "lucide-react"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { AppHeader, AppSidebar, ProjectProvider } from "@/components/unitone/app-sidebar"
import { SecureInput } from "@/components/unitone/secure-input"

interface ProjectItem {
  id: string
  name: string
  description: string
  createdAt: string
  updatedAt: string
}

export default function SettingsPage() {
  // Integrations state
  const [jiraUrl, setJiraUrl] = useState("")
  const [jiraEmail, setJiraEmail] = useState("")
  const [jiraToken, setJiraToken] = useState("")
  const [jiraProjectKey, setJiraProjectKey] = useState("")
  const [githubToken, setGithubToken] = useState("")
  const [anthropicKey, setAnthropicKey] = useState("")
  const [llmProvider, setLlmProvider] = useState<"anthropic" | "gemini">("anthropic")
  const [geminiKey, setGeminiKey] = useState("")
  const [geminiModel, setGeminiModel] = useState("gemini-2.5-flash")
  const [geminiEndpoint, setGeminiEndpoint] = useState("")
  const [saving, setSaving] = useState(false)
  const [saveSuccess, setSaveSuccess] = useState(false)

  // Profile state
  const [profileName, setProfileName] = useState("")
  const [profileEmail, setProfileEmail] = useState("")
  const [profileSaving, setProfileSaving] = useState(false)
  const [profileSaveSuccess, setProfileSaveSuccess] = useState(false)

  // Projects state
  const [projects, setProjects] = useState<ProjectItem[]>([])
  const [projectsLoading, setProjectsLoading] = useState(true)
  const [newProjectName, setNewProjectName] = useState("")
  const [newProjectDesc, setNewProjectDesc] = useState("")
  const [showNewProject, setShowNewProject] = useState(false)
  const [editingProject, setEditingProject] = useState<string | null>(null)
  const [editName, setEditName] = useState("")
  const [editDesc, setEditDesc] = useState("")

  const loadSettings = useCallback(async () => {
    try {
      const res = await fetch("/api/settings")
      if (res.ok) {
        const data = await res.json()
        for (const s of data) {
          switch (s.key) {
            case "jira_url": setJiraUrl(s.value); break
            case "jira_email": setJiraEmail(s.value); break
            case "jira_token": setJiraToken(s.value); break
            case "jira_project_key": setJiraProjectKey(s.value); break
            case "github_token": setGithubToken(s.value); break
            case "anthropic_key": setAnthropicKey(s.value); break
            case "llm_provider": setLlmProvider(s.value === "gemini" ? "gemini" : "anthropic"); break
            case "gemini_key": setGeminiKey(s.value); break
            case "gemini_model": setGeminiModel(s.value || "gemini-2.5-flash"); break
            case "gemini_endpoint": setGeminiEndpoint(s.value); break
            case "profile_name": setProfileName(s.value); break
            case "profile_email": setProfileEmail(s.value); break
          }
        }
      }
    } catch {
      // Use defaults
    }
  }, [])

  const loadProjects = useCallback(async () => {
    setProjectsLoading(true)
    try {
      const res = await fetch("/api/projects")
      if (res.ok) {
        setProjects(await res.json())
      }
    } catch {
      // Use defaults
    } finally {
      setProjectsLoading(false)
    }
  }, [])

  useEffect(() => {
    loadSettings()
    loadProjects()
  }, [loadSettings, loadProjects])

  async function handleSaveIntegrations() {
    setSaving(true)
    setSaveSuccess(false)
    try {
      const settings = [
        { key: "jira_url", value: jiraUrl, category: "jira", isSecret: false },
        { key: "jira_email", value: jiraEmail, category: "jira", isSecret: false },
        { key: "jira_token", value: jiraToken, category: "jira", isSecret: true },
        { key: "jira_project_key", value: jiraProjectKey, category: "jira", isSecret: false },
        { key: "github_token", value: githubToken, category: "github", isSecret: true },
        { key: "anthropic_key", value: anthropicKey, category: "anthropic", isSecret: true },
        { key: "llm_provider", value: llmProvider, category: "llm", isSecret: false },
        { key: "gemini_key", value: geminiKey, category: "gemini", isSecret: true },
        { key: "gemini_model", value: geminiModel, category: "gemini", isSecret: false },
        { key: "gemini_endpoint", value: geminiEndpoint, category: "gemini", isSecret: false },
      ].filter((s) => s.value)

      await fetch("/api/settings", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ settings }),
      })
      setSaveSuccess(true)
      setTimeout(() => setSaveSuccess(false), 3000)
    } catch {
      // Handle error
    } finally {
      setSaving(false)
    }
  }

  async function handleSaveProfile() {
    setProfileSaving(true)
    setProfileSaveSuccess(false)
    try {
      const settings = [
        { key: "profile_name", value: profileName, category: "profile", isSecret: false },
        { key: "profile_email", value: profileEmail, category: "profile", isSecret: false },
      ].filter((s) => s.value)

      await fetch("/api/settings", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ settings }),
      })
      setProfileSaveSuccess(true)
      setTimeout(() => setProfileSaveSuccess(false), 3000)
    } catch {
      // Handle error
    } finally {
      setProfileSaving(false)
    }
  }

  async function handleCreateProject() {
    if (!newProjectName) return
    try {
      await fetch("/api/projects", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: newProjectName, description: newProjectDesc }),
      })
      setNewProjectName("")
      setNewProjectDesc("")
      setShowNewProject(false)
      loadProjects()
    } catch {
      // Handle error
    }
  }

  async function handleUpdateProject(id: string) {
    try {
      await fetch(`/api/projects/${id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: editName, description: editDesc }),
      })
      setEditingProject(null)
      loadProjects()
    } catch {
      // Handle error
    }
  }

  async function handleDeleteProject(id: string) {
    try {
      await fetch(`/api/projects/${id}`, { method: "DELETE" })
      loadProjects()
    } catch {
      // Handle error
    }
  }

  return (
    <ProjectProvider>
    <div className="flex h-screen bg-background">
      <AppSidebar />
      <main className="flex-1 flex flex-col overflow-hidden">
        <AppHeader title="Settings">
          <Badge variant="secondary" className="gap-1 text-xs">
            <Settings className="size-3" />
            Configuration
          </Badge>
        </AppHeader>

        <ScrollArea className="flex-1 overflow-hidden">
          <div className="p-6 max-w-4xl">
            <Tabs defaultValue="integrations">
              <TabsList>
                <TabsTrigger value="integrations" className="gap-1.5">
                  <Key className="size-3.5" />
                  Integrations
                </TabsTrigger>
                <TabsTrigger value="profile" className="gap-1.5">
                  <User className="size-3.5" />
                  Profile
                </TabsTrigger>
                <TabsTrigger value="projects" className="gap-1.5">
                  <FolderKanban className="size-3.5" />
                  Projects
                </TabsTrigger>
              </TabsList>

              {/* Integrations Tab */}
              <TabsContent value="integrations" className="space-y-6 mt-6">
                {/* LLM Provider Toggle */}
                <Card>
                  <CardContent className="pt-6 space-y-4">
                    <div className="flex items-center gap-2 mb-2">
                      <Sparkles className="size-5 text-primary" />
                      <div>
                        <h3 className="font-semibold">LLM Provider</h3>
                        <p className="text-xs text-muted-foreground">
                          Select which AI provider to use for threat analysis
                        </p>
                      </div>
                    </div>
                    <div className="flex gap-2">
                      <button
                        type="button"
                        onClick={() => setLlmProvider("anthropic")}
                        className={`flex-1 px-4 py-2.5 rounded-md border text-sm font-medium transition-colors ${
                          llmProvider === "anthropic"
                            ? "bg-primary text-primary-foreground border-primary"
                            : "bg-background text-muted-foreground border-input hover:bg-muted"
                        }`}
                      >
                        Anthropic (Claude)
                      </button>
                      <button
                        type="button"
                        onClick={() => setLlmProvider("gemini")}
                        className={`flex-1 px-4 py-2.5 rounded-md border text-sm font-medium transition-colors ${
                          llmProvider === "gemini"
                            ? "bg-primary text-primary-foreground border-primary"
                            : "bg-background text-muted-foreground border-input hover:bg-muted"
                        }`}
                      >
                        Google Gemini
                      </button>
                    </div>
                  </CardContent>
                </Card>

                {/* Jira */}
                <Card>
                  <CardContent className="pt-6 space-y-4">
                    <div className="flex items-center gap-2 mb-4">
                      <div className="size-8 rounded bg-blue-600 flex items-center justify-center">
                        <span className="text-sm font-bold text-white">J</span>
                      </div>
                      <div>
                        <h3 className="font-semibold">Jira Integration</h3>
                        <p className="text-xs text-muted-foreground">
                          Connect to create tickets from threat mitigations
                        </p>
                      </div>
                    </div>
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <label className="text-sm font-medium mb-1.5 block">Jira URL</label>
                        <input
                          type="text"
                          value={jiraUrl}
                          onChange={(e) => setJiraUrl(e.target.value)}
                          placeholder="https://your-domain.atlassian.net"
                          className="w-full px-3 py-2 rounded-md border border-input bg-background text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                        />
                      </div>
                      <div>
                        <label className="text-sm font-medium mb-1.5 block">Email</label>
                        <input
                          type="email"
                          value={jiraEmail}
                          onChange={(e) => setJiraEmail(e.target.value)}
                          placeholder="you@company.com"
                          className="w-full px-3 py-2 rounded-md border border-input bg-background text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                        />
                      </div>
                      <div>
                        <label className="text-sm font-medium mb-1.5 block">API Token</label>
                        <SecureInput
                          value={jiraToken}
                          onChange={setJiraToken}
                          placeholder="Jira API token"
                        />
                      </div>
                      <div>
                        <label className="text-sm font-medium mb-1.5 block">Project Key</label>
                        <input
                          type="text"
                          value={jiraProjectKey}
                          onChange={(e) => setJiraProjectKey(e.target.value)}
                          placeholder="e.g., SEC"
                          className="w-full px-3 py-2 rounded-md border border-input bg-background text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                        />
                      </div>
                    </div>
                  </CardContent>
                </Card>

                {/* GitHub */}
                <Card>
                  <CardContent className="pt-6 space-y-4">
                    <div className="flex items-center gap-2 mb-4">
                      <div className="size-8 rounded bg-gray-900 flex items-center justify-center">
                        <Github className="size-4 text-white" />
                      </div>
                      <div>
                        <h3 className="font-semibold">GitHub</h3>
                        <p className="text-xs text-muted-foreground">
                          Personal access token for repository operations and PR creation
                        </p>
                      </div>
                    </div>
                    <div>
                      <label className="text-sm font-medium mb-1.5 block">
                        Personal Access Token
                      </label>
                      <SecureInput
                        value={githubToken}
                        onChange={setGithubToken}
                        placeholder="ghp_..."
                      />
                    </div>
                  </CardContent>
                </Card>

                {/* Anthropic */}
                <Card>
                  <CardContent className="pt-6 space-y-4">
                    <div className="flex items-center gap-2 mb-4">
                      <div className="size-8 rounded bg-orange-600 flex items-center justify-center">
                        <Key className="size-4 text-white" />
                      </div>
                      <div>
                        <h3 className="font-semibold">Anthropic</h3>
                        <p className="text-xs text-muted-foreground">
                          API key for Claude-powered threat analysis
                          {llmProvider === "anthropic" && (
                            <span className="ml-1.5 inline-flex items-center rounded-full bg-green-100 px-1.5 py-0.5 text-[10px] font-medium text-green-700 dark:bg-green-900/30 dark:text-green-400">Active</span>
                          )}
                        </p>
                      </div>
                    </div>
                    <div>
                      <label className="text-sm font-medium mb-1.5 block">API Key</label>
                      <SecureInput
                        value={anthropicKey}
                        onChange={setAnthropicKey}
                        placeholder="sk-ant-..."
                      />
                    </div>
                  </CardContent>
                </Card>

                {/* Google Gemini */}
                <Card>
                  <CardContent className="pt-6 space-y-4">
                    <div className="flex items-center gap-2 mb-4">
                      <div className="size-8 rounded bg-blue-500 flex items-center justify-center">
                        <Sparkles className="size-4 text-white" />
                      </div>
                      <div>
                        <h3 className="font-semibold">Google Gemini</h3>
                        <p className="text-xs text-muted-foreground">
                          API key for Gemini-powered threat analysis
                          {llmProvider === "gemini" && (
                            <span className="ml-1.5 inline-flex items-center rounded-full bg-green-100 px-1.5 py-0.5 text-[10px] font-medium text-green-700 dark:bg-green-900/30 dark:text-green-400">Active</span>
                          )}
                        </p>
                      </div>
                    </div>
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <label className="text-sm font-medium mb-1.5 block">API Key</label>
                        <SecureInput
                          value={geminiKey}
                          onChange={setGeminiKey}
                          placeholder="AIza..."
                        />
                      </div>
                      <div>
                        <label className="text-sm font-medium mb-1.5 block">Model</label>
                        <div className="relative">
                          <select
                            value={geminiModel}
                            onChange={(e) => setGeminiModel(e.target.value)}
                            className="w-full appearance-none px-3 py-2 rounded-md border border-input bg-background text-sm focus:outline-none focus:ring-2 focus:ring-ring pr-8"
                          >
                            <option value="gemini-2.5-pro">Gemini 2.5 Pro</option>
                            <option value="gemini-2.5-flash">Gemini 2.5 Flash</option>
                            <option value="gemini-2.0-flash">Gemini 2.0 Flash</option>
                          </select>
                          <ChevronDown className="absolute right-2.5 top-1/2 -translate-y-1/2 size-4 text-muted-foreground pointer-events-none" />
                        </div>
                      </div>
                    </div>
                    <div>
                      <label className="text-sm font-medium mb-1.5 block">
                        API Endpoint <span className="text-muted-foreground font-normal">(optional)</span>
                      </label>
                      <input
                        type="text"
                        value={geminiEndpoint}
                        onChange={(e) => setGeminiEndpoint(e.target.value)}
                        placeholder="https://generativelanguage.googleapis.com"
                        className="w-full px-3 py-2 rounded-md border border-input bg-background text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                      />
                      <p className="text-xs text-muted-foreground mt-1">
                        Custom endpoint for Vertex AI or proxy setups. Leave blank for default.
                      </p>
                    </div>
                  </CardContent>
                </Card>

                <div className="flex items-center gap-3">
                  <Button
                    onClick={handleSaveIntegrations}
                    disabled={saving}
                    className="gap-2 bg-primary hover:bg-primary/90"
                  >
                    {saving ? (
                      <Loader2 className="size-4 animate-spin" />
                    ) : saveSuccess ? (
                      <Check className="size-4" />
                    ) : null}
                    {saveSuccess ? "Saved" : "Save Integrations"}
                  </Button>
                </div>
              </TabsContent>

              {/* Profile Tab */}
              <TabsContent value="profile" className="space-y-6 mt-6">
                <Card>
                  <CardContent className="pt-6 space-y-4">
                    <div className="flex items-center gap-2 mb-4">
                      <User className="size-5 text-primary" />
                      <h3 className="font-semibold">User Profile</h3>
                    </div>
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <label className="text-sm font-medium mb-1.5 block">Name</label>
                        <input
                          type="text"
                          value={profileName}
                          onChange={(e) => setProfileName(e.target.value)}
                          placeholder="Your name"
                          className="w-full px-3 py-2 rounded-md border border-input bg-background text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                        />
                      </div>
                      <div>
                        <label className="text-sm font-medium mb-1.5 block">Email</label>
                        <input
                          type="email"
                          value={profileEmail}
                          onChange={(e) => setProfileEmail(e.target.value)}
                          placeholder="you@company.com"
                          className="w-full px-3 py-2 rounded-md border border-input bg-background text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                        />
                      </div>
                    </div>
                  </CardContent>
                </Card>
                <div className="flex items-center gap-3">
                  <Button
                    onClick={handleSaveProfile}
                    disabled={profileSaving}
                    className="gap-2 bg-primary hover:bg-primary/90"
                  >
                    {profileSaving ? (
                      <Loader2 className="size-4 animate-spin" />
                    ) : profileSaveSuccess ? (
                      <Check className="size-4" />
                    ) : null}
                    {profileSaveSuccess ? "Saved" : "Save Profile"}
                  </Button>
                </div>
              </TabsContent>

              {/* Projects Tab */}
              <TabsContent value="projects" className="space-y-6 mt-6">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="font-semibold">Projects</h3>
                    <p className="text-sm text-muted-foreground">
                      Organize threat model sessions into projects
                    </p>
                  </div>
                  <Button
                    onClick={() => setShowNewProject(true)}
                    className="gap-2 bg-primary hover:bg-primary/90"
                    size="sm"
                  >
                    <Plus className="size-4" />
                    New Project
                  </Button>
                </div>

                {showNewProject && (
                  <Card>
                    <CardContent className="pt-6 space-y-4">
                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <label className="text-sm font-medium mb-1.5 block">
                            Project Name
                          </label>
                          <input
                            type="text"
                            value={newProjectName}
                            onChange={(e) => setNewProjectName(e.target.value)}
                            placeholder="e.g., Smart Building Cloud"
                            className="w-full px-3 py-2 rounded-md border border-input bg-background text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                          />
                        </div>
                        <div>
                          <label className="text-sm font-medium mb-1.5 block">
                            Description
                          </label>
                          <input
                            type="text"
                            value={newProjectDesc}
                            onChange={(e) => setNewProjectDesc(e.target.value)}
                            placeholder="Optional description"
                            className="w-full px-3 py-2 rounded-md border border-input bg-background text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                          />
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <Button size="sm" onClick={handleCreateProject} className="gap-1">
                          <Check className="size-3" />
                          Create
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => {
                            setShowNewProject(false)
                            setNewProjectName("")
                            setNewProjectDesc("")
                          }}
                          className="gap-1 bg-transparent"
                        >
                          <X className="size-3" />
                          Cancel
                        </Button>
                      </div>
                    </CardContent>
                  </Card>
                )}

                {projectsLoading ? (
                  <div className="flex items-center justify-center py-8">
                    <Loader2 className="size-6 animate-spin text-muted-foreground" />
                  </div>
                ) : projects.length === 0 ? (
                  <Card className="py-12">
                    <CardContent className="text-center">
                      <FolderKanban className="size-10 text-muted-foreground mx-auto mb-3" />
                      <h4 className="font-semibold mb-1">No Projects Yet</h4>
                      <p className="text-sm text-muted-foreground">
                        Create a project to organize your threat model sessions.
                      </p>
                    </CardContent>
                  </Card>
                ) : (
                  <div className="space-y-3">
                    {projects.map((project) => (
                      <Card key={project.id}>
                        <CardContent className="py-4 px-6">
                          {editingProject === project.id ? (
                            <div className="space-y-3">
                              <div className="grid grid-cols-2 gap-4">
                                <input
                                  type="text"
                                  value={editName}
                                  onChange={(e) => setEditName(e.target.value)}
                                  className="px-3 py-2 rounded-md border border-input bg-background text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                                />
                                <input
                                  type="text"
                                  value={editDesc}
                                  onChange={(e) => setEditDesc(e.target.value)}
                                  className="px-3 py-2 rounded-md border border-input bg-background text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                                />
                              </div>
                              <div className="flex items-center gap-2">
                                <Button
                                  size="sm"
                                  onClick={() => handleUpdateProject(project.id)}
                                  className="gap-1"
                                >
                                  <Check className="size-3" />
                                  Save
                                </Button>
                                <Button
                                  size="sm"
                                  variant="outline"
                                  onClick={() => setEditingProject(null)}
                                  className="gap-1 bg-transparent"
                                >
                                  <X className="size-3" />
                                  Cancel
                                </Button>
                              </div>
                            </div>
                          ) : (
                            <div className="flex items-center justify-between">
                              <div>
                                <div className="flex items-center gap-2">
                                  <FolderKanban className="size-4 text-primary" />
                                  <span className="font-medium">{project.name}</span>
                                </div>
                                {project.description && (
                                  <p className="text-sm text-muted-foreground mt-1 ml-6">
                                    {project.description}
                                  </p>
                                )}
                              </div>
                              <div className="flex items-center gap-1">
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  onClick={() => {
                                    setEditingProject(project.id)
                                    setEditName(project.name)
                                    setEditDesc(project.description || "")
                                  }}
                                  className="size-8 p-0"
                                >
                                  <Pencil className="size-3.5" />
                                </Button>
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  onClick={() => handleDeleteProject(project.id)}
                                  className="size-8 p-0 text-red-500 hover:text-red-600"
                                >
                                  <Trash2 className="size-3.5" />
                                </Button>
                              </div>
                            </div>
                          )}
                        </CardContent>
                      </Card>
                    ))}
                  </div>
                )}
              </TabsContent>
            </Tabs>
          </div>
        </ScrollArea>
      </main>
    </div>
    </ProjectProvider>
  )
}
