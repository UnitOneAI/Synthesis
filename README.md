# Synthesis

AI-powered threat modeling platform. Analyze GitHub repositories or design documents to generate structured threat models using STRIDE, OWASP Top 10, or AWS Threat Grammar frameworks.

## Features

- **Repository Analysis** — Point at a GitHub repo URL to auto-detect components, data flows, trust boundaries, and security findings
- **Design Document Analysis** — Upload PDF, Markdown, or text files to generate threats before writing code
- **Design Review Engine** — Generates security enhancement suggestions, pre-code architectural risks, and a context layer file (CLAUDE.md / AGENTS.md format)
- **Dual LLM Support** — Choose between Anthropic Claude or Google Gemini as the analysis engine
- **Data Flow Diagrams** — Auto-generated Mermaid DFDs from repository analysis
- **Jira Integration** — Create tickets directly from threat mitigations
- **PDF Export** — Download threat model reports as PDF
- **Project Management** — Organize sessions into projects

## Prerequisites

- **Node.js 20+**
- **pnpm** (install with `npm install -g pnpm`)

## Quick Start

```bash
# Clone the repo
git clone https://github.com/UnitOneAI/Synthesis.git
cd Synthesis

# Install dependencies
pnpm install

# Create env file with your API key (at least one required for LLM analysis)
cp .env.example .env.local
# Edit .env.local and add your key:
#   ANTHROPIC_API_KEY=sk-ant-...
#   or
#   GOOGLE_GEMINI_API_KEY=AIza...

# Start the dev server
pnpm dev
```

Open [http://localhost:3000](http://localhost:3000).

> **No API key?** The app runs in demo mode with realistic mock data — you can explore the full UI without any keys configured. Keys can also be added later from the Settings page.

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `ANTHROPIC_API_KEY` | No* | Anthropic API key for Claude |
| `GOOGLE_GEMINI_API_KEY` | No* | Google Gemini API key |
| `GITHUB_TOKEN` | No | GitHub PAT for private repo access |

\* At least one LLM key is needed for real analysis. Without one, the app uses demo mode. Keys can also be set from **Settings > Integrations** in the UI.

## Docker

```bash
# Build and run
docker compose up --build

# With API key
ANTHROPIC_API_KEY=sk-ant-... docker compose up --build
```

The app will be available at [http://localhost:3000](http://localhost:3000).

## Project Structure

```
app/
  threat-modeling/     Main threat modeling UI
  settings/            Settings & integrations page
  api/                 API routes (sessions, threats, settings, projects)
lib/
  llm-provider.ts      Shared LLM abstraction (Anthropic + Gemini)
  db.ts                SQLite database (auto-created, zero config)
  threat-engine/
    repo-analyzer.ts   GitHub repo cloning & analysis
    threat-generator.ts  LLM-powered threat generation
    design-review-engine.ts  Design enhancements, risks, context layer
    dfd-generator.ts   Data flow diagram generation
    document-parser.ts PDF/Markdown/text parsing
  jira-client.ts       Jira API integration
  pdf-export.ts        PDF report generation
```

## Tech Stack

- **Framework:** Next.js 16 (App Router, React 19)
- **Database:** SQLite via better-sqlite3 (auto-created, no setup needed)
- **UI:** Tailwind CSS, Radix UI, Lucide icons
- **LLMs:** Anthropic Claude Sonnet 4.5, Google Gemini 2.5

---

## Python Package (UnitoneController Integration)

Synthesis also provides a Python package for integration with UnitoneController.

### Installation

```bash
pip install git+https://github.com/UnitOneAI/Synthesis.git
```

### Usage with UnitoneController

```python
from synthesis import SynthesisThreatModelTool

# Register with UnitoneController
tool = SynthesisThreatModelTool()
registry.register(tool)

# Run threat model
from unitone import UnitOneFlow
unitone = UnitOneFlow("/path/to/repo")
result = unitone.run("synthesis")
```

### Standalone CLI

```bash
# Run threat model on a repository
python -m synthesis.tool /path/to/repo --framework STRIDE

# Or using npx (TypeScript CLI)
npx ts-node cli/scan.ts /path/to/repo --framework STRIDE
```

### Python Package Structure

```
synthesis/
├── __init__.py       # Package exports
├── models.py         # Data models (Threat, OWASP, STRIDE)
└── tool.py           # SynthesisThreatModelTool (Tool interface)

cli/
└── scan.ts           # TypeScript CLI (called by Python tool)
```

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    UnitoneController                             │
│                                                                  │
│  from synthesis import SynthesisThreatModelTool                  │
│  tool = SynthesisThreatModelTool()                               │
│  output = tool.run(context)                                      │
└───────────────────────────┬─────────────────────────────────────┘
                            │ subprocess
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Synthesis (Python)                            │
│                    synthesis/tool.py                             │
│                                                                  │
│  - Implements Tool interface                                     │
│  - Calls TypeScript CLI                                          │
│  - Parses JSON output to Issue objects                           │
└───────────────────────────┬─────────────────────────────────────┘
                            │ npx ts-node
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Synthesis (TypeScript)                        │
│                    cli/scan.ts                                   │
│                                                                  │
│  - Analyzes repository                                           │
│  - Generates STRIDE threats                                      │
│  - Calculates OWASP risk ratings                                 │
│  - Outputs JSON to stdout                                        │
└─────────────────────────────────────────────────────────────────┘
```

See `synthesis/CLAUDE.md` for detailed architecture documentation.

## License

Private — UnitOne AI
