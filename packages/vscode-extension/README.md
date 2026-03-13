# Synthesis Threat Model — VS Code / Cursor Extension

AI-powered STRIDE threat modeling directly in your editor. Analyze your codebase, individual files, or git changes to identify security threats, generate data flow diagrams, and get actionable mitigations — all mapped to MITRE ATT&CK techniques.

Works in both **VS Code** and **Cursor**.

## Features

### Scan Commands

| Command | Description |
|---------|-------------|
| `Synthesis: Scan Workspace for Threats` | STRIDE analysis across your entire project |
| `Synthesis: Scan This File for Threats` | Analyze the currently open file |
| `Synthesis: Scan Uncommitted Git Changes` | Analyze your `git diff` before committing |
| `Synthesis: Show Threat Model Panel` | Open the results webview |

Access via **Command Palette** (`Cmd+Shift+P` / `Ctrl+Shift+P`) or **right-click** any file in the editor or explorer.

### Threat Explorer Sidebar

A dedicated shield icon in the activity bar opens the **Threat Explorer** tree view, grouping identified threats by:

- STRIDE category (Spoofing, Tampering, Repudiation, etc.)
- Severity level (Critical, High, Medium, Low)
- Component name

Click any threat to view full details.

### Threat Model Panel (Webview)

After a scan completes, a rich webview panel displays:

- **Summary cards** — Critical / High / Medium / Low counts at a glance
- **Threat register table** — Sortable, filterable by severity
- **Expandable details** — Full description, mitigation, and ATT&CK technique per threat
- **Data Flow Diagram** — Auto-generated Mermaid DFD with trust boundaries
- **Export buttons** — Save as Markdown or JSON

### Inline Annotations

- **CodeLens** — Shows threat counts above functions and classes with associated threats
- **Problems panel** — Threats appear as diagnostics (Error for critical/high, Warning for medium, Info for low)
- **Status bar** — Persistent threat count indicator (e.g., `Synthesis: 2C 5H 3M`)

## Installation

### From VSIX

```bash
# VS Code
code --install-extension synthesis-threat-model-0.2.0.vsix

# Cursor
cursor --install-extension synthesis-threat-model-0.2.0.vsix
```

Or: `Cmd+Shift+P` → `Extensions: Install from VSIX...` → select the `.vsix` file.

### From Source (Development)

```bash
git clone https://github.com/UnitOneAI/Synthesis.git
cd Synthesis
pnpm install
pnpm --filter @synthesis/core build
pnpm --filter synthesis-threat-model build
```

Press **F5** in VS Code to launch the Extension Development Host.

## Configuration

### API Key Setup (Secure)

API keys are stored in **VS Code SecretStorage** — never in plaintext `settings.json`.

On first scan, you'll be prompted to enter your key. To update it later:

1. Open Command Palette
2. Run any scan command
3. Select "Set API Key" when prompted

**Supported providers:**

| Provider | Model | Key required |
|----------|-------|-------------|
| Anthropic | Claude Sonnet 4.5 | `ANTHROPIC_API_KEY` |
| Google | Gemini 2.5 Flash | `GOOGLE_GEMINI_API_KEY` |

At least one API key is required.

### Settings

Configure via `File → Preferences → Settings → Synthesis Threat Model`:

| Setting | Default | Description |
|---------|---------|-------------|
| `synthesis.provider` | `anthropic` | AI provider (`anthropic` or `gemini`) |
| `synthesis.frameworks` | `["STRIDE"]` | Frameworks to apply (`STRIDE`, `OWASP`, `AWS_THREAT_GRAMMAR`) |
| `synthesis.severityThreshold` | `low` | Minimum severity to display |
| `synthesis.maxFiles` | `100` | Max files in workspace scan (1-500) |

## Output Formats

### Threat Register

Each threat includes:

- **ID** — Unique identifier (e.g., `TM-001`)
- **STRIDE Category** — Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege
- **Severity** — Critical, High, Medium, Low (calculated via likelihood x impact matrix)
- **Component** — Affected system component
- **ATT&CK Technique** — Mapped MITRE ATT&CK ID (e.g., T1078, T1190)
- **Mitigation** — Specific remediation guidance
- **Status** — Open / In Progress / Resolved

### Data Flow Diagram

Auto-generated Mermaid DFD showing:
- Components with type-specific shapes (services, datastores, gateways, queues)
- Trust boundaries as subgraphs
- Cross-boundary data flows as dashed lines
- Risk-based color coding

### Export

- **Markdown** — GitHub-flavored with collapsible threat details
- **JSON** — Structured format for integration with other tools

## Security Architecture

This extension was built using [UnitOne SecuritySkills](https://github.com/UnitOneAI/SecuritySkills) secure development patterns:

| Control | Implementation |
|---------|---------------|
| Secret storage | VS Code SecretStorage API — keys never in plaintext settings |
| Content Security Policy | Strict CSP with nonce-based scripts in all webviews |
| XSS prevention | All dynamic content HTML-escaped before rendering |
| Mermaid injection | Directive stripping, HTML tag removal, `javascript:` URI blocking |
| Path traversal | `path.resolve` + `startsWith` validation, workspace-scoped only |
| Resource limits | Configurable `maxFiles`, 1MB diff cap, cancellation support |
| Shell safety | `spawn()` with `shell: false`, args as array (no interpolation) |
| Trust boundary | Server-side severity recalculation — LLM scores never trusted |

## Requirements

- VS Code 1.85+ or Cursor (any recent version)
- Node.js 20+ (for development only)
- At least one API key (Anthropic or Google Gemini)

## Part of the Synthesis Platform

This extension is one surface of the Synthesis threat modeling platform:

| Surface | Description |
|---------|-------------|
| **VS Code / Cursor Extension** | Editor integration (this package) |
| **GitHub Action** | CI/CD pipeline — runs on every PR |
| **Synthesis Web** | Full web UI with project management |

All share the `@synthesis/core` engine for consistent threat analysis.

## License

MIT — UnitOne AI
