"use client"

import { useState } from "react"
import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  Clock,
  ExternalLink,
  FileCode,
  GitPullRequest,
  Play,
  Repeat,
  ShieldAlert,
  ShieldCheck,
  Users,
} from "lucide-react"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { ScrollArea } from "@/components/ui/scroll-area"
import { AppHeader, AppSidebar, ProjectProvider } from "@/components/unitone/app-sidebar"
import { CodeDiff } from "@/components/unitone/code-diff"
import { getSeverityColor } from "@/lib/threat-data"

// Types
interface CVEFix {
  summary: string
  filePath: string
  originalCode: string
  fixedCode: string
  lineStart: number
  lineEnd: number
}

interface CVE {
  id: string
  title: string
  severity: "Critical" | "High" | "Medium" | "Low"
  source: string
  file: string
  line: number
  timeEstimate: string
  assignee: {
    name: string
    initials: string
  }
  fix: CVEFix
}

// Mock Data
const cveData: CVE[] = [
  {
    id: "CVE-2024-1001",
    title: "SQL Injection in User Authentication Module",
    severity: "Critical",
    source: "Veracode",
    file: "pkg/auth/login.go",
    line: 127,
    timeEstimate: "15 min",
    assignee: { name: "Sarah Chen", initials: "SC" },
    fix: {
      summary:
        "This patch mitigates SQL injection on line 127 by replacing string concatenation with parameterized queries using prepared statements.",
      filePath: "pkg/auth/login.go",
      lineStart: 125,
      lineEnd: 133,
      originalCode: `func (a *Auth) ValidateUser(req, res) {
    username := req.Body.Username
    password := req.Body.Password
    query := "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
    result := db.Query(query)
    if result.Rows > 0 {
        return createSession(result.User)
    }
}`,
      fixedCode: `func (a *Auth) ValidateUser(req, res) {
    username := req.Body.Username
    password := req.Body.Password
    query := "SELECT * FROM users WHERE username=? AND password=?"
    stmt := db.Prepare(query)
    result := stmt.Query(username, hashPassword(password))
    if result.Rows > 0 {
        return createSession(result.User)
    }
}`,
    },
  },
  {
    id: "CVE-2024-1002",
    title: "Insecure MQTT Protocol in Chiller-Controller-V4",
    severity: "Critical",
    source: "Annual Pentest",
    file: "iot/controllers/chiller.c",
    line: 89,
    timeEstimate: "30 min",
    assignee: { name: "Mike Torres", initials: "MT" },
    fix: {
      summary:
        "Upgrades MQTT connection from plaintext to TLS 1.3 with certificate pinning to prevent man-in-the-middle attacks on building control systems.",
      filePath: "iot/controllers/chiller.c",
      lineStart: 87,
      lineEnd: 95,
      originalCode: `void connect_mqtt_broker() {
    mqtt_client *client = mqtt_new();
    client->host = BROKER_HOST;
    client->port = 1883;  // Unencrypted
    client->protocol = MQTT_PLAIN;
    mqtt_connect(client);
    subscribe_topics(client);
}`,
      fixedCode: `void connect_mqtt_broker() {
    mqtt_client *client = mqtt_new();
    client->host = BROKER_HOST;
    client->port = 8883;  // TLS encrypted
    client->protocol = MQTT_TLS_1_3;
    client->ca_cert = load_cert("/certs/ca.pem");
    client->verify_hostname = true;
    mqtt_connect(client);
    subscribe_topics(client);
}`,
    },
  },
  {
    id: "CVE-2024-1003",
    title: "Hardcoded API Key in Metasys-Cloud-Gateway",
    severity: "High",
    source: "SonarQube",
    file: "cloud/gateway/config.js",
    line: 23,
    timeEstimate: "10 min",
    assignee: { name: "Alex Kim", initials: "AK" },
    fix: {
      summary:
        "Removes hardcoded API credentials and migrates to HashiCorp Vault for secure secret management with automatic rotation.",
      filePath: "cloud/gateway/config.js",
      lineStart: 21,
      lineEnd: 28,
      originalCode: `const config = {
    apiEndpoint: "https://api.metasys.jci.com",
    apiKey: "sk_live_JCI_2024_BUILDING_MGMT_KEY",
    apiSecret: "super_secret_123!@#",
    timeout: 30000,
    retries: 3
};`,
      fixedCode: `const vault = require('@hashicorp/vault-client');

const config = {
    apiEndpoint: process.env.METASYS_API_ENDPOINT,
    apiKey: await vault.getSecret('metasys/api-key'),
    apiSecret: await vault.getSecret('metasys/api-secret'),
    timeout: 30000,
    retries: 3
};`,
    },
  },
  {
    id: "CVE-2024-1004",
    title: "Broken Access Control in HVAC API",
    severity: "High",
    source: "Veracode",
    file: "api/hvac/controls.py",
    line: 156,
    timeEstimate: "20 min",
    assignee: { name: "Jordan Lee", initials: "JL" },
    fix: {
      summary:
        "Implements role-based access control (RBAC) with tenant isolation to prevent unauthorized cross-tenant HVAC system access.",
      filePath: "api/hvac/controls.py",
      lineStart: 154,
      lineEnd: 164,
      originalCode: `@app.route('/api/hvac/setpoint', methods=['POST'])
def set_temperature():
    building_id = request.json['building_id']
    zone_id = request.json['zone_id']
    temp = request.json['temperature']
    
    hvac = get_hvac_controller(building_id, zone_id)
    hvac.set_setpoint(temp)
    return jsonify({"status": "success"})`,
      fixedCode: `@app.route('/api/hvac/setpoint', methods=['POST'])
@require_auth
@check_tenant_access
def set_temperature():
    user = get_current_user()
    building_id = request.json['building_id']
    
    if not user.can_access_building(building_id):
        raise PermissionDenied("Unauthorized building access")
    
    zone_id = request.json['zone_id']
    temp = request.json['temperature']
    
    audit_log(user, "HVAC_SETPOINT", building_id, zone_id)
    hvac = get_hvac_controller(building_id, zone_id)
    hvac.set_setpoint(temp)
    return jsonify({"status": "success"})`,
    },
  },
  {
    id: "CVE-2024-1005",
    title: "XSS in Tenant Management Portal",
    severity: "Medium",
    source: "Bug Bounty",
    file: "web/admin/tenants.tsx",
    line: 78,
    timeEstimate: "15 min",
    assignee: { name: "Casey Wong", initials: "CW" },
    fix: {
      summary:
        "Sanitizes user input and implements Content Security Policy headers to prevent cross-site scripting attacks in the admin portal.",
      filePath: "web/admin/tenants.tsx",
      lineStart: 76,
      lineEnd: 84,
      originalCode: `function TenantCard({ tenant }) {
  return (
    <div className="tenant-card">
      <h3 dangerouslySetInnerHTML={{ __html: tenant.name }} />
      <p>{tenant.description}</p>
      <span>{tenant.contactEmail}</span>
    </div>
  );
}`,
      fixedCode: `import DOMPurify from 'dompurify';

function TenantCard({ tenant }) {
  const sanitizedName = DOMPurify.sanitize(tenant.name);
  return (
    <div className="tenant-card">
      <h3>{sanitizedName}</h3>
      <p>{DOMPurify.sanitize(tenant.description)}</p>
      <span>{tenant.contactEmail}</span>
    </div>
  );
}`,
    },
  },
  {
    id: "CVE-2024-1006",
    title: "Outdated OpenSSL in Embedded Linux Firmware",
    severity: "Critical",
    source: "Dependency Scan",
    file: "firmware/build/openssl.mk",
    line: 12,
    timeEstimate: "45 min",
    assignee: { name: "Riley Park", initials: "RP" },
    fix: {
      summary:
        "Updates OpenSSL from vulnerable 1.0.2 to 3.0.12 LTS with security patches for CVE-2023-5678 and related vulnerabilities.",
      filePath: "firmware/build/openssl.mk",
      lineStart: 10,
      lineEnd: 18,
      originalCode: `OPENSSL_VERSION := 1.0.2u
OPENSSL_URL := https://www.openssl.org/source/openssl-$(OPENSSL_VERSION).tar.gz
OPENSSL_HASH := ecd0c6ffb493dd06707d38b14bb4d8c2288bb7033735606569d8f90f89669d16

$(OPENSSL_DIR)/.configured:
    ./Configure linux-generic32 --prefix=/usr
    touch $@`,
      fixedCode: `OPENSSL_VERSION := 3.0.12
OPENSSL_URL := https://www.openssl.org/source/openssl-$(OPENSSL_VERSION).tar.gz
OPENSSL_HASH := f93c9e8edde5e9166119de31755fc87b4aa34863662f67ddfcba14d0b6b69b61

$(OPENSSL_DIR)/.configured:
    ./Configure linux-generic32 --prefix=/usr \\
        no-ssl2 no-ssl3 no-weak-ssl-ciphers \\
        enable-ktls
    touch $@`,
    },
  },
]

// Main Dashboard Component
export default function UnitoneDashboard() {
  const [selectedCVE, setSelectedCVE] = useState<CVE | null>(null)

  return (
    <ProjectProvider>
    <div className="flex h-screen bg-background">
      <AppSidebar />

      <main className="flex-1 flex flex-col overflow-hidden">
        <AppHeader title="Security Dashboard">
          <Badge variant="secondary" className="gap-1">
            <span className="size-2 rounded-full bg-green-500" />
            All Systems Operational
          </Badge>
        </AppHeader>

        {/* Dashboard Content */}
        <ScrollArea className="flex-1">
          <div className="p-6 space-y-6">
            {/* KPI Cards */}
            <div className="grid grid-cols-4 gap-4">
              <Card className="py-4">
                <CardContent className="flex flex-col gap-1">
                  <div className="flex items-center gap-2">
                    <ShieldAlert className="size-5 text-red-500" />
                    <span className="text-sm text-muted-foreground">
                      Open CVEs
                    </span>
                  </div>
                  <div className="text-3xl font-bold">48,185</div>
                  <span className="text-xs text-muted-foreground">
                    +5% from last pentest
                  </span>
                </CardContent>
              </Card>

              <Card className="py-4">
                <CardContent className="flex flex-col gap-1">
                  <div className="flex items-center gap-2">
                    <Clock className="size-5 text-blue-500" />
                    <span className="text-sm text-muted-foreground">
                      Remediation Velocity
                    </span>
                  </div>
                  <div className="text-3xl font-bold">2.4 Days</div>
                  <span className="text-xs text-green-600">
                    Down from 45 days
                  </span>
                </CardContent>
              </Card>

              <Card className="py-4">
                <CardContent className="flex flex-col gap-1">
                  <div className="flex items-center gap-2">
                    <Repeat className="size-5 text-blue-500" />
                    <span className="text-sm text-muted-foreground">
                      Innovation Recovery
                    </span>
                  </div>
                  <div className="text-3xl font-bold">140h Saved</div>
                  <span className="text-xs text-muted-foreground">
                    Engineering cycles returned
                  </span>
                </CardContent>
              </Card>

              <Card className="py-4">
                <CardContent className="flex flex-col gap-1">
                  <div className="flex items-center gap-2">
                    <ShieldCheck className="size-5 text-green-500" />
                    <span className="text-sm text-muted-foreground">
                      Auto-Fixed
                    </span>
                  </div>
                  <div className="text-3xl font-bold">280</div>
                  <span className="text-xs text-muted-foreground">
                    {"Verified & Ready for PR"}
                  </span>
                </CardContent>
              </Card>
            </div>

            {/* CVE Table */}
            <Card>
              <div className="px-6 py-4 border-b border-border flex items-center justify-between">
                <h2 className="font-semibold">Remediation Feed</h2>
                <div className="flex items-center gap-2">
                  <Button variant="outline" size="sm" className="bg-transparent">
                    Filter
                  </Button>
                  <Button variant="outline" size="sm" className="bg-transparent">
                    Export
                  </Button>
                </div>
              </div>
              <div className="divide-y divide-border">
                {cveData.map((cve) => (
                  <div
                    key={cve.id}
                    className="px-6 py-4 flex items-center gap-4 hover:bg-muted/50 transition-colors"
                  >
                    {/* Severity */}
                    <Badge
                      variant="outline"
                      className={`${getSeverityColor(cve.severity)} min-w-[70px] justify-center`}
                    >
                      {cve.severity}
                    </Badge>

                    {/* CVE Info */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="font-medium truncate">{cve.title}</span>
                        <span className="text-xs text-muted-foreground">
                          {cve.id}
                        </span>
                      </div>
                      <div className="flex items-center gap-3 mt-1 text-sm text-muted-foreground">
                        <span className="flex items-center gap-1">
                          <FileCode className="size-3" />
                          {cve.file}:{cve.line}
                        </span>
                      </div>
                    </div>

                    {/* Source */}
                    <div className="text-sm text-muted-foreground w-24">
                      {cve.source}
                    </div>

                    {/* Time Estimate */}
                    <div className="flex items-center gap-1 text-sm text-muted-foreground w-20">
                      <Clock className="size-3" />
                      {cve.timeEstimate}
                    </div>

                    {/* Assignee */}
                    <div className="flex items-center gap-2 w-32">
                      <div className="size-7 rounded-full bg-muted flex items-center justify-center text-xs font-medium">
                        {cve.assignee.initials}
                      </div>
                      <span className="text-sm truncate">
                        {cve.assignee.name}
                      </span>
                    </div>

                    {/* Action */}
                    <Button
                      variant="outline"
                      size="sm"
                      className="gap-1 text-primary border-primary hover:bg-primary hover:text-primary-foreground bg-transparent"
                      onClick={() => setSelectedCVE(cve)}
                    >
                      Review Fix
                      <ExternalLink className="size-3" />
                    </Button>
                  </div>
                ))}
              </div>
            </Card>
          </div>
        </ScrollArea>
      </main>

      {/* AutoFix Modal */}
      <Dialog open={!!selectedCVE} onOpenChange={() => setSelectedCVE(null)}>
        <DialogContent className="max-w-4xl max-h-[90vh] overflow-hidden flex flex-col">
          <DialogHeader>
            <DialogTitle className="text-xl">Autofix Preview</DialogTitle>
          </DialogHeader>

          {selectedCVE && (
            <div className="flex-1 overflow-y-auto space-y-4">
              {/* Summary */}
              <div>
                <h3 className="text-sm font-medium text-muted-foreground mb-1">
                  Summary
                </h3>
                <p className="text-sm leading-relaxed">{selectedCVE.fix.summary}</p>
              </div>

              {/* Verification Badge */}
              <div className="flex items-center gap-2 p-3 rounded-lg bg-green-50 border border-green-200">
                <CheckCircle2 className="size-5 text-green-600" />
                <div>
                  <span className="font-medium text-green-800">
                    Unitone Verified
                  </span>
                  <span className="text-green-700 text-sm ml-2">
                    0% Regression Risk
                  </span>
                </div>
              </div>

              {/* Code Diff */}
              <CodeDiff
                original={selectedCVE.fix.originalCode}
                fixed={selectedCVE.fix.fixedCode}
                filePath={selectedCVE.fix.filePath}
                lineStart={selectedCVE.fix.lineStart}
              />
            </div>
          )}

          {/* Action Bar */}
          <div className="flex items-center justify-between pt-4 border-t border-border mt-4">
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" className="gap-2 bg-transparent">
                  Actions
                  <ChevronDown className="size-4" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent>
                <DropdownMenuItem>
                  <AlertTriangle className="size-4 mr-2" />
                  Mark as False Positive
                </DropdownMenuItem>
                <DropdownMenuItem>
                  <Clock className="size-4 mr-2" />
                  Snooze for 30 Days
                </DropdownMenuItem>
                <DropdownMenuItem>
                  <Users className="size-4 mr-2" />
                  Assign to Lead Architect
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>

            <div className="flex items-center gap-2">
              <Button variant="outline" className="gap-2 bg-transparent">
                <Play className="size-4" />
                Apply directly in VS Code
              </Button>
              <Button className="gap-2 bg-primary hover:bg-primary/90">
                <GitPullRequest className="size-4" />
                Create PR
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </div>
    </ProjectProvider>
  )
}
