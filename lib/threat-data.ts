// ============================================
// Threat Composer Data Types & Mock Data
// Based on AWS Threat Composer Threat Grammar
// ============================================

// STRIDE Categories
export type StrideCategory =
  | "Spoofing"
  | "Tampering"
  | "Repudiation"
  | "Information Disclosure"
  | "Denial of Service"
  | "Elevation of Privilege"

export type Severity = "Critical" | "High" | "Medium" | "Low"

export type ThreatStatus =
  | "Identified"
  | "In Progress"
  | "Mitigated"
  | "Accepted"

// AWS Threat Grammar: An [Actor] can [Action] against [Asset] leading to [Impact]
export interface ThreatStatement {
  actor: string
  action: string
  asset: string
  impact: string
}

export interface Mitigation {
  id: string
  description: string
  status: "Proposed" | "Implemented" | "Verified"
  codeSnippet?: {
    file: string
    line: number
    original: string
    fixed: string
  }
  jiraTicket?: {
    key: string
    summary: string
    status: "To Do" | "In Progress" | "Done"
  }
}

export interface Threat {
  id: string
  title: string
  stride: StrideCategory
  severity: Severity
  status: ThreatStatus
  threatStatement: ThreatStatement
  trustBoundary: string
  assumptions: string[]
  mitigations: Mitigation[]
  relatedCVE?: string
}

export interface ThreatModelSession {
  id: string
  name: string
  description: string
  source: "design-doc" | "github-repo"
  sourceRef: string
  createdAt: string
  status: "Processing" | "Review" | "Complete"
  threats: Threat[]
  dataFlowDiagram: string // Mermaid.js
  stats: {
    total: number
    critical: number
    high: number
    medium: number
    low: number
    mitigated: number
  }
}

// Helper
export function getSeverityColor(severity: Severity) {
  switch (severity) {
    case "Critical":
      return "bg-red-500/10 text-red-600 border-red-200"
    case "High":
      return "bg-orange-500/10 text-orange-600 border-orange-200"
    case "Medium":
      return "bg-yellow-500/10 text-yellow-700 border-yellow-200"
    case "Low":
      return "bg-green-500/10 text-green-600 border-green-200"
  }
}

export function getStrideColor(stride: StrideCategory) {
  switch (stride) {
    case "Spoofing":
      return "bg-violet-500/10 text-violet-700 border-violet-200"
    case "Tampering":
      return "bg-red-500/10 text-red-600 border-red-200"
    case "Repudiation":
      return "bg-amber-500/10 text-amber-700 border-amber-200"
    case "Information Disclosure":
      return "bg-blue-500/10 text-blue-600 border-blue-200"
    case "Denial of Service":
      return "bg-orange-500/10 text-orange-600 border-orange-200"
    case "Elevation of Privilege":
      return "bg-rose-500/10 text-rose-700 border-rose-200"
  }
}

export function getStatusColor(status: ThreatStatus) {
  switch (status) {
    case "Identified":
      return "bg-red-500/10 text-red-600 border-red-200"
    case "In Progress":
      return "bg-blue-500/10 text-blue-600 border-blue-200"
    case "Mitigated":
      return "bg-green-500/10 text-green-600 border-green-200"
    case "Accepted":
      return "bg-muted text-muted-foreground border-border"
  }
}

// All past sessions for the session list view
export const allSessions: {
  id: string
  name: string
  source: "design-doc" | "github-repo"
  sourceRef: string
  createdAt: string
  status: "Processing" | "Review" | "Complete"
  framework: string
  stats: ThreatModelSession["stats"]
}[] = [
  {
    id: "tm-001",
    name: "HVAC Cloud API - Threat Model",
    source: "github-repo",
    sourceRef: "github.com/jci/smart-building-cloud",
    createdAt: "2026-02-04T14:30:00Z",
    status: "Review",
    framework: "STRIDE",
    stats: { total: 8, critical: 2, high: 3, medium: 2, low: 1, mitigated: 3 },
  },
  {
    id: "tm-002",
    name: "Fire Safety Controller - Threat Model",
    source: "github-repo",
    sourceRef: "github.com/jci/fire-safety-platform",
    createdAt: "2026-01-22T09:15:00Z",
    status: "Complete",
    framework: "STRIDE",
    stats: { total: 6, critical: 1, high: 2, medium: 2, low: 1, mitigated: 5 },
  },
  {
    id: "tm-003",
    name: "Tenant Management Portal - Threat Model",
    source: "design-doc",
    sourceRef: "tenant-portal-design-v3.pdf",
    createdAt: "2026-01-15T11:00:00Z",
    status: "Complete",
    framework: "OWASP Top 10",
    stats: { total: 10, critical: 3, high: 4, medium: 2, low: 1, mitigated: 8 },
  },
  {
    id: "tm-004",
    name: "BACnet Edge Gateway Firmware - Threat Model",
    source: "github-repo",
    sourceRef: "github.com/jci/bacnet-edge-firmware",
    createdAt: "2026-01-08T16:45:00Z",
    status: "Complete",
    framework: "STRIDE",
    stats: { total: 5, critical: 2, high: 2, medium: 1, low: 0, mitigated: 4 },
  },
  {
    id: "tm-005",
    name: "OpenBlue Cloud Identity Service",
    source: "design-doc",
    sourceRef: "identity-service-arch.md",
    createdAt: "2025-12-19T10:30:00Z",
    status: "Complete",
    framework: "STRIDE",
    stats: { total: 7, critical: 1, high: 3, medium: 2, low: 1, mitigated: 6 },
  },
  {
    id: "tm-006",
    name: "Chiller Plant Optimization ML Pipeline",
    source: "github-repo",
    sourceRef: "github.com/jci/chiller-ml-pipeline",
    createdAt: "2025-12-05T13:20:00Z",
    status: "Review",
    framework: "AWS Threat Grammar",
    stats: { total: 4, critical: 0, high: 2, medium: 2, low: 0, mitigated: 1 },
  },
]

// Mock Threat Model Session — JCI Smart Building Cloud
export const mockSession: ThreatModelSession = {
  id: "tm-001",
  name: "HVAC Cloud API - Threat Model",
  description:
    "Threat model for the JCI Smart Building Cloud HVAC Control API, covering BACnet/IP gateway, MQTT message broker, and tenant management plane.",
  source: "github-repo",
  sourceRef: "github.com/jci/smart-building-cloud",
  createdAt: "2026-02-04T14:30:00Z",
  status: "Review",
  dataFlowDiagram: `graph LR
    subgraph External
      A[Building Operator] -->|HTTPS| B[API Gateway]
      F[IoT Sensors] -->|MQTT/TLS| E
    end
    subgraph Trust Boundary: Cloud
      B --> C[Auth Service]
      B --> D[HVAC Controller API]
      D --> E[MQTT Broker]
      D --> G[(Tenant DB)]
      C --> G
    end
    subgraph Trust Boundary: Edge
      E --> H[BACnet/IP Gateway]
      H --> I[Chiller Units]
      H --> J[AHU Controllers]
    end`,
  stats: {
    total: 8,
    critical: 2,
    high: 3,
    medium: 2,
    low: 1,
    mitigated: 3,
  },
  threats: [
    {
      id: "TC-001",
      title: "Cross-Tenant HVAC Command Injection",
      stride: "Elevation of Privilege",
      severity: "Critical",
      status: "Identified",
      threatStatement: {
        actor: "An authenticated tenant user",
        action:
          "can modify the building_id parameter in HVAC setpoint API calls",
        asset: "to access another tenant's HVAC control plane",
        impact:
          "leading to unauthorized temperature manipulation in critical facilities (e.g., data center cooling).",
      },
      trustBoundary: "API Gateway to HVAC Controller API",
      assumptions: [
        "Tenant isolation is enforced only at the UI layer, not the API layer.",
        "Building IDs are sequential integers, making enumeration trivial.",
      ],
      mitigations: [
        {
          id: "MIT-001",
          description:
            "Implement tenant-scoped RBAC middleware with JWT claims validation",
          status: "Proposed",
          codeSnippet: {
            file: "api/hvac/controls.py",
            line: 156,
            original: `@app.route('/api/hvac/setpoint', methods=['POST'])
def set_temperature():
    building_id = request.json['building_id']
    zone_id = request.json['zone_id']
    temp = request.json['temperature']
    hvac = get_hvac_controller(building_id, zone_id)
    hvac.set_setpoint(temp)
    return jsonify({"status": "success"})`,
            fixed: `@app.route('/api/hvac/setpoint', methods=['POST'])
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
          jiraTicket: {
            key: "SEC-4201",
            summary: "Implement tenant RBAC for HVAC setpoint API",
            status: "To Do",
          },
        },
      ],
      relatedCVE: "CVE-2024-1004",
    },
    {
      id: "TC-002",
      title: "MQTT Broker Man-in-the-Middle on BACnet Edge",
      stride: "Tampering",
      severity: "Critical",
      status: "In Progress",
      threatStatement: {
        actor: "A network-adjacent attacker on the building LAN",
        action:
          "can intercept and modify MQTT messages between the cloud broker and BACnet/IP gateway",
        asset: "to inject malicious control commands to chiller units",
        impact:
          "leading to physical equipment damage or unsafe environmental conditions.",
      },
      trustBoundary: "MQTT Broker to BACnet/IP Gateway (Cloud to Edge)",
      assumptions: [
        "Edge devices may not validate message integrity due to firmware constraints.",
        "Building LANs are often flat networks without micro-segmentation.",
      ],
      mitigations: [
        {
          id: "MIT-002",
          description:
            "Upgrade MQTT to TLS 1.3 with mutual authentication and message signing",
          status: "Implemented",
          codeSnippet: {
            file: "iot/controllers/chiller.c",
            line: 89,
            original: `void connect_mqtt_broker() {
    mqtt_client *client = mqtt_new();
    client->host = BROKER_HOST;
    client->port = 1883;
    client->protocol = MQTT_PLAIN;
    mqtt_connect(client);
}`,
            fixed: `void connect_mqtt_broker() {
    mqtt_client *client = mqtt_new();
    client->host = BROKER_HOST;
    client->port = 8883;
    client->protocol = MQTT_TLS_1_3;
    client->ca_cert = load_cert("/certs/ca.pem");
    client->client_cert = load_cert("/certs/device.pem");
    client->verify_hostname = true;
    mqtt_connect(client);
}`,
          },
        },
        {
          id: "MIT-003",
          description:
            "Implement HMAC-SHA256 message signing for all control commands",
          status: "Proposed",
        },
      ],
      relatedCVE: "CVE-2024-1002",
    },
    {
      id: "TC-003",
      title: "Credential Stuffing on Operator Portal",
      stride: "Spoofing",
      severity: "High",
      status: "Mitigated",
      threatStatement: {
        actor: "An external attacker with leaked credential databases",
        action:
          "can perform automated credential stuffing attacks against the building operator login portal",
        asset: "to gain access to building management accounts",
        impact:
          "leading to unauthorized building control and potential safety system overrides.",
      },
      trustBoundary: "External to API Gateway",
      assumptions: [
        "Building operators may reuse passwords across services.",
        "No rate limiting is currently enforced on login endpoints.",
      ],
      mitigations: [
        {
          id: "MIT-004",
          description:
            "Enforce MFA and rate-limiting with account lockout after 5 failed attempts",
          status: "Verified",
          jiraTicket: {
            key: "SEC-4102",
            summary: "Add MFA and login rate limiting",
            status: "Done",
          },
        },
      ],
    },
    {
      id: "TC-004",
      title: "Audit Log Deletion by Insider",
      stride: "Repudiation",
      severity: "High",
      status: "Identified",
      threatStatement: {
        actor: "A privileged system administrator",
        action:
          "can delete or modify audit log entries in the tenant database",
        asset: "to cover traces of unauthorized configuration changes",
        impact:
          "leading to inability to detect and investigate security incidents.",
      },
      trustBoundary: "Auth Service to Tenant DB",
      assumptions: [
        "Admins have direct database write access to audit tables.",
        "No immutable logging or write-once storage is in place.",
      ],
      mitigations: [
        {
          id: "MIT-005",
          description:
            "Ship audit logs to immutable S3 bucket with Object Lock and separate IAM boundary",
          status: "Proposed",
          jiraTicket: {
            key: "SEC-4305",
            summary: "Implement immutable audit logging to S3",
            status: "To Do",
          },
        },
      ],
    },
    {
      id: "TC-005",
      title: "Sensor Data Exfiltration via MQTT Topic Subscription",
      stride: "Information Disclosure",
      severity: "High",
      status: "In Progress",
      threatStatement: {
        actor: "An authenticated user with limited MQTT topic permissions",
        action:
          "can subscribe to wildcard MQTT topics (e.g., buildings/#)",
        asset: "to access sensor telemetry data from all buildings",
        impact:
          "leading to disclosure of occupancy patterns, energy usage, and facility layouts.",
      },
      trustBoundary: "MQTT Broker internal topic ACLs",
      assumptions: [
        "MQTT broker ACLs are configured per-building but wildcard subscriptions bypass them.",
      ],
      mitigations: [
        {
          id: "MIT-006",
          description:
            "Enforce per-tenant MQTT topic ACLs with wildcard subscription blocking",
          status: "Implemented",
        },
      ],
    },
    {
      id: "TC-006",
      title: "BACnet/IP Gateway Firmware Downgrade",
      stride: "Tampering",
      severity: "Medium",
      status: "Identified",
      threatStatement: {
        actor: "An attacker with physical access to the building network closet",
        action:
          "can flash an older, vulnerable firmware to the BACnet/IP gateway",
        asset: "to reintroduce patched vulnerabilities in the edge device",
        impact:
          "leading to full compromise of the building control system edge layer.",
      },
      trustBoundary: "Physical access to BACnet/IP Gateway",
      assumptions: [
        "Gateway hardware does not enforce secure boot or firmware signature verification.",
      ],
      mitigations: [
        {
          id: "MIT-007",
          description:
            "Enable Secure Boot with signed firmware images and anti-rollback counters",
          status: "Proposed",
        },
      ],
    },
    {
      id: "TC-007",
      title: "API Gateway DDoS via Recursive Scheduling Calls",
      stride: "Denial of Service",
      severity: "Medium",
      status: "Mitigated",
      threatStatement: {
        actor: "An authenticated operator",
        action:
          "can create recursive HVAC scheduling rules that overwhelm the API gateway",
        asset: "causing the scheduling service to consume all available compute",
        impact:
          "leading to denial of service for all building operators on the platform.",
      },
      trustBoundary: "API Gateway to HVAC Controller API",
      assumptions: [
        "No request depth limit exists for scheduling rule definitions.",
      ],
      mitigations: [
        {
          id: "MIT-008",
          description:
            "Add request complexity analysis and depth limiting to scheduling API",
          status: "Verified",
          jiraTicket: {
            key: "SEC-4088",
            summary: "Rate limit recursive scheduling API calls",
            status: "Done",
          },
        },
      ],
    },
    {
      id: "TC-008",
      title: "Hardcoded Cloud Gateway API Credentials",
      stride: "Information Disclosure",
      severity: "Low",
      status: "Mitigated",
      threatStatement: {
        actor: "A developer with repository access",
        action:
          "can extract hardcoded API keys committed to the cloud gateway configuration",
        asset: "to authenticate as the gateway service account",
        impact:
          "leading to unauthorized API access and potential data exfiltration.",
      },
      trustBoundary: "Source Code Repository to Cloud Environment",
      assumptions: [
        "Secret scanning may not catch custom credential formats.",
      ],
      mitigations: [
        {
          id: "MIT-009",
          description:
            "Migrate all secrets to HashiCorp Vault with dynamic credential rotation",
          status: "Verified",
          codeSnippet: {
            file: "cloud/gateway/config.js",
            line: 23,
            original: `const config = {
    apiEndpoint: "https://api.metasys.jci.com",
    apiKey: "sk_live_JCI_2024_BUILDING_MGMT_KEY",
    apiSecret: "super_secret_123!@#",
};`,
            fixed: `const vault = require('@hashicorp/vault-client');

const config = {
    apiEndpoint: process.env.METASYS_API_ENDPOINT,
    apiKey: await vault.getSecret('metasys/api-key'),
    apiSecret: await vault.getSecret('metasys/api-secret'),
};`,
          },
          jiraTicket: {
            key: "SEC-3990",
            summary: "Migrate hardcoded credentials to Vault",
            status: "Done",
          },
        },
      ],
    },
  ],
}
