"use client"

import jsPDF from "jspdf"
import autoTable from "jspdf-autotable"

interface PdfMitigation {
  id: string
  description: string
  status: string
  codeSnippet?: { file: string; line: number }
  jiraTicket?: { key: string; summary: string; status: string }
}

interface PdfOwaspRisk {
  likelihoodScore: number
  impactScore: number
  riskLevel: string
  factors: {
    likelihood: Record<string, number>
    impact: Record<string, number>
  }
}

interface PdfThreat {
  id: string
  title: string
  stride: string
  severity: string
  status: string
  threatStatement: {
    actor: string
    prerequisites?: string
    action: string
    asset: string
    impact: string
  }
  trustBoundary: string
  assumptions: string[]
  mitigations: PdfMitigation[]
  relatedCVE?: string
  owaspRisk?: PdfOwaspRisk
}

interface PdfSession {
  name: string
  source: string
  sourceRef: string
  framework: string
  createdAt: string
  description: string
  dataFlowDiagram?: string
  threats: PdfThreat[]
  stats: {
    total: number
    critical: number
    high: number
    medium: number
    low: number
    mitigated: number
  }
  insights: {
    riskScore: number
    strideCoverage: { percentage: number }
    mitigationRate: { percentage: number }
    recommendations: string[]
  }
}

function owaspLevel(score: number): string {
  if (score < 3) return "Low"
  if (score < 6) return "Medium"
  return "High"
}

function ensureSpace(doc: jsPDF, y: number, needed: number): number {
  if (y + needed > doc.internal.pageSize.getHeight() - 20) {
    doc.addPage()
    return 20
  }
  return y
}

function sectionHeading(doc: jsPDF, text: string, y: number): number {
  y = ensureSpace(doc, y, 20)
  doc.setFontSize(14)
  doc.setFont("helvetica", "bold")
  doc.setTextColor(0)
  doc.text(text, 14, y)
  // Underline
  doc.setDrawColor(200)
  doc.setLineWidth(0.3)
  doc.line(14, y + 2, doc.internal.pageSize.getWidth() - 14, y + 2)
  return y + 10
}

export function generateThreatModelPDF(session: PdfSession) {
  const doc = new jsPDF()
  const pageWidth = doc.internal.pageSize.getWidth()
  let y = 20

  // ═══════════════════════════════════════
  // COVER PAGE
  // ═══════════════════════════════════════

  y = 50
  doc.setFontSize(28)
  doc.setFont("helvetica", "bold")
  doc.setTextColor(30, 30, 30)
  doc.text("Threat Model Report", pageWidth / 2, y, { align: "center" })
  y += 20

  doc.setFontSize(16)
  doc.setFont("helvetica", "normal")
  doc.setTextColor(60, 60, 60)
  doc.text(session.name, pageWidth / 2, y, { align: "center" })
  y += 12

  doc.setFontSize(11)
  doc.setTextColor(100)
  doc.text(`Framework: ${session.framework}`, pageWidth / 2, y, { align: "center" })
  y += 7
  doc.text(
    `Generated: ${new Date(session.createdAt).toLocaleDateString("en-US", {
      month: "long",
      day: "numeric",
      year: "numeric",
    })}`,
    pageWidth / 2,
    y,
    { align: "center" }
  )
  y += 7
  doc.text(`Source: ${session.source === "github-repo" ? "GitHub Repository" : "Design Document"}`, pageWidth / 2, y, { align: "center" })
  y += 12

  // Source reference
  doc.setFontSize(9)
  doc.setTextColor(80, 80, 200)
  const refText = session.sourceRef.length > 80 ? session.sourceRef.substring(0, 80) + "..." : session.sourceRef
  doc.text(refText, pageWidth / 2, y, { align: "center" })
  y += 20

  // Summary stats box
  doc.setTextColor(0)
  doc.setFontSize(10)
  doc.setFont("helvetica", "normal")
  const statsText = [
    `Total Threats: ${session.stats.total}`,
    `Critical: ${session.stats.critical}  |  High: ${session.stats.high}  |  Medium: ${session.stats.medium}  |  Low: ${session.stats.low}`,
    `Mitigated: ${session.stats.mitigated}/${session.stats.total} (${session.stats.total > 0 ? Math.round((session.stats.mitigated / session.stats.total) * 100) : 0}%)`,
    `Risk Score: ${session.insights.riskScore}/100`,
  ]
  for (const line of statsText) {
    doc.text(line, pageWidth / 2, y, { align: "center" })
    y += 6
  }

  y += 10
  doc.setFontSize(8)
  doc.setTextColor(130)
  doc.text("Unitone Synthesis — AI-Native Threat Modeling", pageWidth / 2, y, { align: "center" })

  // ═══════════════════════════════════════
  // SECTION 1: DESCRIPTION
  // ═══════════════════════════════════════

  doc.addPage()
  y = 20

  y = sectionHeading(doc, "1. Description", y)
  doc.setFontSize(10)
  doc.setFont("helvetica", "normal")
  doc.setTextColor(0)

  if (session.description) {
    const descLines = doc.splitTextToSize(session.description, pageWidth - 28)
    doc.text(descLines, 14, y)
    y += descLines.length * 5 + 4
  }

  // Source reference
  y += 4
  doc.setFont("helvetica", "bold")
  doc.text(session.source === "github-repo" ? "Repository:" : "Document:", 14, y)
  doc.setFont("helvetica", "normal")
  doc.setTextColor(60, 60, 180)
  doc.text(session.sourceRef, 50, y)
  doc.setTextColor(0)
  y += 8

  doc.setFont("helvetica", "bold")
  doc.text("Framework:", 14, y)
  doc.setFont("helvetica", "normal")
  doc.text(session.framework, 50, y)
  y += 8

  doc.setFont("helvetica", "bold")
  doc.text("Date:", 14, y)
  doc.setFont("helvetica", "normal")
  doc.text(
    new Date(session.createdAt).toLocaleDateString("en-US", {
      month: "long",
      day: "numeric",
      year: "numeric",
    }),
    50,
    y
  )
  y += 12

  // ═══════════════════════════════════════
  // SECTION 2: DATA FLOW DIAGRAM
  // ═══════════════════════════════════════

  if (session.dataFlowDiagram) {
    y = ensureSpace(doc, y, 40)
    y = sectionHeading(doc, "2. Data Flow Diagram", y)
    doc.setFontSize(9)
    doc.setFont("helvetica", "normal")
    doc.setTextColor(80)
    doc.text("(Mermaid diagram source — render with mermaid.live or similar tool)", 14, y)
    y += 8

    doc.setFontSize(7)
    doc.setFont("courier", "normal")
    doc.setTextColor(60)
    const dfdLines = doc.splitTextToSize(session.dataFlowDiagram, pageWidth - 28)
    // Limit to first ~40 lines
    const maxDfdLines = dfdLines.slice(0, 40)
    for (const line of maxDfdLines) {
      y = ensureSpace(doc, y, 6)
      doc.text(line, 14, y)
      y += 4
    }
    if (dfdLines.length > 40) {
      doc.text("... (truncated)", 14, y)
      y += 4
    }
    doc.setFont("helvetica", "normal")
    doc.setTextColor(0)
    y += 8
  }

  // ═══════════════════════════════════════
  // SECTION 3: THREAT ACTORS
  // ═══════════════════════════════════════

  y = ensureSpace(doc, y, 50)
  const actorSectionNum = session.dataFlowDiagram ? "3" : "2"
  y = sectionHeading(doc, `${actorSectionNum}. Threat Actors`, y)

  // Categorize threats by actor type
  const actorCategories: Record<string, { threats: string[]; mitigations: string[] }> = {
    "External Attacker": { threats: [], mitigations: [] },
    "Internal User": { threats: [], mitigations: [] },
    "Partner / Third Party": { threats: [], mitigations: [] },
  }

  for (const threat of session.threats) {
    const actorLower = threat.threatStatement.actor.toLowerCase()
    let category = "External Attacker"
    if (
      actorLower.includes("internal") ||
      actorLower.includes("insider") ||
      actorLower.includes("employee") ||
      actorLower.includes("developer") ||
      actorLower.includes("admin") ||
      actorLower.includes("privileged")
    ) {
      category = "Internal User"
    } else if (
      actorLower.includes("partner") ||
      actorLower.includes("vendor") ||
      actorLower.includes("third") ||
      actorLower.includes("supply chain") ||
      actorLower.includes("dependency")
    ) {
      category = "Partner / Third Party"
    }
    actorCategories[category].threats.push(threat.title)
    for (const mit of threat.mitigations) {
      actorCategories[category].mitigations.push(mit.description)
    }
  }

  const actorTableData: string[][] = []
  for (const [category, data] of Object.entries(actorCategories)) {
    if (data.threats.length === 0) continue
    actorTableData.push([
      category,
      String(data.threats.length),
      data.threats.slice(0, 3).join("; ") + (data.threats.length > 3 ? ` (+${data.threats.length - 3} more)` : ""),
      data.mitigations.length > 0
        ? data.mitigations.slice(0, 2).join("; ") + (data.mitigations.length > 2 ? " ..." : "")
        : "See individual threats",
    ])
  }

  if (actorTableData.length > 0) {
    autoTable(doc, {
      startY: y,
      head: [["Actor Type", "Count", "Threats", "Key Mitigations"]],
      body: actorTableData,
      theme: "striped",
      headStyles: { fillColor: [41, 37, 36], fontSize: 8 },
      styles: { fontSize: 7, cellPadding: 3 },
      columnStyles: {
        0: { cellWidth: 32, fontStyle: "bold" },
        1: { cellWidth: 14, halign: "center" },
        2: { cellWidth: 60 },
        3: { cellWidth: 60 },
      },
    })
    // @ts-expect-error jspdf-autotable extends doc
    y = doc.lastAutoTable.finalY + 12
  }

  // ═══════════════════════════════════════
  // SECTION 4: THREAT TABLE
  // ═══════════════════════════════════════

  y = ensureSpace(doc, y, 40)
  const threatSectionNum = session.dataFlowDiagram ? "4" : "3"
  y = sectionHeading(doc, `${threatSectionNum}. Threat Analysis`, y)

  const threatTableData = session.threats.map((t) => {
    const mitText = t.mitigations.map((m) => m.description).join("; ")
    const mitTruncated = mitText.length > 80 ? mitText.substring(0, 80) + "..." : mitText

    const likelihoodStr = t.owaspRisk ? `${t.owaspRisk.likelihoodScore.toFixed(1)} (${owaspLevel(t.owaspRisk.likelihoodScore)})` : "-"
    const impactStr = t.owaspRisk ? `${t.owaspRisk.impactScore.toFixed(1)} (${owaspLevel(t.owaspRisk.impactScore)})` : "-"

    const jiraKeys = t.mitigations
      .filter((m) => m.jiraTicket)
      .map((m) => m.jiraTicket!.key)
    const jiraStr = jiraKeys.length > 0 ? jiraKeys.join(", ") : "-"

    return [
      t.stride,
      t.title.length > 35 ? t.title.substring(0, 35) + "..." : t.title,
      mitTruncated,
      likelihoodStr,
      impactStr,
      jiraStr,
      t.status,
    ]
  })

  autoTable(doc, {
    startY: y,
    head: [["STRIDE", "Description", "Mitigation", "Likelihood", "Impact", "Jira", "Status"]],
    body: threatTableData,
    theme: "striped",
    headStyles: { fillColor: [41, 37, 36], fontSize: 7 },
    styles: { fontSize: 6.5, cellPadding: 2 },
    columnStyles: {
      0: { cellWidth: 22 },
      1: { cellWidth: 38 },
      2: { cellWidth: 50 },
      3: { cellWidth: 20, halign: "center" },
      4: { cellWidth: 20, halign: "center" },
      5: { cellWidth: 18, halign: "center" },
      6: { cellWidth: 18, halign: "center" },
    },
    didParseCell: (data) => {
      // Color-code severity/status cells
      if (data.section === "body" && data.column.index === 6) {
        const val = String(data.cell.raw)
        if (val === "Mitigated") data.cell.styles.textColor = [22, 163, 74]
        else if (val === "Accepted") data.cell.styles.textColor = [59, 130, 246]
        else if (val === "Identified") data.cell.styles.textColor = [234, 88, 12]
      }
    },
  })

  // @ts-expect-error jspdf-autotable extends doc
  y = doc.lastAutoTable.finalY + 12

  // ═══════════════════════════════════════
  // SECTION 5: DETAILED THREAT BREAKDOWN
  // ═══════════════════════════════════════

  y = ensureSpace(doc, y, 30)
  const detailSectionNum = session.dataFlowDiagram ? "5" : "4"
  y = sectionHeading(doc, `${detailSectionNum}. Detailed Threat Breakdown`, y)

  for (const threat of session.threats) {
    y = ensureSpace(doc, y, 40)

    // Threat header
    doc.setFontSize(10)
    doc.setFont("helvetica", "bold")
    doc.setTextColor(0)
    doc.text(`${threat.id}: ${threat.title}`, 14, y)
    y += 5

    doc.setFontSize(8)
    doc.setFont("helvetica", "normal")

    // Metadata line
    let metaLine = `STRIDE: ${threat.stride}  |  Severity: ${threat.severity}  |  Status: ${threat.status}`
    if (threat.owaspRisk) {
      metaLine += `  |  Risk: ${threat.owaspRisk.riskLevel} (L:${threat.owaspRisk.likelihoodScore.toFixed(1)} × I:${threat.owaspRisk.impactScore.toFixed(1)})`
    }
    doc.setTextColor(80)
    doc.text(metaLine, 14, y)
    y += 5

    // Trust boundary
    doc.text(`Trust Boundary: ${threat.trustBoundary}`, 14, y)
    y += 5

    // Threat statement
    doc.setTextColor(0)
    const statement = `A ${threat.threatStatement.actor} ${threat.threatStatement.prerequisites ? `with ${threat.threatStatement.prerequisites} ` : ""}can ${threat.threatStatement.action}, leading to ${threat.threatStatement.impact}.`
    const stmtLines = doc.splitTextToSize(statement, pageWidth - 28)
    doc.text(stmtLines, 14, y)
    y += stmtLines.length * 4 + 3

    // Mitigations
    if (threat.mitigations.length > 0) {
      doc.setFont("helvetica", "bold")
      doc.text("Mitigations:", 14, y)
      y += 4
      doc.setFont("helvetica", "normal")

      for (const mit of threat.mitigations) {
        y = ensureSpace(doc, y, 10)
        const mitLines = doc.splitTextToSize(`• ${mit.description}`, pageWidth - 32)
        doc.text(mitLines, 18, y)
        y += mitLines.length * 4

        if (mit.codeSnippet) {
          doc.setTextColor(100)
          doc.text(`  File: ${mit.codeSnippet.file}:${mit.codeSnippet.line}`, 20, y)
          doc.setTextColor(0)
          y += 4
        }

        if (mit.jiraTicket) {
          doc.setTextColor(60, 60, 180)
          doc.text(`  Jira: ${mit.jiraTicket.key} — ${mit.jiraTicket.summary} [${mit.jiraTicket.status}]`, 20, y)
          doc.setTextColor(0)
          y += 4
        }
      }
    }

    // OWASP factor summary (compact)
    if (threat.owaspRisk) {
      y = ensureSpace(doc, y, 8)
      doc.setTextColor(80)
      doc.setFontSize(7)
      const likelihoodFactors = threat.owaspRisk.factors.likelihood
      const impactFactors = threat.owaspRisk.factors.impact
      doc.text(
        `OWASP Factors — Likelihood [${Object.values(likelihoodFactors).join(",")}] avg=${threat.owaspRisk.likelihoodScore.toFixed(1)}  |  Impact [${Object.values(impactFactors).join(",")}] avg=${threat.owaspRisk.impactScore.toFixed(1)}`,
        14,
        y
      )
      doc.setFontSize(8)
      doc.setTextColor(0)
      y += 5
    }

    // Related CVE
    if (threat.relatedCVE) {
      doc.text(`Related CVE: ${threat.relatedCVE}`, 14, y)
      y += 5
    }

    y += 6
  }

  // ═══════════════════════════════════════
  // SECTION: RECOMMENDATIONS
  // ═══════════════════════════════════════

  if (session.insights.recommendations.length > 0) {
    y = ensureSpace(doc, y, 30)
    const recSectionNum = session.dataFlowDiagram ? "6" : "5"
    y = sectionHeading(doc, `${recSectionNum}. Recommendations`, y)

    doc.setFontSize(9)
    doc.setFont("helvetica", "normal")
    doc.setTextColor(0)

    for (const rec of session.insights.recommendations) {
      y = ensureSpace(doc, y, 10)
      const recLines = doc.splitTextToSize(`• ${rec}`, pageWidth - 28)
      doc.text(recLines, 14, y)
      y += recLines.length * 4.5 + 2
    }
  }

  // ═══════════════════════════════════════
  // FOOTER ON ALL PAGES
  // ═══════════════════════════════════════

  const pageCount = doc.getNumberOfPages()
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i)
    doc.setFontSize(7)
    doc.setTextColor(150)
    doc.text(
      `Unitone Synthesis — ${session.name} — Page ${i} of ${pageCount}`,
      pageWidth / 2,
      doc.internal.pageSize.getHeight() - 8,
      { align: "center" }
    )
  }

  // Save
  const fileName = `threat-model-${session.name.replace(/[^a-zA-Z0-9]/g, "-").toLowerCase()}.pdf`
  doc.save(fileName)
}
