"use client"

import jsPDF from "jspdf"
import autoTable from "jspdf-autotable"

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
  mitigations: {
    description: string
    codeSnippet?: { file: string; line: number }
  }[]
  relatedCVE?: string
}

interface PdfSession {
  name: string
  framework: string
  createdAt: string
  description: string
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

export function generateThreatModelPDF(session: PdfSession) {
  const doc = new jsPDF()
  const pageWidth = doc.internal.pageSize.getWidth()
  let y = 20

  // Cover page
  doc.setFontSize(24)
  doc.setFont("helvetica", "bold")
  doc.text("Threat Model Report", pageWidth / 2, y, { align: "center" })
  y += 15

  doc.setFontSize(16)
  doc.setFont("helvetica", "normal")
  doc.text(session.name, pageWidth / 2, y, { align: "center" })
  y += 10

  doc.setFontSize(10)
  doc.setTextColor(100)
  doc.text(`Framework: ${session.framework}`, pageWidth / 2, y, { align: "center" })
  y += 6
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
  y += 6
  doc.text("Unitone Sentinel", pageWidth / 2, y, { align: "center" })
  doc.setTextColor(0)

  // Executive summary
  y += 20
  doc.setFontSize(14)
  doc.setFont("helvetica", "bold")
  doc.text("Executive Summary", 14, y)
  y += 8

  doc.setFontSize(10)
  doc.setFont("helvetica", "normal")

  const summaryLines = [
    `Risk Score: ${session.insights.riskScore}/100`,
    `Total Threats: ${session.stats.total} (Critical: ${session.stats.critical}, High: ${session.stats.high}, Medium: ${session.stats.medium}, Low: ${session.stats.low})`,
    `Mitigated: ${session.stats.mitigated}/${session.stats.total} (${session.stats.total > 0 ? Math.round((session.stats.mitigated / session.stats.total) * 100) : 0}%)`,
    `STRIDE Coverage: ${session.insights.strideCoverage.percentage}%`,
    `Mitigation Rate: ${session.insights.mitigationRate.percentage}%`,
  ]

  for (const line of summaryLines) {
    doc.text(line, 14, y)
    y += 6
  }

  // Threat table
  y += 10
  doc.setFontSize(14)
  doc.setFont("helvetica", "bold")
  doc.text("Threat Summary Table", 14, y)
  y += 4

  const tableData = session.threats.map((t, i) => [
    String(i + 1),
    t.title.length > 40 ? t.title.substring(0, 40) + "..." : t.title,
    t.stride,
    t.severity,
    t.status,
  ])

  autoTable(doc, {
    startY: y,
    head: [["#", "Title", "STRIDE", "Severity", "Status"]],
    body: tableData,
    theme: "striped",
    headStyles: { fillColor: [41, 37, 36] },
    styles: { fontSize: 8, cellPadding: 3 },
    columnStyles: {
      0: { cellWidth: 10 },
      1: { cellWidth: 70 },
      2: { cellWidth: 35 },
      3: { cellWidth: 25 },
      4: { cellWidth: 25 },
    },
  })

  // Per-threat details
  // @ts-expect-error jspdf-autotable extends doc
  y = doc.lastAutoTable.finalY + 15

  for (const threat of session.threats) {
    // Check if we need a new page
    if (y > 250) {
      doc.addPage()
      y = 20
    }

    doc.setFontSize(12)
    doc.setFont("helvetica", "bold")
    doc.text(`${threat.id}: ${threat.title}`, 14, y)
    y += 6

    doc.setFontSize(9)
    doc.setFont("helvetica", "normal")

    const details = [
      `Severity: ${threat.severity} | STRIDE: ${threat.stride} | Status: ${threat.status}`,
      `Trust Boundary: ${threat.trustBoundary}`,
      "",
      `Threat Statement: ${threat.threatStatement.actor} ${threat.threatStatement.prerequisites ? `with ${threat.threatStatement.prerequisites} ` : ""}${threat.threatStatement.action} ${threat.threatStatement.asset}, ${threat.threatStatement.impact}`,
    ]

    for (const line of details) {
      if (line === "") {
        y += 3
        continue
      }
      const splitLines = doc.splitTextToSize(line, pageWidth - 28)
      doc.text(splitLines, 14, y)
      y += splitLines.length * 4.5
    }

    // Mitigations
    if (threat.mitigations.length > 0) {
      y += 3
      doc.setFont("helvetica", "bold")
      doc.text("Mitigations:", 14, y)
      y += 5
      doc.setFont("helvetica", "normal")

      for (const mit of threat.mitigations) {
        const mitLines = doc.splitTextToSize(`- ${mit.description}`, pageWidth - 32)
        doc.text(mitLines, 18, y)
        y += mitLines.length * 4.5
        if (mit.codeSnippet) {
          doc.text(`  File: ${mit.codeSnippet.file}:${mit.codeSnippet.line}`, 18, y)
          y += 4.5
        }
      }
    }

    // Related CVE
    if (threat.relatedCVE) {
      doc.text(`Related CVE: ${threat.relatedCVE}`, 14, y)
      y += 5
    }

    y += 8
  }

  // Recommendations
  if (session.insights.recommendations.length > 0) {
    if (y > 240) {
      doc.addPage()
      y = 20
    }

    doc.setFontSize(14)
    doc.setFont("helvetica", "bold")
    doc.text("Recommendations", 14, y)
    y += 8

    doc.setFontSize(9)
    doc.setFont("helvetica", "normal")

    for (const rec of session.insights.recommendations) {
      const recLines = doc.splitTextToSize(`- ${rec}`, pageWidth - 28)
      doc.text(recLines, 14, y)
      y += recLines.length * 4.5 + 2
    }
  }

  // Save
  const fileName = `threat-model-${session.name.replace(/[^a-zA-Z0-9]/g, "-").toLowerCase()}.pdf`
  doc.save(fileName)
}
