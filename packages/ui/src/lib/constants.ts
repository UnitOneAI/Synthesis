import { Severity } from "../types"

export const STRIDE_COLORS: Record<string, string> = {
  spoofing: "bg-violet-500/10 text-violet-700 border-violet-200",
  tampering: "bg-red-500/10 text-red-600 border-red-200",
  repudiation: "bg-amber-500/10 text-amber-700 border-amber-200",
  information_disclosure: "bg-blue-500/10 text-blue-600 border-blue-200",
  "information-disclosure": "bg-blue-500/10 text-blue-600 border-blue-200",
  denial_of_service: "bg-orange-500/10 text-orange-600 border-orange-200",
  "denial-of-service": "bg-orange-500/10 text-orange-600 border-orange-200",
  elevation_of_privilege: "bg-rose-500/10 text-rose-700 border-rose-200",
  "elevation-of-privilege": "bg-rose-500/10 text-rose-700 border-rose-200",
}

export const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "bg-red-500/10 text-red-600 border-red-200",
  high: "bg-orange-500/10 text-orange-600 border-orange-200",
  medium: "bg-yellow-500/10 text-yellow-700 border-yellow-200",
  low: "bg-green-500/10 text-green-600 border-green-200",
  info: "bg-blue-500/10 text-blue-600 border-blue-200",
}

export const STRIDE_CATEGORIES = [
  "spoofing",
  "tampering",
  "repudiation",
  "information_disclosure",
  "denial_of_service",
  "elevation_of_privilege",
]

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"]

export function normalizeStride(stride: string): string {
  return stride.toLowerCase().replace(/\s+/g, "_")
}

export function getStrideColor(stride: string): string {
  return STRIDE_COLORS[normalizeStride(stride)] || "bg-muted text-muted-foreground"
}

export function getStrideLabel(stride: string): string {
  const labels: Record<string, string> = {
    spoofing: "Spoofing",
    tampering: "Tampering",
    repudiation: "Repudiation",
    information_disclosure: "Information Disclosure",
    "information-disclosure": "Information Disclosure",
    denial_of_service: "Denial of Service",
    "denial-of-service": "Denial of Service",
    elevation_of_privilege: "Elevation of Privilege",
    "elevation-of-privilege": "Elevation of Privilege",
  }
  return labels[normalizeStride(stride)] || stride
}

export function cleanTitle(title: string): string {
  return title.replace(/^\[[\w\s]+\]\s*/, "")
}
