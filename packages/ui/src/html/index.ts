/**
 * HTML rendering module for Synthesis UI.
 *
 * Provides standalone HTML generation for threat model visualization
 * that can be used in VSCode webviews, standalone pages, or any HTML context.
 */

export {
  generateThreatPanelHTML,
  getThreatPanelStyles,
  getThreatPanelScript,
  buildThreatSummary,
  generateNonce,
  type ThreatPanelOptions,
  type ThreatSummary,
} from "./threat-panel-html";
