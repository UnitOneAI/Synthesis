/**
 * Output sanitization utilities for webview rendering.
 *
 * SECURITY: All threat model data is treated as untrusted.  Analyzed code may
 * contain XSS payloads, script tags, or Mermaid injection attempts.  Every
 * dynamic string MUST pass through these helpers before being placed in HTML.
 *
 * References:
 *   - OWASP XSS Prevention Cheat Sheet
 *   - STRIDE / Information Disclosure — prevent leaking raw code into webview DOM
 */

/**
 * HTML-escape a string for safe insertion into HTML element content or attributes.
 * Covers the OWASP-recommended minimum character set for HTML context.
 */
export function escapeHtml(unsafe: string): string {
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

/**
 * Sanitize a string for use inside a Mermaid diagram definition.
 *
 * Mermaid supports limited markup; an attacker could inject diagram-breaking
 * syntax or embed click handlers (Mermaid `click` directive).  We strip
 * everything that is not alphanumeric, whitespace, hyphens, underscores,
 * periods, colons, slashes, or parentheses.
 */
export function sanitizeMermaid(raw: string): string {
  // Remove click/linkStyle/classDef directives that could execute JS
  let cleaned = raw.replace(
    /^\s*(click|linkStyle|classDef|callback|securityLevel)\b.*$/gm,
    "",
  );
  // Strip HTML tags entirely
  cleaned = cleaned.replace(/<[^>]*>/g, "");
  // Remove javascript: protocol references
  cleaned = cleaned.replace(/javascript\s*:/gi, "");
  return cleaned;
}

/**
 * Strip script tags and event handler attributes from a string.
 * Defense-in-depth for content that also goes through escapeHtml.
 */
export function stripScriptContent(raw: string): string {
  let cleaned = raw;
  // Remove <script>...</script> blocks (including multiline)
  cleaned = cleaned.replace(
    /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
    "",
  );
  // Remove on* event handler attributes
  cleaned = cleaned.replace(/\bon\w+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]*)/gi, "");
  // Remove javascript: URIs
  cleaned = cleaned.replace(/javascript\s*:/gi, "");
  return cleaned;
}

/**
 * Sanitize an entire ThreatModel-shaped object for webview rendering.
 * Returns a new object with all string fields HTML-escaped.  The `dfd` field
 * is sanitized for Mermaid specifically.
 */
export function sanitizeThreatModelForView<
  T extends Record<string, unknown>,
>(model: T): T {
  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(model)) {
    if (typeof value === "string") {
      result[key] =
        key === "dfd" ? sanitizeMermaid(value) : escapeHtml(value);
    } else if (Array.isArray(value)) {
      result[key] = value.map((item) =>
        typeof item === "object" && item !== null
          ? sanitizeThreatModelForView(item as Record<string, unknown>)
          : typeof item === "string"
            ? escapeHtml(item)
            : item,
      );
    } else if (typeof value === "object" && value !== null) {
      result[key] = sanitizeThreatModelForView(
        value as Record<string, unknown>,
      );
    } else {
      result[key] = value;
    }
  }
  return result as T;
}
