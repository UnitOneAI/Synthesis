/**
 * @synthesis/core — LLM provider abstraction
 *
 * Provides a unified interface for interacting with Anthropic Claude
 * and Google Gemini. Implements rate limiting, input sanitization,
 * and API key validation.
 *
 * SECURITY:
 * - API keys are validated as non-empty but never logged or included in errors.
 * - User content is sanitized before being sent to LLMs to mitigate prompt injection.
 * - Concurrent request limiting prevents upstream API abuse / cost runaway.
 */

import Anthropic from "@anthropic-ai/sdk";
import { GoogleGenerativeAI } from "@google/generative-ai";
import { SynthesisConfigSchema, type SynthesisConfig } from "./types.js";

// ---------------------------------------------------------------------------
// Interface
// ---------------------------------------------------------------------------

export interface LLMProviderInterface {
  /**
   * Send a prompt to the LLM and return the text response.
   * @param prompt - The user/analysis prompt.
   * @param systemPrompt - The system prompt establishing role and constraints.
   */
  analyze(prompt: string, systemPrompt: string): Promise<string>;
}

// ---------------------------------------------------------------------------
// Input sanitization
// ---------------------------------------------------------------------------

/**
 * Strip patterns commonly used in prompt injection attacks from
 * user-supplied content before sending it to the LLM.
 *
 * This is a defense-in-depth measure — the system prompt also
 * contains instruction-hierarchy boundaries. We strip the most
 * dangerous patterns (role reassignment, instruction override)
 * while preserving the analytical content.
 */
export function sanitizeInput(input: string): string {
  // Remove attempts to break out of data boundaries
  let sanitized = input.replace(/<<<[A-Z_]+>>>/g, "[BOUNDARY_STRIPPED]");

  // Remove common prompt injection patterns (case-insensitive)
  const injectionPatterns = [
    /ignore\s+(all\s+)?previous\s+instructions/gi,
    /you\s+are\s+now\s+a/gi,
    /new\s+system\s+prompt/gi,
    /override\s+(system|instructions)/gi,
    /\bsystem\s*:\s*you\s+are/gi,
    /\bassistant\s*:\s*/gi,
    /\bhuman\s*:\s*/gi,
    /\[INST\]/gi,
    /<\|im_start\|>/gi,
    /<\|im_end\|>/gi,
  ];

  for (const pattern of injectionPatterns) {
    sanitized = sanitized.replace(pattern, "[INJECTION_PATTERN_STRIPPED]");
  }

  return sanitized;
}

// ---------------------------------------------------------------------------
// Rate limiter
// ---------------------------------------------------------------------------

class RateLimiter {
  private active = 0;
  private readonly queue: Array<() => void> = [];

  constructor(private readonly maxConcurrent: number) {}

  async acquire(): Promise<void> {
    if (this.active < this.maxConcurrent) {
      this.active++;
      return;
    }
    return new Promise<void>((resolve) => {
      this.queue.push(() => {
        this.active++;
        resolve();
      });
    });
  }

  release(): void {
    this.active--;
    const next = this.queue.shift();
    if (next) {
      next();
    }
  }
}

// ---------------------------------------------------------------------------
// Anthropic provider
// ---------------------------------------------------------------------------

export class AnthropicProvider implements LLMProviderInterface {
  private readonly client: Anthropic;
  private readonly rateLimiter: RateLimiter;

  constructor(apiKey: string, maxConcurrent = 5) {
    if (!apiKey || typeof apiKey !== "string" || apiKey.trim().length === 0) {
      throw new Error("Anthropic API key is required and must be a non-empty string");
    }
    this.client = new Anthropic({ apiKey });
    this.rateLimiter = new RateLimiter(maxConcurrent);
  }

  async analyze(prompt: string, systemPrompt: string): Promise<string> {
    const sanitizedPrompt = sanitizeInput(prompt);

    await this.rateLimiter.acquire();
    try {
      const response = await this.client.messages.create({
        model: "claude-sonnet-4-5-20250514",
        max_tokens: 8192,
        system: systemPrompt,
        messages: [{ role: "user", content: sanitizedPrompt }],
      });

      const textBlock = response.content.find((block) => block.type === "text");
      if (!textBlock || textBlock.type !== "text") {
        throw new Error("LLM response contained no text content");
      }
      return textBlock.text;
    } finally {
      this.rateLimiter.release();
    }
  }
}

// ---------------------------------------------------------------------------
// Gemini provider
// ---------------------------------------------------------------------------

export class GeminiProvider implements LLMProviderInterface {
  private readonly client: GoogleGenerativeAI;
  private readonly rateLimiter: RateLimiter;

  constructor(apiKey: string, maxConcurrent = 5) {
    if (!apiKey || typeof apiKey !== "string" || apiKey.trim().length === 0) {
      throw new Error("Gemini API key is required and must be a non-empty string");
    }
    this.client = new GoogleGenerativeAI(apiKey);
    this.rateLimiter = new RateLimiter(maxConcurrent);
  }

  async analyze(prompt: string, systemPrompt: string): Promise<string> {
    const sanitizedPrompt = sanitizeInput(prompt);

    await this.rateLimiter.acquire();
    try {
      const model = this.client.getGenerativeModel({
        model: "gemini-2.5-flash",
        systemInstruction: systemPrompt,
      });

      const result = await model.generateContent(sanitizedPrompt);
      const response = result.response;
      const text = response.text();

      if (!text) {
        throw new Error("LLM response contained no text content");
      }
      return text;
    } finally {
      this.rateLimiter.release();
    }
  }
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create an LLM provider instance from a validated config.
 *
 * SECURITY: The config is validated via Zod before use. The API key
 * is passed directly to the provider constructor and never logged.
 */
export function createProvider(config: SynthesisConfig): LLMProviderInterface {
  // Re-validate at the boundary (defense-in-depth)
  const validated = SynthesisConfigSchema.parse(config);

  switch (validated.provider) {
    case "anthropic":
      return new AnthropicProvider(validated.apiKey, validated.maxConcurrentRequests);
    case "gemini":
      return new GeminiProvider(validated.apiKey, validated.maxConcurrentRequests);
    default: {
      // Exhaustiveness check
      const _exhaustive: never = validated.provider;
      throw new Error(`Unknown provider: ${String(_exhaustive)}`);
    }
  }
}
