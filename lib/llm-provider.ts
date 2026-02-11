import Anthropic from "@anthropic-ai/sdk";
import { GoogleGenAI } from "@google/genai";

export type LLMProvider = "anthropic" | "gemini";

export interface LLMConfig {
  provider: LLMProvider;
  apiKey: string;
  model?: string;
  geminiEndpoint?: string;
}

/**
 * Resolve LLM configuration from environment variables or DB settings.
 * Returns null if no API keys are configured (triggers demo mode in callers).
 */
export async function getLLMConfig(): Promise<LLMConfig | null> {
  // Check which provider is configured
  let dbProvider: string | null = null;
  let dbAnthropicKey: string | null = null;
  let dbGeminiKey: string | null = null;
  let dbGeminiModel: string | null = null;
  let dbGeminiEndpoint: string | null = null;

  try {
    const { getSettingValue } = await import("@/lib/db");
    dbProvider = getSettingValue("llm_provider");
    dbAnthropicKey = getSettingValue("anthropic_key");
    dbGeminiKey = getSettingValue("gemini_key");
    dbGeminiModel = getSettingValue("gemini_model");
    dbGeminiEndpoint = getSettingValue("gemini_endpoint");
  } catch {
    // DB not available
  }

  const provider = (dbProvider as LLMProvider) || "anthropic";

  if (provider === "gemini") {
    const apiKey = process.env.GOOGLE_GEMINI_API_KEY || dbGeminiKey;
    if (!apiKey) return null;
    return {
      provider: "gemini",
      apiKey,
      model: dbGeminiModel || "gemini-2.5-flash",
      geminiEndpoint: dbGeminiEndpoint || undefined,
    };
  }

  // Default: Anthropic
  const apiKey = process.env.ANTHROPIC_API_KEY || dbAnthropicKey;
  if (!apiKey) return null;
  return {
    provider: "anthropic",
    apiKey,
  };
}

/**
 * Call an LLM with a system prompt and user prompt.
 * Supports both Anthropic Claude and Google Gemini.
 */
export async function callLLM(
  systemPrompt: string,
  userPrompt: string,
  config: LLMConfig,
  maxTokens: number = 4096
): Promise<string> {
  if (config.provider === "gemini") {
    return callGemini(systemPrompt, userPrompt, config, maxTokens);
  }
  return callAnthropic(systemPrompt, userPrompt, config, maxTokens);
}

async function callAnthropic(
  systemPrompt: string,
  userPrompt: string,
  config: LLMConfig,
  maxTokens: number
): Promise<string> {
  const client = new Anthropic({ apiKey: config.apiKey });

  const message = await client.messages.create({
    model: "claude-sonnet-4-5-20250929",
    max_tokens: maxTokens,
    system: systemPrompt,
    messages: [{ role: "user", content: userPrompt }],
  });

  const textBlock = message.content.find((b) => b.type === "text");
  if (!textBlock || textBlock.type !== "text") {
    throw new Error("No text response from Anthropic");
  }

  return textBlock.text;
}

async function callGemini(
  systemPrompt: string,
  userPrompt: string,
  config: LLMConfig,
  maxTokens: number
): Promise<string> {
  const ai = new GoogleGenAI({
    apiKey: config.apiKey,
    ...(config.geminiEndpoint
      ? { httpOptions: { baseUrl: config.geminiEndpoint } }
      : {}),
  });

  const response = await ai.models.generateContent({
    model: config.model || "gemini-2.5-flash",
    contents: userPrompt,
    config: {
      systemInstruction: systemPrompt,
      maxOutputTokens: maxTokens,
    },
  });

  const text = response.text;
  if (!text) {
    throw new Error("No text response from Gemini");
  }

  return text;
}
