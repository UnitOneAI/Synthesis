/**
 * Secure API key management using VS Code SecretStorage API.
 *
 * SECURITY: API keys are NEVER stored in settings.json or workspace config.
 * On first activation, if legacy keys are found in settings, they are migrated
 * to SecretStorage and the settings entries are cleared.
 *
 * References:
 *   - OWASP Secrets Management Cheat Sheet
 *   - NIST SP 800-57 Part 1 Rev 5 (key storage)
 */

import * as vscode from "vscode";

const ANTHROPIC_KEY = "synthesis.anthropicApiKey";
const GEMINI_KEY = "synthesis.geminiApiKey";

export class SecretStorageManager {
  constructor(private readonly secrets: vscode.SecretStorage) {}

  // ── Retrieval ──────────────────────────────────────────────

  async getAnthropicKey(): Promise<string | undefined> {
    return this.secrets.get(ANTHROPIC_KEY);
  }

  async getGeminiKey(): Promise<string | undefined> {
    return this.secrets.get(GEMINI_KEY);
  }

  async getKeyForProvider(
    provider: "anthropic" | "gemini",
  ): Promise<string | undefined> {
    return provider === "anthropic"
      ? this.getAnthropicKey()
      : this.getGeminiKey();
  }

  // ── Storage ────────────────────────────────────────────────

  async setAnthropicKey(key: string): Promise<void> {
    await this.secrets.store(ANTHROPIC_KEY, key);
  }

  async setGeminiKey(key: string): Promise<void> {
    await this.secrets.store(GEMINI_KEY, key);
  }

  async deleteAnthropicKey(): Promise<void> {
    await this.secrets.delete(ANTHROPIC_KEY);
  }

  async deleteGeminiKey(): Promise<void> {
    await this.secrets.delete(GEMINI_KEY);
  }

  // ── Interactive prompt ─────────────────────────────────────

  /**
   * Prompt the user to enter an API key via a password-masked input box.
   * Returns true if a key was stored, false if the user cancelled.
   */
  async promptForKey(provider: "anthropic" | "gemini"): Promise<boolean> {
    const label =
      provider === "anthropic" ? "Anthropic API Key" : "Gemini API Key";

    const key = await vscode.window.showInputBox({
      title: `Synthesis — Enter ${label}`,
      prompt: `Your key is stored securely in VS Code SecretStorage and never written to settings.json.`,
      password: true,
      placeHolder: provider === "anthropic" ? "sk-ant-..." : "AIza...",
      ignoreFocusOut: true,
      validateInput: (value: string) => {
        if (!value || value.trim().length < 10) {
          return "API key appears too short. Please enter a valid key.";
        }
        return undefined;
      },
    });

    if (key === undefined) {
      return false; // user cancelled
    }

    if (provider === "anthropic") {
      await this.setAnthropicKey(key.trim());
    } else {
      await this.setGeminiKey(key.trim());
    }

    vscode.window.showInformationMessage(
      `Synthesis: ${label} stored securely.`,
    );
    return true;
  }

  // ── Migration from legacy settings ─────────────────────────

  /**
   * If API keys exist in settings.json (legacy), migrate them to SecretStorage
   * and remove from settings.  This runs once at activation.
   *
   * SECURITY: We clear the plaintext setting immediately after migration.
   */
  async migrateLegacyKeys(): Promise<void> {
    const config = vscode.workspace.getConfiguration("synthesis");

    for (const settingKey of [
      "anthropicApiKey",
      "geminiApiKey",
    ] as const) {
      const legacyValue = config.get<string>(settingKey);
      if (legacyValue && legacyValue.trim().length > 0) {
        // Store in SecretStorage
        const secretKey =
          settingKey === "anthropicApiKey" ? ANTHROPIC_KEY : GEMINI_KEY;
        await this.secrets.store(secretKey, legacyValue.trim());

        // Clear from settings.json — try global first, then workspace
        try {
          await config.update(
            settingKey,
            undefined,
            vscode.ConfigurationTarget.Global,
          );
        } catch {
          // Setting may not exist at global level — that is fine.
        }
        try {
          await config.update(
            settingKey,
            undefined,
            vscode.ConfigurationTarget.Workspace,
          );
        } catch {
          // Setting may not exist at workspace level — that is fine.
        }

        vscode.window.showWarningMessage(
          `Synthesis: Migrated ${settingKey} from settings.json to SecretStorage. ` +
            `The plaintext entry has been removed.`,
        );
      }
    }
  }

  // ── Validation helper ──────────────────────────────────────

  /**
   * Returns true if the currently-configured provider has a stored key.
   * Shows a warning and offers to set the key if missing.
   */
  async ensureKeyConfigured(): Promise<boolean> {
    const provider = vscode.workspace
      .getConfiguration("synthesis")
      .get<string>("provider", "anthropic") as "anthropic" | "gemini";

    const existing = await this.getKeyForProvider(provider);
    if (existing && existing.length > 0) {
      return true;
    }

    const action = await vscode.window.showWarningMessage(
      `Synthesis: No API key configured for provider "${provider}". ` +
        `Threat analysis requires an API key.`,
      "Set API Key",
      "Cancel",
    );

    if (action === "Set API Key") {
      return this.promptForKey(provider);
    }
    return false;
  }
}
