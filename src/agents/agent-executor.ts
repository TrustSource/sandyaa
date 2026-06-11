import Anthropic from '@anthropic-ai/sdk';
import { v4 as uuidv4 } from 'uuid';
import * as fs from 'fs/promises';
import * as path from 'path';
import { spawn, execSync } from 'child_process';
import { withRetry, classifyError } from '../utils/retry.js';
import { DynamicModelSelector, ModelRecommendation } from '../utils/model-selector.js';
import { getClaudeModelMap, getDefaultContextWindow } from '../utils/model-registry.js';
import { RLMExecutor } from './rlm/rlm-executor.js';
import { RLMCostTracker } from './rlm/rlm-cost-tracker.js';
import { RLMConfig, RLMActivation } from './rlm/rlm-types.js';
import { ContentReplacer } from '../utils/content-replacement.js';
import { selectPocExamples } from './poc-examples.js';

export interface AgentTask {
  id?: string;
  type: 'context-building' | 'vulnerability-detection' | 'poc-generation' |
        'vulnerability-pattern-extraction' | 'regression-detection' |
        'memory-safety-analysis' | 'concurrency-analysis' | 'semantic-analysis' |
        'blast-radius-analysis' | 'file-prioritization' | 'analysis-planning' |
        'custom-security-analysis';
  input: any;
  maxTokens?: number;
  model?: 'haiku' | 'sonnet' | 'opus';
}

export interface AgentResult {
  success: boolean;
  output: any;
  error?: string;
  tokensUsed?: number;
  model?: string;
}

export class ClaudeExecutor {
  private client: Anthropic | null = null;
  private tasksInProgress: Map<string, AbortController>;
  private tasksDir: string;
  private isClaudeCode: boolean;
  private static totalTokensUsed: number = 0;
  private static tokensByTask: Map<string, number> = new Map();
  private modelSelector: DynamicModelSelector;
  private rlmExecutor: RLMExecutor | null = null;
  private rlmCostTracker: RLMCostTracker | null = null;
  private rlmConfig: RLMConfig | null = null;
  private contentReplacer: ContentReplacer;
  private static globalTargetCwd: string | undefined;  // Shared across all instances
  private static globalForcedModel: 'haiku' | 'sonnet' | 'opus' | undefined;

  /**
   * Set the target codebase path globally for ALL ClaudeExecutor instances.
   * Claude CLI will run with this CWD so it only sees/accesses target files.
   */
  static setGlobalTargetPath(targetPath: string): void {
    ClaudeExecutor.globalTargetCwd = path.resolve(targetPath);
  }

  /**
   * Pin every Claude task to a specific model, bypassing the dynamic
   * complexity-based selector. Set from the `--model` CLI flag or the
   * configured `provider.models.claude` so users can opt into Opus
   * (1M context) or pin Haiku for cost-sensitive runs.
   */
  static setGlobalForcedModel(model: 'haiku' | 'sonnet' | 'opus'): void {
    ClaudeExecutor.globalForcedModel = model;
  }

  static getGlobalForcedModel(): 'haiku' | 'sonnet' | 'opus' | undefined {
    return ClaudeExecutor.globalForcedModel;
  }

  /** Instance-level alias for backwards compatibility */
  setTargetPath(targetPath: string): void {
    ClaudeExecutor.setGlobalTargetPath(targetPath);
  }

  constructor(apiKey?: string, tasksDir: string = './.sandyaa/tasks', rlmConfig?: RLMConfig) {
    this.tasksInProgress = new Map();
    this.tasksDir = tasksDir;
    this.modelSelector = new DynamicModelSelector();
    this.contentReplacer = new ContentReplacer(path.join(path.dirname(tasksDir), 'content-cache'));

    // Initialize RLM if config provided
    if (rlmConfig) {
      this.rlmConfig = rlmConfig;
      this.rlmCostTracker = new RLMCostTracker(rlmConfig);
      this.rlmCostTracker.loadFromFile();  // Load previous cost data
      this.rlmExecutor = new RLMExecutor(rlmConfig, this.rlmCostTracker, this);
    }

    // Try Claude CLI first (Claude Code integration)
    this.isClaudeCode = this.checkClaudeCLIAvailable();

    if (!this.isClaudeCode) {
      // Fallback to Anthropic SDK (works in Cursor, VS Code, standalone)
      const key = apiKey ||
                  process.env.ANTHROPIC_API_KEY ||
                  process.env.CLAUDE_API_KEY ||
                  process.env.API_KEY ||
                  this.getCursorAPIKey();

      if (!key) {
        throw new Error(
          'No AI provider found.\n' +
          'Options:\n' +
          '1. Install Claude Code CLI\n' +
          '2. Set ANTHROPIC_API_KEY environment variable\n' +
          '3. Run in Cursor with API key configured'
        );
      }

      this.client = new Anthropic({ apiKey: key });

      const environment = process.env.TERM_PROGRAM === 'vscode' ? 'VS Code/Cursor' : 'standalone';
      console.log(`Using Anthropic API (${environment} mode)`);
    }
  }

  private getCursorAPIKey(): string | undefined {
    // Cursor stores API keys in settings or uses its own proxy
    // Users should set ANTHROPIC_API_KEY in their environment
    return undefined;
  }

  private checkClaudeCLIAvailable(): boolean {
    try {
      // Try to find claude command
      execSync('which claude', { stdio: 'pipe' });
      return true;
    } catch {
      return false;
    }
  }

  async execute(task: AgentTask): Promise<AgentResult> {
    const taskId = task.id || uuidv4();
    const abortController = new AbortController();
    this.tasksInProgress.set(taskId, abortController);

    try {
      let result: AgentResult;

      if (this.isClaudeCode) {
        // File-based execution for Claude Code
        result = await this.executeViaFiles(taskId, task);
      } else {
        // Direct API execution for standalone
        result = await this.executeViaAPI(taskId, task);
      }

      // Apply content replacement for large results to keep context manageable
      if (result.success && result.output != null) {
        const outputStr = typeof result.output === 'string'
          ? result.output
          : JSON.stringify(result.output);

        if (outputStr.length > 50_000) {
          const label = `${task.type}_${taskId}`;
          const replaced = this.contentReplacer.replaceIfLarge(
            outputStr,
            50_000,
            label,
          );
          // If content was replaced, store the summarized version
          if (replaced !== outputStr) {
            result = {
              ...result,
              output: replaced,
            };
          }
        }
      }

      return result;
    } finally {
      this.tasksInProgress.delete(taskId);
    }
  }

  private async executeViaFiles(taskId: string, task: AgentTask): Promise<AgentResult> {
    try {
      // Create task directory for logging
      await fs.mkdir(this.tasksDir, { recursive: true });

      // Build prompt
      const prompt = this.buildPrompt(task);

      // Log task for debugging
      const taskFile = path.join(this.tasksDir, `${taskId}.md`);
      await fs.writeFile(taskFile, prompt);

      // RLM activation decision (Phase 2)
      const rlmActivation = this.shouldActivateRLM(task, prompt);

      if (rlmActivation.shouldActivate && this.rlmExecutor) {
        console.log(`    🚀 RLM Mode: ${rlmActivation.reason}`);
        const rlmResult = await this.rlmExecutor.execute(taskId, task, prompt);

        // Track RLM cost with actual breakdown (not estimates)
        if (this.rlmCostTracker && rlmResult.success && 'tokenBreakdown' in rlmResult) {
          this.rlmCostTracker.recordRLMExecution(task.type, rlmResult.tokenBreakdown as any);
        }

        return rlmResult;
      }

      // Dynamic model selection based on code complexity
      let model: 'haiku' | 'sonnet' | 'opus';
      let modelReasoning: string = '';

      if (task.model) {
        // User explicitly specified model
        model = task.model;
        modelReasoning = 'explicitly specified';
      } else if (ClaudeExecutor.globalForcedModel) {
        // Globally forced model (--model flag or config provider.models.claude)
        model = ClaudeExecutor.globalForcedModel;
        modelReasoning = 'forced by --model flag / config';
      } else {
        // Dynamic selection based on complexity
        const files = this.extractFilesFromTask(task);
        const previousFindings = task.input?.previousFindings;
        const recommendation = await this.modelSelector.selectModel(task.type, files, previousFindings);

        model = recommendation.model;
        modelReasoning = recommendation.reasoning;

        // Show reasoning for model selection
        console.log(`    Model: ${model.toUpperCase()} - ${modelReasoning}`);
      }

      // Execute analysis
      const result = await this.executeViaCLI(prompt, taskId, task.type, model);

      // Record result for learning
      if (result.success && result.tokensUsed) {
        this.modelSelector.recordTaskResult(task.type, model, result.success, result.tokensUsed);
      }

      return result;

    } catch (error) {
      return {
        success: false,
        output: null,
        error: error instanceof Error ? error.message : String(error)
      };
    }
  }

  /**
   * DEPRECATED: Old hardcoded model selection (kept as fallback)
   * New code uses DynamicModelSelector for intelligent selection
   */
  private selectModelForTask(taskType: string): 'haiku' | 'sonnet' | 'opus' {
    // Fast planning tasks → Haiku (cheap, 200k context)
    if (['file-prioritization', 'analysis-planning'].includes(taskType)) {
      return 'haiku';
    }

    // Critical detection tasks → Sonnet (was Opus, optimized for cost)
    if (['vulnerability-detection', 'poc-generation', 'vulnerability-pattern-extraction'].includes(taskType)) {
      return 'sonnet';  // Changed from opus to sonnet (5x cheaper, still excellent)
    }

    // Important analysis tasks → Sonnet (quality matters)
    if (['semantic-analysis', 'memory-safety-analysis', 'concurrency-analysis', 'context-building'].includes(taskType)) {
      return 'sonnet';
    }

    // Default → Sonnet (balanced)
    return 'sonnet';
  }

  /**
   * Extract file paths from task input for complexity analysis
   */
  private extractFilesFromTask(task: AgentTask): string[] {
    const files: string[] = [];

    // Extract from different task input structures
    if (task.input?.files) {
      if (Array.isArray(task.input.files)) {
        // Simple array of file paths
        files.push(...task.input.files);
      } else if (typeof task.input.files === 'object') {
        // Context structure with file objects
        for (const file of task.input.files) {
          if (typeof file === 'string') {
            files.push(file);
          } else if (file.path) {
            files.push(file.path);
          }
        }
      }
    }

    // Extract from context object
    if (task.input?.context?.files) {
      for (const file of task.input.context.files) {
        if (typeof file === 'string') {
          files.push(file);
        } else if (file.path) {
          files.push(file.path);
        }
      }
    }

    // Extract from targetPath
    if (task.input?.targetPath && typeof task.input.targetPath === 'string') {
      files.push(task.input.targetPath);
    }

    return files;
  }

  private async executeViaCLI(prompt: string, taskId: string, taskType: string, model: 'haiku' | 'sonnet' | 'opus'): Promise<AgentResult> {
    // Wrap the entire CLI call with retry logic for rate limits and transient failures.
    // On non-retryable errors the inner function throws, which surfaces after all
    // retries are exhausted — we catch that and return a failed AgentResult.
    try {
      return await withRetry<AgentResult>(
        () => this._spawnCLI(prompt, taskId, taskType, model),
        {
          maxRetries: 3,
          baseDelay: 2000,
          maxDelay: 30_000,
          onRetry: (_error, attempt, delay, kind) => {
            console.log(
              `[retry] Claude CLI ${kind} error for task ${taskId} — ` +
              `attempt ${attempt}, waiting ${Math.round(delay)}ms`,
            );
          },
        },
      );
    } catch (error) {
      // All retries exhausted — return a failed result
      return {
        success: false,
        output: null,
        error: `Claude CLI failed after retries: ${error instanceof Error ? error.message : String(error)}`,
      };
    }
  }

  /**
   * Internal: spawn a single Claude CLI invocation.
   * Rejects on retryable errors (rate limits, connection issues) so
   * `withRetry` can catch and retry. Resolves normally otherwise.
   */
  private _spawnCLI(prompt: string, taskId: string, taskType: string, model: 'haiku' | 'sonnet' | 'opus'): Promise<AgentResult> {
    return new Promise((resolve, reject) => {
      // Map model names to Claude model IDs
      const modelMap = getClaudeModelMap();

      const args = [
        '--dangerously-skip-permissions',
        '--verbose',
        '--output-format', 'stream-json',
        '--model', modelMap[model],
        '--print',
        // Prompt will be passed via stdin instead of command line argument
        // to avoid E2BIG errors with large prompts
        '--append-system-prompt',
        'IMPORTANT: You are analyzing a TARGET codebase for security vulnerabilities. ' +
        'Only analyze files in the current working directory. ' +
        'Do NOT analyze the scanning tool itself (sandyaa/scanner). ' +
        'Focus exclusively on the target codebase provided in the prompt.'
      ];

      // Debug: Log the command being executed (only in verbose mode)
      if (process.env.SANDYAA_DEBUG) {
        console.log(`[DEBUG] Spawning: claude ${args.join(' ')}`);
        console.log(`[DEBUG] Prompt length: ${prompt.length} chars`);
      }

      const proc = spawn('claude', args, {
        stdio: ['pipe', 'pipe', 'pipe'],  // Enable stdin for prompt input
        cwd: ClaudeExecutor.globalTargetCwd || process.cwd()  // Run in target directory to prevent self-scanning
      });

      // Write prompt to stdin (avoids E2BIG errors with large prompts)
      if (proc.stdin) {
        proc.stdin.write(prompt);
        proc.stdin.end();
      }

      let stdout = '';
      let stderr = '';

      proc.stdout?.on('data', (data: Buffer) => {
        stdout += data.toString();
      });

      proc.stderr?.on('data', (data: Buffer) => {
        stderr += data.toString();
      });

      proc.on('close', async (exitCode) => {
        if (exitCode !== 0) {
          const combinedOutput = (stderr + stdout).toLowerCase();
          const isRetryable =
            combinedOutput.includes('rate limit') ||
            combinedOutput.includes('rate_limit') ||
            combinedOutput.includes('429') ||
            combinedOutput.includes('529') ||
            combinedOutput.includes('overloaded') ||
            combinedOutput.includes('econnreset') ||
            combinedOutput.includes('epipe') ||
            combinedOutput.includes('etimedout');

          if (isRetryable) {
            // Reject so withRetry catches and retries
            const err = new Error(
              `rate limit: Claude CLI exited with code ${exitCode}: ${(stderr || stdout).substring(0, 300)}`,
            );
            reject(err);
            return;
          }

          // Non-retryable failure — save debug info and resolve with failure
          const stderrFile = path.join(this.tasksDir, `${taskId}-stderr.txt`);
          const stdoutDebugFile = path.join(this.tasksDir, `${taskId}-stdout-debug.txt`);
          await fs.writeFile(stderrFile, stderr || '(empty)');
          await fs.writeFile(stdoutDebugFile, stdout || '(empty)');

          const errorMsg = stderr || stdout || 'No error message available';
          resolve({
            success: false,
            output: null,
            error: `Claude CLI exited with code ${exitCode}\nError: ${errorMsg.substring(0, 500)}${errorMsg.length > 500 ? '...' : ''}\nDebug files: ${stderrFile}, ${stdoutDebugFile}`
          });
          return;
        }

        try {
          // Save raw output for debugging
          const rawFile = path.join(this.tasksDir, `${taskId}-raw.txt`);
          await fs.writeFile(rawFile, stdout);

          // Parse stream-json output
          const { data: parsed, tokensUsed } = this.parseStreamJsonOutput(stdout);

          // Log parsed output
          const outputFile = path.join(this.tasksDir, `${taskId}-output.json`);
          await fs.writeFile(outputFile, JSON.stringify(parsed, null, 2));

          // Track tokens
          ClaudeExecutor.totalTokensUsed += tokensUsed;
          ClaudeExecutor.tokensByTask.set(taskType,
            (ClaudeExecutor.tokensByTask.get(taskType) || 0) + tokensUsed
          );

          // parseResponse returns null on total failure (e.g. truncated JSON).
          // Surface that as a real error so callers see a useful message
          // instead of `Context analysis failed: undefined`.
          if (parsed === null) {
            resolve({
              success: false,
              output: null,
              tokensUsed,
              error: `Could not parse model response as JSON (likely truncated or non-JSON output). Raw stream saved to ${rawFile}.`
            });
            return;
          }

          resolve({
            success: true,
            output: parsed,
            tokensUsed
          });
        } catch (error) {
          // Save raw output on error for debugging
          const rawFile = path.join(this.tasksDir, `${taskId}-raw.txt`);
          await fs.writeFile(rawFile, stdout);

          resolve({
            success: false,
            output: null,
            error: `Failed to parse Claude output: ${error}\nRaw output: ${rawFile}`
          });
        }
      });

      proc.on('error', (error) => {
        // Spawn-level errors — check if retryable (e.g. ECONNRESET)
        const kind = classifyError(error);
        if (kind === 'connection' || kind === 'timeout') {
          reject(error);
          return;
        }
        resolve({
          success: false,
          output: null,
          error: `Failed to spawn Claude CLI: ${error.message}`
        });
      });
    });
  }

  private parseStreamJsonOutput(output: string): { data: any; tokensUsed: number } {
    // Parse stream-json format from Claude CLI.
    // Each line is a JSON event in the message lifecycle. When Claude tool-calls
    // (Read/Grep/etc) the stream interleaves multiple assistant messages with
    // tool_use blocks and user-role tool_result messages. The final structured
    // answer lives in the LAST assistant message's text — concatenating all
    // assistant text mixes reasoning ("I'll check these files...") with the
    // final JSON and breaks parseResponse. So we collect per-message and try
    // the latest first.
    const lines = output.trim().split('\n');
    let tokensUsed = 0;
    const assistantMessages: string[] = [];

    for (const line of lines) {
      try {
        const json = JSON.parse(line);

        if (json.type === 'system' && json.subtype === 'init') continue;
        if (json.type === 'result') continue;
        if (json.type === 'rate_limit_event') continue;
        if (json.type === 'user') continue; // tool_result echoes

        if (json.type === 'assistant' && json.message?.content) {
          if (json.message.usage) {
            tokensUsed += (json.message.usage.input_tokens || 0) +
                          (json.message.usage.output_tokens || 0) +
                          (json.message.usage.cache_read_input_tokens || 0);
          }

          let msgText = '';
          for (const block of json.message.content) {
            if (block.type === 'text' && block.text) {
              msgText += block.text + '\n';
            }
          }
          if (msgText.trim()) assistantMessages.push(msgText);
        }
      } catch {
        // Skip invalid JSON lines
      }
    }

    let responseData: any = null;

    // Try latest assistant message first — that's where the final structured
    // answer lives after any tool-calling.
    for (let i = assistantMessages.length - 1; i >= 0 && !responseData; i--) {
      try {
        const parsed = this.parseResponse(assistantMessages[i]);
        if (parsed) responseData = parsed;
      } catch {
        // try previous
      }
    }

    // Fallback: concatenated text (legacy behavior, useful for non-tool-call cases)
    if (!responseData && assistantMessages.length > 0) {
      try {
        responseData = this.parseResponse(assistantMessages.join('\n'));
      } catch {
        // continue to raw fallback
      }
    }

    // Final fallback: any non-metadata JSON line in the raw stream
    if (!responseData) {
      const filteredOutput = lines
        .filter((line) => {
          try {
            const json = JSON.parse(line);
            return !(json.type === 'system' || json.type === 'result' || json.type === 'assistant' || json.type === 'rate_limit_event' || json.type === 'user');
          } catch {
            return true;
          }
        })
        .join('\n');

      if (filteredOutput.trim()) {
        try {
          responseData = this.parseResponse(filteredOutput);
        } catch {
          responseData = null;
        }
      }
    }

    if (!responseData && assistantMessages.length > 0) {
      const last = assistantMessages[assistantMessages.length - 1];
      console.error('Failed to parse assistant response. Last message preview:', last.substring(0, 300));
    }

    return { data: responseData, tokensUsed };
  }

  private async executeViaAPI(taskId: string, task: AgentTask): Promise<AgentResult> {
    try {
      // Create task directory for logging
      await fs.mkdir(this.tasksDir, { recursive: true });

      // Build prompt based on task type
      const prompt = this.buildPrompt(task);

      // Log task for debugging
      const taskFile = path.join(this.tasksDir, `${taskId}.md`);
      await fs.writeFile(taskFile, prompt);

      // Dynamic model selection based on code complexity
      let model: 'haiku' | 'sonnet' | 'opus';
      let modelReasoning: string = '';

      if (task.model) {
        // User explicitly specified model
        model = task.model;
        modelReasoning = 'explicitly specified';
      } else if (ClaudeExecutor.globalForcedModel) {
        // Globally forced model (--model flag or config provider.models.claude)
        model = ClaudeExecutor.globalForcedModel;
        modelReasoning = 'forced by --model flag / config';
      } else {
        // Dynamic selection based on complexity
        const files = this.extractFilesFromTask(task);
        const previousFindings = task.input?.previousFindings;
        const recommendation = await this.modelSelector.selectModel(task.type, files, previousFindings);

        model = recommendation.model;
        modelReasoning = recommendation.reasoning;

        // Show reasoning for model selection
        console.log(`    Model: ${model.toUpperCase()} - ${modelReasoning}`);
      }

      const modelMap = getClaudeModelMap();

      // Execute using Anthropic SDK directly
      const response = await this.client!.messages.create({
        model: modelMap[model],
        max_tokens: task.maxTokens || 8000,
        messages: [{ role: 'user', content: prompt }],
        temperature: 0.0, // Deterministic for security analysis
      });

      // Extract text content from response
      const textContent = response.content
        .filter((block): block is Anthropic.TextBlock => block.type === 'text')
        .map(block => block.text)
        .join('\n');

      // Log raw response for debugging
      const rawOutputFile = path.join(this.tasksDir, `${taskId}-raw.txt`);
      await fs.writeFile(rawOutputFile, textContent);

      // Parse JSON output from response
      const parsed = this.parseResponse(textContent);

      // Log parsed output for debugging
      const outputFile = path.join(this.tasksDir, `${taskId}-output.json`);
      await fs.writeFile(outputFile, JSON.stringify(parsed, null, 2));

      const tokensUsed = response.usage.input_tokens + response.usage.output_tokens;

      // Track tokens
      ClaudeExecutor.totalTokensUsed += tokensUsed;
      ClaudeExecutor.tokensByTask.set(task.type,
        (ClaudeExecutor.tokensByTask.get(task.type) || 0) + tokensUsed
      );

      // Record result for learning
      this.modelSelector.recordTaskResult(task.type, model, true, tokensUsed);

      return {
        success: true,
        output: parsed,
        tokensUsed
      };

    } catch (error) {
      return {
        success: false,
        output: null,
        error: error instanceof Error ? error.message : String(error)
      };
    }
  }

  cancel(taskId: string): void {
    const controller = this.tasksInProgress.get(taskId);
    if (controller) {
      controller.abort();
      this.tasksInProgress.delete(taskId);
    }
  }

  static getTotalTokensUsed(): number {
    return ClaudeExecutor.totalTokensUsed;
  }

  static getTokensByTask(): Map<string, number> {
    return new Map(ClaudeExecutor.tokensByTask);
  }

  static resetTokenTracking(): void {
    ClaudeExecutor.totalTokensUsed = 0;
    ClaudeExecutor.tokensByTask.clear();
  }

  static formatTokenUsage(): string {
    const total = ClaudeExecutor.totalTokensUsed;
    const byTask = ClaudeExecutor.tokensByTask;

    const contextWindow = getDefaultContextWindow();
    const contextUsagePercent = ((total / contextWindow) * 100).toFixed(2);

    let output = `Total tokens: ${total.toLocaleString()}`;
    output += `\nContext window usage: ${contextUsagePercent}% of ${(contextWindow / 1000).toFixed(0)}k`;

    if (byTask.size > 0) {
      output += '\n\nBreakdown by phase:';
      const sorted = Array.from(byTask.entries()).sort((a, b) => b[1] - a[1]);
      for (const [task, tokens] of sorted) {
        const percentage = ((tokens / total) * 100).toFixed(1);
        const taskName = task.replace(/-/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
        output += `\n  ${taskName}: ${tokens.toLocaleString()} tokens (${percentage}%)`;
      }
    }

    return output;
  }

  private parseResponse(text: string): any {
    // 1. Closed markdown code block: ```json ... ```
    const codeBlockMatch = text.match(/```(?:json)?\s*\n([\s\S]*?)\n```/);
    if (codeBlockMatch) {
      const parsed = this.tryParseJson(codeBlockMatch[1]);
      if (parsed !== undefined) return parsed;
    }

    // 2. UNCLOSED code block (response truncated mid-JSON, no closing fence).
    //    Take everything after the opening fence and try string-aware extraction
    //    + repair below.
    const openFenceMatch = text.match(/```(?:json)?\s*\n([\s\S]*)$/);
    const candidates: string[] = [];
    if (openFenceMatch) candidates.push(openFenceMatch[1]);
    candidates.push(text);

    for (const candidate of candidates) {
      // 3. String-aware scan for the first top-level balanced { ... }.
      //    Unlike the per-line brace counter this version ignores braces
      //    inside string literals and does not latch onto an inner object
      //    just because its line happens to start with `{`.
      const extracted = this.extractTopLevelJson(candidate);
      if (extracted) {
        const parsed = this.tryParseJson(extracted);
        if (parsed !== undefined) return parsed;
      }

      // 4. Repair attempt: response was truncated mid-JSON. Close any
      //    unterminated string / array / object based on the running state.
      const repaired = this.repairTruncatedJson(candidate);
      if (repaired) {
        const parsed = this.tryParseJson(repaired);
        if (parsed !== undefined) return parsed;
      }
    }

    // 5. Legacy regex fallback: known top-level keys.
    const jsonObjectMatch = text.match(/\{[^]*?"(?:analyses|semanticIssues|vulnerabilities|files|components|dataFlows|patterns|prioritized|language|code|setupInstructions|memoryIssues|concurrencyIssues|type|regressed)"[^]*?\}/);
    if (jsonObjectMatch) {
      const parsed = this.tryParseJson(jsonObjectMatch[0]);
      if (parsed !== undefined) return parsed;
    }

    // 6. Last resort: parse the whole text verbatim.
    const wholeParsed = this.tryParseJson(text);
    if (wholeParsed !== undefined) return wholeParsed;

    console.error('All JSON parsing attempts failed. Text preview:', text.substring(0, 300));
    return null;
  }

  private tryParseJson(s: string): any {
    try {
      return JSON.parse(s);
    } catch {
      return undefined;
    }
  }

  /**
   * Scan text for the first top-level balanced JSON object (`{...}`),
   * ignoring braces inside string literals and respecting `\"` escapes.
   * Returns the matching substring or null if no balanced object exists.
   */
  private extractTopLevelJson(text: string): string | null {
    const start = text.indexOf('{');
    if (start === -1) return null;

    let depth = 0;
    let inString = false;
    let escape = false;

    for (let i = start; i < text.length; i++) {
      const ch = text[i];

      if (escape) { escape = false; continue; }
      if (inString) {
        if (ch === '\\') { escape = true; continue; }
        if (ch === '"') inString = false;
        continue;
      }
      if (ch === '"') { inString = true; continue; }
      if (ch === '{') depth++;
      else if (ch === '}') {
        depth--;
        if (depth === 0) return text.slice(start, i + 1);
      }
    }
    return null;
  }

  /**
   * If `text` looks like a JSON object that was truncated mid-stream
   * (response cut off by max_tokens), attempt to close the open contexts
   * so the prefix becomes parseable. Returns the repaired string or null
   * if the input does not look like an unterminated JSON object.
   */
  private repairTruncatedJson(text: string): string | null {
    const start = text.indexOf('{');
    if (start === -1) return null;
    const body = text.slice(start);

    const stack: Array<'{' | '['> = [];
    let inString = false;
    let escape = false;
    let lastNonWs = '';

    for (let i = 0; i < body.length; i++) {
      const ch = body[i];

      if (escape) { escape = false; continue; }
      if (inString) {
        if (ch === '\\') { escape = true; continue; }
        if (ch === '"') inString = false;
        continue;
      }
      if (ch === '"') { inString = true; continue; }
      if (ch === '{' || ch === '[') stack.push(ch);
      else if (ch === '}' || ch === ']') stack.pop();
      if (!/\s/.test(ch)) lastNonWs = ch;
    }

    if (stack.length === 0 && !inString) return null; // not truncated

    let repaired = body;
    if (inString) repaired += '"';
    // Drop dangling trailing comma so we don't produce `[1,2,]` etc.
    repaired = repaired.replace(/,\s*$/, '');
    // Also drop a trailing key-without-value: `"foo":` at the very end.
    repaired = repaired.replace(/"[^"\\]*"\s*:\s*$/, '');
    repaired = repaired.replace(/,\s*$/, '');

    while (stack.length > 0) {
      const opener = stack.pop();
      repaired += opener === '{' ? '}' : ']';
    }

    // Sanity: only return if it parses. Otherwise caller falls through.
    try {
      JSON.parse(repaired);
      return repaired;
    } catch {
      return null;
    }
  }

  private buildPrompt(task: AgentTask): string {
    switch (task.type) {
      case 'context-building':
        return this.buildContextPrompt(task.input);
      case 'vulnerability-detection':
        return this.buildDetectionPrompt(task.input);
      case 'poc-generation':
        return this.buildPOCPrompt(task.input);
      case 'vulnerability-pattern-extraction':
        return this.buildPatternExtractionPrompt(task.input);
      case 'regression-detection':
        return this.buildRegressionDetectionPrompt(task.input);
      case 'memory-safety-analysis':
        return this.buildMemorySafetyPrompt(task.input);
      case 'concurrency-analysis':
        return this.buildConcurrencyPrompt(task.input);
      case 'semantic-analysis':
        return this.buildSemanticPrompt(task.input);
      case 'blast-radius-analysis':
        return this.buildBlastRadiusPrompt(task.input);
      case 'file-prioritization':
        return this.buildFilePrioritizationPrompt(task.input);
      case 'analysis-planning':
        return this.buildAnalysisPlanningPrompt(task.input);
      case 'custom-security-analysis':
        return this.buildCustomAnalysisPrompt(task.input);
      default:
        throw new Error(`Unknown task type: ${task.type}`);
    }
  }

  private buildBlastRadiusPrompt(input: any): string {
    const { vulnerability, context, callSites } = input;

    return `# Blast Radius Analysis

Analyze the impact and reach of this vulnerability.

## Vulnerability
${JSON.stringify(vulnerability, null, 2)}

## Context
${JSON.stringify(context, null, 2).substring(0, 5000)}

## Call Sites (${callSites.length})
${callSites.slice(0, 20).join('\n')}

## Your Task

Determine the blast radius - how far can this vulnerability's impact reach?

1. **Data Flow Impact**:
   - What data is affected by this vulnerability?
   - How far does the tainted data propagate?
   - What systems/modules use this data?

2. **User Impact**:
   - How many users could be affected?
   - What functionality is impacted?
   - Is this a critical user flow?

3. **System Impact**:
   - What systems/services are affected?
   - Can this cascade to other vulnerabilities?
   - What is the worst-case scenario?

## Output Format

\`\`\`json
{
  "affectedDataPaths": number,
  "userImpact": 0.0-1.0,
  "affectedSystems": ["system1", "system2"],
  "description": "detailed impact description"
}
\`\`\`
`;
  }

  private buildContextPrompt(input: any): string {
    const { files, targetPath, focusAreas, fileContents } = input;

    // Build file contents section - include actual source code
    let fileContentSection = '';
    if (fileContents && typeof fileContents === 'object') {
      const entries = Object.entries(fileContents as Record<string, string>);
      // Prioritize security-critical files, limit total to avoid context overflow
      const securityKeywords = ['auth', 'login', 'session', 'token', 'crypto', 'password', 'secret', 'admin', 'permission', 'role', 'access', 'sanitiz', 'valid', 'exec', 'eval', 'sql', 'query', 'upload', 'file', 'ipc', 'handler', 'route', 'api', 'middleware', 'security'];

      const scored = entries.map(([filePath, content]) => {
        const lowerPath = filePath.toLowerCase();
        const score = securityKeywords.filter(kw => lowerPath.includes(kw)).length;
        return { filePath, content: content as string, score };
      });
      scored.sort((a, b) => b.score - a.score);

      // Include files up to ~80K chars total (leaves room for prompt instructions)
      let totalChars = 0;
      const maxChars = 80_000;
      const includedFiles: { filePath: string; content: string }[] = [];

      for (const entry of scored) {
        if (totalChars + entry.content.length > maxChars && includedFiles.length > 0) break;
        includedFiles.push(entry);
        totalChars += entry.content.length;
      }

      fileContentSection = includedFiles.map(f =>
        `### ${f.filePath}\n\`\`\`\n${f.content}\n\`\`\``
      ).join('\n\n');
    }

    return `# Context Building Task

You are analyzing code for security vulnerabilities. Your job is to build deep understanding of the code.

## Target
Base path: ${targetPath}

## Files to Analyze (${files.length} files)
${files.map((f: string) => `- ${f}`).join('\n')}

${focusAreas && focusAreas.length > 0 ? `\n## Focus Areas (prioritize these)\n${focusAreas.map((f: string) => `- ${f}`).join('\n')}\n` : ''}

${fileContentSection ? `## Source Code\n\n${fileContentSection}\n` : ''}

## Instructions

1. Analyze the source code provided above thoroughly
2. For each function:
   - Identify parameters and where they come from
   - Track data flow from inputs to outputs
   - Identify dangerous operations (SQL, exec, eval, file ops, etc.)
   - Note if user input reaches dangerous operations
3. Map entry points (main, HTTP handlers, CLI args, IPC handlers)
4. Identify trust boundaries (network, filesystem, user input, process boundaries)

## Output

Respond with ONLY a JSON object (you can wrap it in markdown code blocks). Use this exact structure:
\`\`\`json
{
  "files": [
    {
      "path": "relative/path/to/file",
      "language": "javascript",
      "functions": [
        {
          "name": "functionName",
          "line": 42,
          "params": ["req", "res"],
          "userInputs": ["req.body.username"],
          "sensitiveSinks": ["db.query()"],
          "dataFlow": [
            {
              "source": "req.body.username",
              "sink": "db.query()",
              "taintPath": ["req.body.username", "username", "query"],
              "isTainted": true
            }
          ]
        }
      ]
    }
  ],
  "entryPoints": ["server.js:app.listen"],
  "trustBoundaries": [
    {
      "location": "routes/api.js:POST /login",
      "type": "user-input",
      "validation": ["none"]
    }
  ]
}
\`\`\`

Only report what you actually find in the code. Do not speculate.
`;
  }

  /**
   * Serialize CodeContext intelligently — prioritize security-relevant data,
   * avoid hard-truncating in the middle of useful information.
   */
  private serializeContext(context: any): string {
    if (!context) return '(no context available)';

    const maxChars = 120_000; // ~30K tokens — fits comfortably in context window
    const parts: string[] = [];

    // 1. Entry points and trust boundaries first (small, high-value)
    if (context.entryPoints?.length) {
      parts.push(`Entry Points:\n${context.entryPoints.map((ep: string) => `  - ${ep}`).join('\n')}`);
    }
    if (context.trustBoundaries?.length) {
      parts.push(`Trust Boundaries:\n${JSON.stringify(context.trustBoundaries, null, 2)}`);
    }

    // 2. Data flows (critical for vulnerability detection)
    if (context.dataFlows?.length) {
      parts.push(`Data Flows:\n${JSON.stringify(context.dataFlows, null, 2)}`);
    }

    // 3. Files with functions — include all but truncate individual large files
    if (context.files?.length) {
      const filesSummary = context.files.map((f: any) => {
        const funcs = f.functions?.map((fn: any) => ({
          name: fn.name,
          line: fn.line,
          params: fn.params,
          userInputs: fn.userInputs,
          sensitiveSinks: fn.sensitiveSinks,
          dataFlow: fn.dataFlow,
        })) || [];
        return {
          path: f.path,
          language: f.language,
          functions: funcs,
          imports: f.imports,
          exports: f.exports,
        };
      });
      parts.push(`Files (${context.files.length}):\n${JSON.stringify(filesSummary, null, 2)}`);
    }

    // 4. Specialized analysis results
    if (context.memorySafety) {
      parts.push(`Memory Safety Analysis:\n${JSON.stringify(context.memorySafety, null, 2)}`);
    }
    if (context.concurrency) {
      parts.push(`Concurrency Analysis:\n${JSON.stringify(context.concurrency, null, 2)}`);
    }
    if (context.semantic) {
      parts.push(`Semantic Analysis:\n${JSON.stringify(context.semantic, null, 2)}`);
    }
    if (context.customStrategies?.length) {
      parts.push(`Custom Analysis Results:\n${JSON.stringify(context.customStrategies, null, 2)}`);
    }

    // Join and apply smart truncation (cut at section boundary, not mid-JSON)
    let result = parts.join('\n\n');
    if (result.length > maxChars) {
      // Truncate from the end, keeping highest-priority sections
      result = result.substring(0, maxChars);
      const lastNewline = result.lastIndexOf('\n\n');
      if (lastNewline > maxChars * 0.8) {
        result = result.substring(0, lastNewline);
      }
      result += '\n\n(context truncated — focus on the data above)';
    }

    return result;
  }

  private buildDetectionPrompt(input: any): string {
    const { context, verificationTask, chainTask } = input;

    // Handle recursive verification sub-tasks (from recursive-analyzer.ts)
    if (verificationTask) {
      return this.buildVerificationSubPrompt(verificationTask, context);
    }
    if (chainTask) {
      return this.buildChainSubPrompt(chainTask, context);
    }

    return `# Autonomous Vulnerability Discovery

You are a world-class security researcher analyzing a codebase to find REAL, EXPLOITABLE bugs.

## ⚠️ CRITICAL: AVOID FALSE POSITIVES ⚠️

**DO NOT REPORT** vulnerabilities unless you can prove ALL of these with concrete evidence:
1. ✅ **Exact file path and line number** where the bug exists
2. ✅ **How attacker reaches it** - concrete entry point (HTTP endpoint, file upload, IPC, etc.)
3. ✅ **Complete data flow** - exact path from attacker input to vulnerable code
4. ✅ **Concrete attack steps** - not "could be exploited" but "here's how to exploit it"
5. ✅ **Real code snippets** - actual code from the codebase as evidence

**REJECT these immediately** (common false positives):
❌ "Potential vulnerability if..." → Need proof, not speculation
❌ "Could lead to..." or "Might allow..." → Need concrete attack path
❌ "Missing validation" without showing exploitable impact → Not a vulnerability
❌ "Theoretical attack" without user input path → Not exploitable
❌ Generic types like "security issue" or "vulnerability" → Be specific
❌ No line numbers or "line: 0" → Must have exact location
❌ Attack vector = "N/A" or < 30 characters → Must be detailed

## Code Context
${this.serializeContext(context)}

## Critical Instructions

**QUALITY OVER QUANTITY**: Report only HIGH-CONFIDENCE, PROVEN vulnerabilities:
- 1 real bug with complete evidence > 10 theoretical bugs
- Spend time verifying each finding before reporting
- If you can't prove it, don't report it

## 🎯 COVERAGE BLINDSPOT HUNTING

**Your Goal**: Find vulnerabilities in areas that humans, fuzzers, and scanners MISS:

**Example Blindspot Vulnerabilities**:

1. **State Machine Confusion** (scanner misses):
   \`\`\`
   User logs in → state="authenticated"
   User uploads file → state="uploading" (authentication not rechecked!)
   Admin views file → XSS (trusted because state was "authenticated" earlier)
   \`\`\`

2. **TOCTOU in Business Logic** (fuzzer can't trigger):
   \`\`\`
   Check: user.balance >= price ✓
   ... (race window) ...
   Deduct: user.balance -= price (balance changed by concurrent request!)
   Result: negative balance, free purchase
   \`\`\`

3. **Indirect Config Injection** (human misses):
   \`\`\`
   User sets displayName = "{{7*7}}" in profile
   Admin views analytics dashboard → template engine renders displayName
   Result: Server-Side Template Injection (user controlled, admin triggered)
   \`\`\`

4. **Multi-Step Privilege Escalation** (static analysis misses):
   \`\`\`
   Step 1: User creates draft post → post.approved=false
   Step 2: User edits post (approval not rechecked!)
   Step 3: User publishes post → shown as "approved" (bypassed workflow)
   \`\`\`

5. **Async Race in Error Path** (all tools miss):
   \`\`\`
   async validateToken() → checks DB (slow)
   async executeAction() → runs immediately (fast)
   Race: executeAction completes BEFORE validateToken rejects
   Result: unauthorized action executed
   \`\`\`

**What Human Reviewers Miss**:
- Complex multi-step state machines (they lose track after 3-4 steps)
- Async race conditions (hard to see in static code review)
- Indirect user control (user influences state, state affects privileged operation later)
- Business logic flaws (require understanding intent, not just code)
- Edge cases in error handling (humans focus on happy paths)
- TOCTOU (Time-Of-Check-Time-Of-Use) in complex flows

**What Fuzzers Can't Reach**:
- Logic bugs that require specific state sequences (fuzzer can't maintain state)
- Authentication/authorization bypasses (fuzzer doesn't understand auth flow)
- Multi-request attack chains (fuzzer sends single requests)
- Timing attacks and race windows (fuzzer doesn't model concurrency)
- Configuration-dependent paths (fuzzer doesn't change configs)
- Cryptographic misuse (fuzzer sees encrypted data, can't analyze crypto logic)

**What Static Scanners Don't Flag**:
- Semantic bugs (code is "correct" but logic is wrong)
- Context-dependent vulnerabilities (safe in one context, vulnerable in another)
- Stateful vulnerabilities (require understanding state transitions)
- Domain-specific logic errors (scanner doesn't understand business rules)
- Implicit trust assumptions (scanner doesn't know what should be trusted)

**ATTACKER CONTROL ANALYSIS**:
For EVERY vulnerability, trace **INDIRECT** and **DIRECT** control:
1. **Direct Control**: User sends malicious HTTP request → RCE
2. **Indirect Control**: User sets config → later admin action → privilege escalation
3. **State Manipulation**: User influences state machine → reaches forbidden state → exploit
4. **Race Conditions**: User sends concurrent requests → TOCTOU → bypass
5. **Sequence-Based**: User performs A → B → C in specific order → vulnerability

**Mark attackerControlled.isControlled = false for bugs where**:
- Attacker needs local code execution first
- No clear attack path from external input
- Requires physical access or insider threat

**Mark attackerControlled.isControlled = true for bugs where**:
- Remote attacker can reach the vulnerable code (directly OR indirectly)
- Clear path from untrusted input to exploitation (even if multi-step)
- Real security impact for external attackers

**DO NOT** limit yourself to predefined vulnerability categories.
**DO NOT** use templates or patterns.
**DO** reason from first principles about what could go wrong.
**DO** report everything but classify it correctly.

## Discovery Process (Think Step-by-Step)

### Phase 1: AUTONOMOUS ANALYSIS START

**YOU decide** based on the code:

1. **Identify security-critical components**:
   - Look at the code structure
   - Which modules handle sensitive data?
   - Which operations are privileged?
   - Where are the trust boundaries?

2. **Select analysis candidates** autonomously:
   - Based on code complexity
   - Based on security sensitivity
   - Based on attack surface exposure
   - Based on historical patterns (if git history available)

3. **Prioritize your focus**:
   - Start with highest-risk components you identify
   - Deep-dive into those components
   - Don't ask what to do - DECIDE and DO IT

### Phase 2: BLINDSPOT COVERAGE HUNTING

**Go where others can't see**:

1. **State Machine Analysis** (humans lose track, fuzzers can't model):
   - Map ALL possible states (including error states)
   - Trace ALL state transitions (including error paths)
   - Find states that "shouldn't be reachable" but are
   - Look for: state confusion, TOCTOU, privilege escalation through state manipulation
   - Ask: "Can user influence state, then trigger operation that trusts that state?"

2. **Multi-Step Attack Chains** (fuzzers can't chain, scanners don't see):
   - Identify sequences: A → B → C where C is vulnerable only after A+B
   - Look for: authentication flows, session management, multi-request workflows
   - Ask: "What if user does steps out of order?" "What if step B fails but C still runs?"

3. **Indirect User Control** (scanners miss this):
   - User sets preference → later system uses preference in privileged operation
   - User uploads file → later admin views file → XSS or XXE
   - User modifies config → later cron job executes with user's config → command injection
   - Ask: "Does user control flow through TIME or STATE?"

4. **Race Condition Windows** (humans can't see, fuzzers hit randomly):
   - Find check-then-use patterns with time gap
   - Identify shared state accessed without locks
   - Look for async operations with intermediate vulnerable states
   - Ask: "What if two requests arrive at the same time?" "What if callback runs before check completes?"

5. **Business Logic Flaws** (requires understanding semantics):
   - Payment manipulation (price, quantity, discount logic)
   - Privilege escalation (role changes, permission checks)
   - Resource exhaustion (unlimited operations, no rate limiting)
   - Ask: "What is this SUPPOSED to do?" "How can I abuse the intended behavior?"

6. **Cryptographic Misuse** (scanners see crypto, don't analyze it):
   - Weak random number generation for security-critical values
   - Timing attacks in comparison operations
   - Padding oracle vulnerabilities
   - Ask: "Is crypto used correctly?" "Can I distinguish encrypted values by timing or error messages?"

7. **Error Path Analysis** (humans focus on happy path):
   - What happens when malloc fails? When file doesn't exist? When network drops?
   - Are errors handled securely or do they reveal information?
   - Do error paths skip security checks?
   - Ask: "What if EVERYTHING goes wrong?"

### Phase 3: DEEP-DIVE & ROOT CAUSE ANALYSIS

For each component YOU selected:

1. **Trace complete data flows**:
   - Where does data originate? (including INDIRECT sources)
   - How is it transformed?
   - Where does it end up?
   - Can attacker inject at any point? (directly or through state/config)

2. **Model state machines** (if stateful):
   - What states exist? (including error/unexpected states)
   - What transitions are allowed? (including race-induced transitions)
   - Can you reach forbidden states? (through unusual sequences)

3. **Analyze assumptions**:
   - What does the code assume? (implicit trust, ordering, timing)
   - Are assumptions enforced? (validation, synchronization)
   - Can they be violated? (race conditions, out-of-order execution)

4. **Root cause thinking** — for every piece of code ask:
   - "What could THIS specific code do unexpectedly?"
   - "What assumptions is the code making, and are they always true?"
   - "As an attacker, what inputs/sequences would I try?"
   - "Can I trace a complete attack path from my control to impact?"

### Phase 4: RECURSIVE DEEPENING

For each potential vulnerability found, recursively deepen:

1. Follow data through every transformation
2. Can you trace a complete attack path?
3. What preconditions are needed? Can they be satisfied?
4. What is the exact exploit and impact?
5. If uncertain — analyze callers recursively, trace data flow deeper

### Phase 5: SELF-VERIFICATION

After finding a potential vulnerability:

1. **Verify the attack path**: Trace from attacker control to impact
2. **Check for defenses**: Are there validations I missed?
3. **Model the state**: What states does the system go through?
4. **Verify the logic**: Does my reasoning have contradictions?
5. **Build a POC**: Can I write code that proves it?

If you can't verify all 5 steps, keep analyzing or mark as uncertain.
If you can't prove it with evidence, **don't report it**.

## ═══════════════════════════════════════════════════════════════
## GOD-LEVEL RULES - ABSOLUTE REQUIREMENTS (NO EXCEPTIONS)
## ═══════════════════════════════════════════════════════════════

**DO NOT REPORT** a vulnerability unless you have ALL of these with CONCRETE EVIDENCE:

1. ✓ **File:Line Location**: Real file path (not "N/A") + actual line number (not 0)
2. ✓ **User Control**: Attacker can trigger remotely (HTTP, network, file, IPC, etc.)
3. ✓ **Entry Point**: EXACT entry point (e.g., "POST /api/upload endpoint at server.js:145")
4. ✓ **Data Flow**: Complete path ["req.body.file" → "parseFile()" → "eval()"]
5. ✓ **Attack Steps**: Concrete exploitation (not "could be" but "send this request")
6. ✓ **Code Evidence**: Real code snippets from the actual files
7. ✓ **Real Impact**: What attacker achieves (with proof)

**STOP AND VERIFY**: Before reporting, ask yourself:
- Can I write a curl command / HTTP request that triggers this?
- Do I have the EXACT line number where the bug is?
- Can I explain step-by-step how to exploit this?
- Do I have real code snippets as evidence?

**If you answer NO to any of these, DO NOT REPORT IT.**

**FALSE POSITIVES to REJECT**:
❌ "Could be vulnerable if..." → REJECT: Need proof
❌ "Potential overflow" without user input path → REJECT: Not exploitable
❌ "Missing validation" without exploit → REJECT: Not a vulnerability
❌ No line number or line=0 → REJECT: No exact location
❌ Generic type like "security issue" → REJECT: Be specific
❌ Attack vector is "N/A" or "unclear" → REJECT: No attack path
❌ attackerControlled missing → REJECT: No proof of control

**REAL BUGS to ACCEPT**:
✅ HTTP POST /upload → parseFile() at upload.js:234 → eval(filename) → RCE
✅ WebSocket msg → JSON.parse() at ws.js:89 → no validation → injection at db.js:145
✅ File upload → extractZip() at zip.js:67 → path traversal → write /etc/passwd

## Output Format

Report ONLY vulnerabilities you can prove meet ALL god-level rules:

\`\`\`json
{
  "vulnerabilities": [
    {
      "id": "vuln-unique-id",
      "type": "descriptive-name-not-generic-category",
      "severity": "critical|high|medium|low",
      "exploitability": 0.0-1.0,
      "attackerControlled": {
        "isControlled": true,
        "entryPoint": "HTTP POST /api/upload - multipart file upload",
        "dataFlow": ["req.files[0].buffer", "parseDocument()", "eval(code)"],
        "attackPath": "Upload malicious file → parser extracts code → eval executes"
      },
      "blindspotCategory": "state-machine-confusion|multi-step-chain|indirect-control|race-condition|business-logic|crypto-misuse|error-path|none",
      "blindspotExplanation": "Why humans/fuzzers/scanners would miss this (e.g., 'Requires understanding 5-step state machine', 'Race window only 50ms', 'Indirect control through config stored 2 weeks ago')",
      "location": {
        "file": "path/to/file.ext",
        "line": 123,
        "function": "functionName"
      },
      "description": "What is wrong (be specific)",
      "rootCause": "Why this bug exists (first principles)",
      "attackVector": "Concrete remote exploitation steps",
      "impact": "What attacker achieves (RCE, data theft, DoS, etc.)",
      "preconditions": ["What must be true for exploitation"],
      "evidenceChain": [
        {
          "step": 1,
          "type": "entry-point|data-flow|state-transition|validation-missing|etc",
          "location": "file.ext:line",
          "code": "actual code snippet",
          "reasoning": "why this is significant"
        }
      ],
      "exploitationDependencies": {
        "required": [
          {
            "type": "state|timing|memory-layout|race-condition|api-sequence|data-structure|environment|configuration|other",
            "description": "e.g., 'Array must be sparse (holes in indices)', 'Object must be in freed state', 'Timing window <100ms', 'Specific API call sequence required'",
            "feasibility": "easy|moderate|difficult|theoretical",
            "required": true
          }
        ],
        "complexity": "trivial|low|medium|high|extreme",
        "directlyExploitable": true,
        "notes": "Additional context about exploitation complexity"
      },
      "reachability": {
        "isReachable": true,
        "reason": "e.g., 'Behind feature flag EXPERIMENTAL', 'Dead code', 'Requires admin auth'",
        "couldBecomeReachable": false,
        "conditions": ["What would make it reachable, e.g., 'Enable feature flag', 'Create admin user'"]
      },
      "discoveryPath": "How you found this (your reasoning process)",
      "selfVerification": "Why you believe this is real (not false positive)"
    }
  ]
}
\`\`\`

**MANDATORY**:
- Every vulnerability MUST include a VALID location with real file path and line number (NO "N/A", NO placeholders)
- If you cannot determine the exact file/line, DO NOT report the vulnerability
- Every vulnerability MUST include the attackerControlled field showing the entry point and data flow
- Every vulnerability SHOULD include blindspotCategory if it falls into coverage gaps (state machines, race conditions, business logic, etc.)
- Use blindspotExplanation to document WHY this would be missed by humans/fuzzers/scanners
- Every vulnerability MUST include exploitationDependencies analyzing prerequisites and complexity
- Every vulnerability SHOULD include reachability analysis (is code actually reachable?)

**EXPLOITATION COMPLEXITY ANALYSIS**:
You MUST analyze and report:
1. **Prerequisites**: What must be true to exploit this? (array must be sparse, object in specific state, timing window, etc.)
2. **Reachability**: Can this code actually be reached? Or is it behind feature flags, dead code, privileged access?
3. **Report ALL bugs**: Even if exploitability is low or code is unreachable, report it if the bug EXISTS
   - "Bug exists but hard to exploit" ≠ "Bug doesn't exist"
   - "Code unreachable now" ≠ "Bug doesn't exist" (could become reachable later)

**Examples of Dependencies to Identify**:
- **Data Structure**: "Array must be sparse with holes in indices", "HashMap must have hash collision"
- **State**: "Object must be in freed state", "Session must be in specific state machine position"
- **Timing**: "Race window is only 50ms", "Requires specific thread interleaving"
- **API Sequence**: "Must call A() then B() then C() in exact order"
- **Memory Layout**: "Heap must be arranged with specific layout", "Stack frame must have specific structure"
- **Environment**: "Only on Linux kernel <5.0", "Requires specific compiler optimization level"
- **Configuration**: "Feature flag must be enabled", "Debug mode must be active"
- **Access**: "Requires authenticated user", "Requires admin privileges"

**Reachability Examples**:
- "Code is behind EXPERIMENTAL_FEATURES flag (disabled by default)" → isReachable=false, couldBecomeReachable=true
- "Dead code path (never called)" → isReachable=false, couldBecomeReachable=false
- "Requires admin authentication" → isReachable=true (if admin exists), conditions=["Must authenticate as admin"]
- "Only reachable in debug builds" → isReachable=false, couldBecomeReachable=true, conditions=["Enable debug build"]

**PRIORITIZE BLINDSPOT BUGS**: These are the HIGH-VALUE findings that researchers pay for!

## Critical Rules

**AUTONOMOUS DECISION-MAKING**:
- DO NOT ask "Should I analyze X or Y?"
- DO NOT ask "Which approach should I take?"
- YOU decide based on the code you see
- YOU select the most promising candidates
- YOU move forward without asking

**EXECUTION**:
- Identify security-critical components from the code
- Prioritize them by risk (YOU decide the criteria)
- Deep-dive into each priority component
- Find vulnerabilities through recursive reasoning
- Report ALL bugs you can prove

**OUTPUT**:
- Only vulnerabilities with concrete evidence
- No questions, no options, no suggestions
- Just findings backed by proof

---

## CRITICAL: JSON-ONLY OUTPUT REQUIREMENT

**YOU MUST RESPOND WITH ONLY A JSON OBJECT. NO OTHER TEXT.**

**DO NOT:**
- ❌ Write "Let me analyze..." or "I'll start by..."
- ❌ Use TodoWrite or any tools
- ❌ Write conversational text before or after JSON
- ❌ Explain your process or reasoning outside the JSON

**DO:**
- ✅ Output ONLY the JSON object with vulnerabilities
- ✅ You may wrap it in markdown code blocks: \`\`\`json ... \`\`\`
- ✅ Include your reasoning INSIDE the JSON fields (discoveryPath, selfVerification)

**Example of CORRECT output:**
\`\`\`json
{
  "vulnerabilities": [
    {
      "id": "vuln-1",
      "type": "buffer-overflow-in-parse",
      ...
    }
  ]
}
\`\`\`

**Example of INCORRECT output:**
❌ "I'll analyze this code using TodoWrite. Let me read the files first..."
❌ Any text before or after the JSON

**START YOUR RESPONSE WITH THE JSON OBJECT NOW.**
`;
  }

  /**
   * Build prompt for recursive verification sub-task
   */
  private buildVerificationSubPrompt(verificationTask: any, context: any): string {
    const vuln = verificationTask.vulnerability;
    return `# Vulnerability Verification Task

You are verifying a previously reported vulnerability. Be CRITICAL — challenge the finding.

## Reported Vulnerability
- **Type**: ${vuln.type}
- **Location**: ${vuln.location?.file}:${vuln.location?.line} (${vuln.location?.function})
- **Severity**: ${vuln.severity}
- **Description**: ${vuln.description}
- **Attack Vector**: ${vuln.attackVector}

## Verification Depth: ${verificationTask.depth}

## Instructions
${verificationTask.instruction}

## Code Context
${this.serializeContext(context)}

## Output Format
Return JSON only:
\`\`\`json
{
  "verified": true|false,
  "confidence": "high|medium|low",
  "reasoning": "why you believe this is/isn't a real vulnerability",
  "missedDefenses": ["any mitigations the original analysis missed"],
  "correctedDataFlow": ["corrected data flow if original was wrong"],
  "additionalContext": "any new information discovered"
}
\`\`\``;
  }

  /**
   * Build prompt for vulnerability chain discovery sub-task
   */
  private buildChainSubPrompt(chainTask: any, context: any): string {
    const startVuln = chainTask.startingVuln;
    return `# Vulnerability Chain Discovery Task

Find OTHER vulnerabilities that chain with this one for higher impact.

## Starting Vulnerability
- **Type**: ${startVuln.type}
- **Location**: ${startVuln.location?.file}:${startVuln.location?.line}
- **Impact**: ${startVuln.impact}

## Instructions
${chainTask.instruction}

## Code Context
${this.serializeContext(context)}

## Output Format
Return JSON only:
\`\`\`json
{
  "chains": [
    {
      "additionalBugs": [
        {
          "id": "chain-vuln-1",
          "type": "specific-type",
          "location": { "file": "path", "line": 123, "function": "name" },
          "description": "what this bug is"
        }
      ],
      "exploitability": 0.0-1.0,
      "path": "step-by-step attack chain description",
      "impact": "combined impact of the chain"
    }
  ]
}
\`\`\``;
  }

  private buildPOCPrompt(input: any): string {
    const { vulnerability, context, targetLanguage } = input;

    // Extract source code from vulnerability or context
    let sourceCode = '';
    if (vulnerability.location && vulnerability.location.file) {
      const fileContext = context?.files?.find((f: any) =>
        f.path === vulnerability.location.file ||
        f.path.endsWith(vulnerability.location.file)
      );
      if (fileContext) {
        sourceCode = fileContext.content || '';
        // Extract 40 lines around the vulnerability line
        if (sourceCode && vulnerability.location.line) {
          const lines = sourceCode.split('\n');
          const start = Math.max(0, vulnerability.location.line - 20);
          const end = Math.min(lines.length, vulnerability.location.line + 20);
          sourceCode = lines.slice(start, end).join('\n');
        }
      }
    }

    const deps = vulnerability.exploitationDependencies?.summary ||
      (vulnerability.exploitationDependencies ? JSON.stringify(vulnerability.exploitationDependencies) : 'none specified');
    const reachability = vulnerability.reachability || 'no conditions specified';

    const examples = selectPocExamples(vulnerability.type || '', 2);
    const examplesSection = examples.length > 0
      ? `## Examples\nThe following examples illustrate the expected output format:\n\n${examples.map((e, i) => {
          const { validated: _omit, ...exampleData } = e.example;
          return `### Example ${i + 1} (${e.example.language})\n` + '```json\n' + JSON.stringify(exampleData, null, 2) + '\n```';
        }).join('\n\n')}\n`
      : '';

    return `Generate a security test case for the following vulnerability.

The test case must be specific to the actual code — use exact function names,
endpoints, parameters, and data types from the source. Do not use placeholder
values.

## Vulnerability
\`\`\`json
${JSON.stringify(vulnerability, null, 2)}
\`\`\`

## Source code context (${vulnerability.location?.file}:${vulnerability.location?.line})
\`\`\`${targetLanguage || 'text'}
${sourceCode || '// Source not available — generate test case from the vulnerability description above'}
\`\`\`

## Output format
Respond with ONLY a JSON object (no text before or after):
\`\`\`json
{
  "language": "html|javascript|python|go|rust|c|cpp|bash|sql|http|curl",
  "code": "complete, runnable test case code",
  "setupInstructions": "numbered steps an independent tester can follow to run this test",
  "expectedImpact": "specific, observable outcome that confirms the vulnerability (not vague — e.g. 'alert(document.cookie) appears' not 'XSS may occur')",
  "testSteps": [
    "action and expected result",
    "action and expected result",
    "how to confirm the test succeeded"
  ],
  "prerequisitesHandled": {
    "exploitationDependencies": "how the test satisfies each required dependency",
    "reachability": "how the test reaches the vulnerable code path",
    "attackChain": "summary of data flow from attacker input to impact"
  },
  "validated": false
}
\`\`\`

## Guidelines
- Trace data flow from attacker-controlled input to the vulnerable code path
- Exploitation dependencies: ${deps}
- Reachability conditions: ${reachability}
- Use exact identifiers from the source: function names, endpoint paths, parameter names, types
- Choose the language that matches the vulnerability type (HTML for browser bugs, Python/JS for web backends, C for memory-safety, Bash for command injection, etc.)
- Setup instructions must be complete enough for a tester who has not seen the code before

${examplesSection}`;
  }

  private buildPatternExtractionPrompt(input: any): string {
    const { message, diff, changedFiles } = input;

    return `# Vulnerability Pattern Extraction

You are analyzing a git commit that fixed a security vulnerability.

## Commit Message
${message}

## Changed Files
${changedFiles.join('\n')}

## Diff
\`\`\`diff
${diff.substring(0, 10000)}
\`\`\`

## Your Task

Analyze this security fix and extract the vulnerability pattern:

1. **What was the vulnerability?**
   - What type of bug was it? (be specific, don't use generic categories)
   - What was the root cause at the code level?
   - What security property was violated?

2. **What pattern caused it?**
   - What code pattern led to this bug?
   - What assumptions were wrong?
   - What checks were missing?

3. **How was it fixed?**
   - What changes were made?
   - What validation/checks were added?
   - What architectural changes were made?

4. **Where could similar bugs exist?**
   - What would similar vulnerable code look like?
   - What search terms would find similar issues?

## Output Format

Respond with ONLY a JSON object:
\`\`\`json
{
  "type": "specific-vulnerability-type",
  "pattern": "code pattern that caused the bug",
  "location": {
    "file": "path/to/file",
    "linesBefore": ["vulnerable code lines"],
    "linesAfter": ["fixed code lines"]
  },
  "rootCause": "fundamental reason this bug existed",
  "fixApplied": "what was done to fix it"
}
\`\`\`
`;
  }

  private buildRegressionDetectionPrompt(input: any): string {
    const { fix, currentState } = input;

    return `# Regression Detection

You are checking if a previously-fixed security vulnerability has been reintroduced.

## Original Security Fix
**Commit**: ${fix.commit}
**Date**: ${fix.date}
**Message**: ${fix.message}

**Vulnerability Pattern**:
${JSON.stringify(fix.vulnerabilityPattern, null, 2)}

## Current Code State
${Object.entries(currentState)
  .map(([file, content]) => `### ${file}\n\`\`\`\n${(content as string).substring(0, 5000)}\n\`\`\``)
  .join('\n\n')}

## Your Task

Determine if the security fix is still present or if the vulnerability has been reintroduced.

1. **Compare current code to the fix**:
   - Is the fix still present?
   - Has the fix been modified or removed?
   - Has refactoring reintroduced the vulnerability?

2. **Check for regression**:
   - Does the current code have the same vulnerability pattern?
   - Is the root cause still addressable by the same fix?

## Output Format

Respond with ONLY a JSON object:
\`\`\`json
{
  "regressed": true/false,
  "reason": "detailed explanation of why this is/isn't a regression"
}
\`\`\`
`;
  }

  private buildMemorySafetyPrompt(input: any): string {
    const { files, instruction } = input;

    return `# Memory Safety Analysis

You are analyzing code for memory safety vulnerabilities.

## Files to Analyze
${files.join('\n')}

## Instruction
${instruction || 'Analyze these files for memory safety issues. Focus on high-risk areas.'}

## Instructions

**DO NOT look for predefined vulnerability types.**

Instead, analyze this code from FIRST PRINCIPLES:

### Step 1: Identify all memory operations
- Where is memory allocated? (malloc, new, alloc, vec creation, etc.)
- Where is memory accessed? (array indexing, pointer deref, etc.)
- Where is memory freed? (free, delete, drop, etc.)

### Step 2: Track object lifetimes
For each allocated object:
- **Creation**: Where and how is it created?
- **Ownership**: Who owns this object? Can ownership transfer?
- **References**: What references/pointers exist to it?
- **Destruction**: When is it destroyed?
- **Post-destruction access**: Can it be accessed after destruction?

### Step 3: Analyze pointer safety
For each pointer operation:
- **Validity**: Is the pointee guaranteed to be alive?
- **Bounds**: Are array accesses bounds-checked?
- **Type safety**: Could type confusion occur?
- **Aliasing**: Can multiple pointers point to same memory?

### Step 4: Check for undefined behavior
- Uninitialized memory reads
- Use-after-free
- Double-free
- Buffer overflow/underflow
- Null pointer dereference
- Integer overflow affecting memory operations

### Step 5: Reason about exploitability
For each issue found:
- Can an attacker control the input?
- What is the impact? (crash, info leak, code execution)
- What is the attack vector?

## Real-World Examples (learn from these patterns)

### Use-After-Free Pattern (Chrome CVE-2020-6463)
\`\`\`cpp
void Process() {
    callback_->Run();  // Might delete 'this'
    data_->Use();      // UAF if callback deleted this
}
\`\`\`
Root cause: Object lifetime not protected during callback.

### Type Confusion (V8 CVE-2019-5825)
\`\`\`javascript
let x = a[0];  // JIT assumes x is always integer
return x + 1;  // Type confusion if a[0] changes to object
\`\`\`
Root cause: JIT optimization based on stale type feedback.

## Output Format

Report ALL memory safety issues you find, regardless of category:

\`\`\`json
{
  "memoryIssues": [
    {
      "type": "describe-the-specific-issue",
      "location": {"file": "...", "line": 123},
      "description": "what is wrong",
      "rootCause": "why this is unsafe",
      "exploitability": 0.0-1.0,
      "impact": "what attacker achieves",
      "evidence": ["line-by-line proof"]
    }
  ]
}
\`\`\`

Think step-by-step. Show your reasoning.
`;
  }

  private buildConcurrencyPrompt(input: any): string {
    const { files, instruction } = input;

    return `# Concurrency Safety Analysis

You are analyzing code for concurrency bugs and race conditions.

## Files to Analyze
${files.join('\n')}

## Instruction
${instruction || 'Analyze these files for concurrency issues. Focus on high-risk areas.'}

## Instructions

**DO NOT look for predefined patterns.**

Instead, reason from FIRST PRINCIPLES about concurrency:

### Step 1: Identify concurrency primitives
- Threads, processes, async/await, goroutines, etc.
- Locks, mutexes, semaphores, atomics
- Channels, message passing
- Shared memory regions

### Step 2: Map shared state
For each shared variable/object:
- **Who accesses it?** (which threads/contexts)
- **How is access synchronized?** (locks, atomics, message passing)
- **What is the critical section?**
- **Can unsynchronized access occur?**

### Step 3: Analyze happens-before relationships
- What operations must happen before others?
- Are ordering guarantees enforced?
- Can reordering cause bugs?

### Step 4: Check for race conditions
**Data races**:
- Concurrent reads + writes to same memory
- No synchronization between accesses

**Time-of-check-time-of-use (TOCTOU)**:
- Check condition at time T1
- Use resource at time T2
- State can change between T1 and T2

**Atomicity violations**:
- Operation should be atomic but isn't
- Intermediate states visible to other threads

### Step 5: Check for deadlocks
- Lock ordering issues
- Circular dependencies
- Missing unlock paths

### Step 6: Business logic races
- Does concurrent execution violate invariants?
- Can race conditions lead to auth bypass?
- Can double-spending occur?

## Real-World Examples

### TOCTOU Pattern
\`\`\`python
if is_safe(file):     # Time-of-check
    # ... delay ...
    read(file)         # Time-of-use (file might have changed)
\`\`\`

### Data Race Pattern
\`\`\`go
var balance int  // Shared state
// Thread 1
balance += 100
// Thread 2
balance -= 50
// Race: final balance is unpredictable
\`\`\`

## Output Format

Report ALL concurrency issues:

\`\`\`json
{
  "concurrencyIssues": [
    {
      "type": "describe-the-specific-issue",
      "location": {"file": "...", "line": 123},
      "description": "what race condition exists",
      "scenario": "how concurrent execution leads to bug",
      "exploitability": 0.0-1.0,
      "impact": "what attacker achieves",
      "evidence": ["step-by-step race scenario"]
    }
  ]
}
\`\`\`

Think step-by-step. Show your reasoning.
`;
  }

  private buildSemanticPrompt(input: any): string {
    const { files, instruction } = input;

    return `# Semantic Security Analysis

You are analyzing code for business logic and semantic vulnerabilities.

## Files to Analyze
${files.join('\n')}

## Instruction
${instruction || 'Analyze these files for semantic vulnerabilities and logic bugs. Focus on high-risk areas.'}

**IMPORTANT**: You must analyze the files listed above directly. DO NOT use the Task tool or spawn agents. Read the files yourself using the Read tool and output your analysis as JSON.

## Instructions

Use FIRST PRINCIPLES thinking with 5 WHYS and 5 HOWS methodology:

### FIRST PRINCIPLES: Understand the purpose

For each function/component:
1. **What is it trying to accomplish?**
   - What is the business purpose?
   - What problem does it solve?
   - What are the use cases?

2. **What are the security-critical operations?**
   - Authentication/authorization
   - Money/value transfers
   - Sensitive data access
   - State transitions

3. **What are the invariants?**
   - What must ALWAYS be true?
   - What assumptions does the code make?
   - What contracts must hold?

### 5 WHYS: Understand design decisions

For each security-critical decision:
1. Why was this approach chosen?
2. Why this data structure?
3. Why this validation method?
4. Why this state management?
5. Why these constraints?

*Goal*: Understand if the WHY reveals a flawed assumption.

### 5 HOWS: Find attack vectors

For each security-critical operation:
1. How could an attacker reach this code?
2. How could invariants be violated?
3. How could assumptions be broken?
4. How could state be corrupted?
5. How could this combine with other bugs?

*Goal*: Find realistic exploitation paths.

### Specific Areas to Analyze

**Authentication/Authorization**:
- Can auth be bypassed?
- Can users impersonate others?
- Are permissions properly enforced?
- Can privilege escalation occur?

**State Machines**:
- What states exist?
- What transitions are allowed?
- Can invalid states be reached?
- Can transitions be skipped?

**Business Logic**:
- Can operations be repeated when they shouldn't?
- Can operations occur in wrong order?
- Can constraints be violated?
- Can race conditions affect business logic?

**Cryptography**:
- Are crypto primitives used correctly?
- Are keys properly managed?
- Is randomness sufficient?

**Trust Boundaries**:
- What data crosses trust boundaries?
- Is external input validated?
- Are outputs properly encoded?

## Real-World Example

### Authentication State Machine Bug
\`\`\`javascript
class Auth {
  state = 'unauthenticated'  // States: unauthenticated, authenticating, authenticated

  async login(user, pass) {
    this.state = 'authenticating'
    if (await checkPassword(user, pass)) {
      this.state = 'authenticated'
    }
  }

  getData() {
    if (this.session) {  // BUG: Doesn't check state!
      return secrets
    }
  }
}
\`\`\`

**5 WHYS**:
1. Why doesn't getData check state? → Assumed session implies authenticated
2. Why assume session implies authenticated? → Didn't model states explicitly
3. Why not model states? → Focused on happy path
4. Why focus on happy path? → Didn't think adversarially
5. Why not think adversarially? → Lack of threat modeling

**5 HOWS**:
1. How to reach getData during 'authenticating'? → Call it before login completes
2. How to get session during 'authenticating'? → Session created early
3. How to exploit? → Race condition: call getData during login
4. How to make it reliable? → Send many requests in parallel
5. How to maximize impact? → Combine with other auth bugs

## Output Format

Report ALL semantic/business logic issues:

\`\`\`json
{
  "semanticIssues": [
    {
      "type": "describe-the-specific-issue",
      "location": {"file": "...", "line": 123},
      "description": "what is wrong",
      "invariantViolated": "what invariant can be broken",
      "attackScenario": "step-by-step exploitation",
      "exploitability": 0.0-1.0,
      "impact": "what attacker achieves",
      "fiveWhys": ["why1", "why2", "why3", "why4", "why5"],
      "fiveHows": ["how1", "how2", "how3", "how4", "how5"]
    }
  ]
}
\`\`\`

Think deeply. Reason from first principles.
`;
  }

  private buildAnalysisPlanningPrompt(input: any): string {
    const { files, learningContext } = input;

    // Build learning context section
    let learningSection = '';
    if (learningContext && Object.keys(learningContext).length > 0) {
      learningSection = `\n## 🧠 LEARNING CONTEXT (Use this knowledge to adapt your strategy!)

**CRITICAL**: You have analyzed previous code chunks. Use these learnings to plan SMARTER strategies.
`;

      if (learningContext.previousFindings && learningContext.previousFindings.length > 0) {
        learningSection += `\n### Previous Vulnerabilities Found (${learningContext.previousFindings.length}):
${learningContext.previousFindings.map((f: any) =>
  `- **${f.type}** (${f.severity}) at ${f.location}: ${f.pattern}`
).join('\n')}

**→ What does this tell you about THIS codebase?**
**→ Should you look for similar patterns in the new files?**
`;
      }

      if (learningContext.gitHistoryPatterns && learningContext.gitHistoryPatterns.length > 0) {
        learningSection += `\n### Historical Vulnerability Patterns from Git:
${learningContext.gitHistoryPatterns.map((p: string) => `- ${p}`).join('\n')}

**→ These patterns were fixed before - are there similar unfixed instances?**
**→ Should you design a strategy to find regression risks?**
`;
      }

      if (learningContext.highRiskAreas && learningContext.highRiskAreas.length > 0) {
        learningSection += `\n### High-Risk Code Areas:
${learningContext.highRiskAreas.map((a: string) => `- ${a}`).join('\n')}

**→ If files from these areas are in the current chunk, prioritize them!**
`;
      }

      if (learningContext.successfulStrategies && learningContext.successfulStrategies.length > 0) {
        learningSection += `\n### Strategies That Found Real Bugs:
${learningContext.successfulStrategies.map((s: string) => `- ${s}`).join('\n')}

**→ Should you apply similar strategies to the new files?**
`;
      }

      learningSection += `\n**KEY INSIGHT**: You are NOT starting from scratch! Use the patterns above to design targeted strategies.\n`;
    }

    return `# Autonomous Analysis Strategy Planning

You are a security expert examining a TARGET APPLICATION to design a custom analysis strategy.

**🚨 ABSOLUTELY CRITICAL - READ THIS FIRST 🚨**

You are analyzing THE APPLICATION SHOWN IN THE FILE LIST BELOW.
You are NOT analyzing:
- Sandyaa (the security tool running this analysis)
- Any security scanning tool
- Any TypeScript analysis framework
- Any files in src/agents/, src/utils/, src/poc-gen/, src/recursive/, etc.

THE ONLY FILES THAT EXIST are the ones listed in "Files in This Chunk" below.
DO NOT reference, mention, or analyze ANY other files.
${learningSection}
## Files in This Chunk
These are the ONLY files you should analyze. NO OTHER FILES EXIST.

${files.join('\n')}

## Your Task

Analyze ONLY the files listed in "Files in This Chunk" above.

**⚠️ ABSOLUTE RULES - VIOLATION WILL CAUSE FAILURE**:
1. ONLY analyze files from the list above
2. NEVER mention or reference Sandyaa, security tools, TypeScript frameworks, or analysis systems
3. If you include targetFiles in your response, they MUST be EXACT copies from the file list above
4. DO NOT invent, imagine, or reference ANY files not in the list above
5. DO NOT analyze how the security tool works - analyze the TARGET APPLICATION only

**What you're analyzing**: The application shown in the file list (Firefox browser, Airflow, or whatever application those files belong to)
**What you're NOT analyzing**: Sandyaa, security tools, scanning frameworks, or anything related to vulnerability analysis tools

**RESEARCHER FOCUS**: As a security researcher, you should prioritize finding:
- **ATTACKER-CONTROLLED** vulnerabilities (remote exploitation possible)
  - Direct: User input (HTTP requests, file uploads, CLI args, environment variables)
  - Indirect: User influences config/state that later affects privileged operations
  - Network data (sockets, APIs, IPC messages)
  - File system data (untrusted files, config files)
  - Any data crossing trust boundaries (even delayed/indirect)

- **HIGH-IMPACT** severity: Critical > High > Medium
  - But still report ALL findings you discover

- **COVERAGE BLINDSPOTS**: Target areas humans/fuzzers/scanners miss
  - State machines and multi-step flows
  - Race conditions and TOCTOU
  - Business logic and semantic bugs
  - Indirect user control through config/state
  - Error paths and edge cases
  - Cryptographic misuse

**ATTACKER-CONTROLLED TRACING**:
For EVERY vulnerability, trace and document (including INDIRECT paths):
1. **Source**: Where does attacker-controlled data enter?
   - Direct: URL param, File upload, IPC message
   - Indirect: User sets config, User manipulates state, User influences timing
2. **Path**: How does it flow through code?
   - Direct: transformations, validations
   - Indirect: stored in DB → later retrieved → used in privileged operation
   - State-based: user influences state → state checked later → wrong decision
   - Time-based: user sets value → later cron/callback uses it
3. **Sink**: Where does it cause harm?
   - Direct: SQL query, system() call, memory corruption
   - Indirect: admin action using user-controlled state, privileged operation with user config
4. Set attackerControlled.isControlled = true if you can trace source to sink (even if indirect/multi-step)
5. Set attackerControlled.isControlled = false if it requires local access or insider threat

**DO NOT** use predefined categories.
**DO NOT** follow generic rules.
**DO** reason from first principles about what could go wrong in THIS code.
**DO** leverage patterns and learnings from previous chunks.
**DO** focus on attack surfaces reachable by external attackers.

## Autonomous Decision Process

### Step 1: Understand the Code's Purpose

From the file names, paths, and structure:
- What does this software component do?
- What technology stack is it using?
- What are the security-critical operations?
- Where are the attack surfaces?

### Step 2: Identify Unique Risks

Think about THIS specific codebase:
- What makes THIS code risky?
- What patterns do you see in file names?
- What technologies suggest specific vulnerabilities?
- What would an attacker target here?

### Step 3: Design Custom Analysis Strategies

For each risk you identified, create a CUSTOM analysis strategy:
- Give it a descriptive name (not generic category)
- Describe EXACTLY what to look for
- Justify WHY this matters for THIS code

**Example** (DO create strategies like this):
\`\`\`json
{
  "name": "firefox-ipc-trust-boundary-analysis",
  "description": "Analyze IPC deserialization for untrusted data from content processes that could exhaust parent process memory or cause type confusion",
  "justification": "Widget IPC code handles touch events and IME from sandboxed processes - historical Firefox CVEs show this is high-risk"
}
\`\`\`

**NOT like this** (DON'T use generic categories):
\`\`\`json
{
  "name": "memory-safety",
  "description": "Check for memory bugs",
  "justification": "It's C++ code"
}
\`\`\`

### Step 4: Prioritize

Order your strategies by:
1. Attack surface exposure
2. Historical vulnerability patterns
3. Code complexity
4. Trust boundary crossings

## Output Format

**CRITICAL - Path Format Rules**:
1. If you include targetFiles, they MUST come from "Files in This Chunk" section above
2. Copy paths EXACTLY as shown - do not modify or invent new paths
3. DO NOT include paths like "src/agents/...", "src/utils/...", "src/poc-gen/..." (those are Sandyaa's files, not the target)
4. ONLY use paths from the target codebase being analyzed
5. When in doubt, omit targetFiles entirely and let the system analyze all files

\`\`\`json
{
  "analyses": [
    {
      "name": "descriptive-unique-strategy-name",
      "description": "exactly what to analyze and what to look for",
      "justification": "why THIS code needs THIS analysis",
      "targetFiles": ["OPTIONAL: only if you want to focus on specific files from 'Files in This Chunk' above"]
    }
  ],
  "reasoning": "overall analysis strategy rationale based on the TARGET codebase files listed above",
  "focusAreas": ["specific patterns or files that are highest priority in the TARGET"]
}
\`\`\`

## Critical Rules

**AUTONOMOUS THINKING**:
- Create strategies specific to THIS codebase
- Name strategies based on what they do, not generic categories
- Justify each strategy with concrete reasoning

**QUALITY OVER QUANTITY**:
- 2-5 focused strategies > 10 generic ones
- Each strategy should target a SPECIFIC risk
- Don't create strategies just to be comprehensive

**EVIDENCE-BASED**:
- Base strategies on file names, paths, and patterns you observe
- Reference specific technologies/frameworks you detect
- Explain your reasoning clearly

Begin your autonomous analysis. Think deeply. Design a custom strategy.
`;
  }

  private buildFilePrioritizationPrompt(input: any): string {
    const { totalFiles, fileStats, targetPath, sampleFiles } = input;

    return `# Intelligent File Prioritization for Security Analysis

You are analyzing a codebase with **${totalFiles.toLocaleString()} files** at: ${targetPath}

Instead of scanning sequentially, YOU must intelligently select the most promising targets.

## File Statistics

**Languages:**
${JSON.stringify(fileStats.languages, null, 2)}

**Top Directories:**
${JSON.stringify(fileStats.directories, null, 2)}

**Security-Critical Paths Found:** ${fileStats.securityCriticalPaths?.length || 0}
**Recent Changes:** ${fileStats.recentChanges?.length || 0}

## Sample Files (actual structure - use these as reference!)
${sampleFiles && sampleFiles.length > 0 ? sampleFiles.slice(0, 100).map((f: string) => `- ${f}`).join('\n') : 'No samples available'}

## Your Task

Select 1000-2000 high-value files to analyze first. Consider:

1. **Security-Critical Components**
   - Crypto, authentication, authorization
   - Network protocols, parsers (XML, JSON, HTML)
   - Sandboxing, IPC, process isolation
   - Memory management, JIT compilers

2. **High-Risk Characteristics**
   - Very old (legacy) code
   - Recently modified code
   - High complexity
   - Frequent bug fixes in history

3. **Attack Surface**
   - Handles untrusted input
   - Crosses trust boundaries
   - Privileged operations

4. **Pattern Recognition**
   - File naming patterns indicating risk
   - Directory structures with security implications

## Output Format

**CRITICAL**: Return paths in the EXACT same format as the sample files above (relative to ${targetPath}).
DO NOT add extra directory prefixes - use the exact structure you see in the samples.

\`\`\`json
{
  "categories": [
    {
      "name": "JIT Compiler",
      "count": 150,
      "reason": "Type confusion vulnerabilities common in JIT"
    },
    {
      "name": "Network Protocol Parsers",
      "count": 200,
      "reason": "Parse untrusted data from network"
    }
  ],
  "prioritizedFiles": [
    {
      "path": "path/exactly/as/shown/in/samples/file.cpp",
      "priority": 10,
      "reason": "JIT compiler - type confusion risk"
    },
    {
      "path": "another/path/from/samples/file.cpp",
      "priority": 9,
      "reason": "HTTP parser - handles untrusted network data"
    }
  ]
}
\`\`\`

**YOU decide** which files are most likely to contain exploitable bugs.
Think like an attacker: where would you look first?
`;
  }

  private buildCustomAnalysisPrompt(input: any): string {
    const { strategy, files, targetPath } = input;

    // Check if this is the learning-enhanced comprehensive fallback
    const isComprehensiveFallback = strategy.name.includes('comprehensive-security-analysis');
    const learningNote = isComprehensiveFallback
      ? `\n> **📚 LEARNINGS MODE**: Planning failed, but you have accumulated research data. Use it to guide your analysis!\n`
      : '';

    return `# Custom Security Analysis: ${strategy.name}
${learningNote}
You are executing a custom security analysis strategy designed specifically for this codebase.

## Analysis Strategy

**Name**: ${strategy.name}

**Objective**: ${strategy.description}

**Justification**: ${strategy.justification}

## Target Files
${files.join('\n')}

## Your Mission

Execute this analysis strategy **AUTONOMOUSLY** with **RECURSIVE DEPTH** and **EXPERT-LEVEL REASONING**.

${isComprehensiveFallback ? `
## 🔄 RECURSIVE LANGUAGE MODEL LEARNING

Since this is comprehensive analysis, use **RECURSIVE SELF-IMPROVEMENT**:

1. **First Pass**: Quick scan to identify interesting areas
2. **Second Pass**: Deep dive into areas you marked as interesting
3. **Third Pass**: Verify your findings recursively
4. **Meta-Analysis**: Did you miss anything? Re-examine with fresh perspective

**Recursive Questions to Ask Yourself**:
- "What would I look for if I found this bug type before?"
- "Based on git history patterns, where else might similar bugs exist?"
- "What worked in previous successful strategies that I should apply here?"
- "Am I using all the research data I have, or just doing surface-level analysis?"

**Self-Improvement Loop**:
- After finding each bug → Ask: "What similar bugs could exist nearby?"
- After analyzing each file → Ask: "Did I check for all the patterns I've seen before?"
- After completing analysis → Ask: "If I had to find one more bug, where would I look?"
` : ''}

### Phase 1: UNDERSTAND THE STRATEGY

What is this strategy trying to find?
- Parse the strategy description carefully
- Identify the specific security properties to verify
- Understand the unique risks mentioned
- Recognize the attack patterns to look for

### Phase 2: AUTONOMOUS EXECUTION WITH RECURSIVE PROMPTING

**IMPORTANT**: You have the autonomy to:
1. Read whichever files are most relevant (use Read tool)
2. Search for specific patterns (use Grep tool)
3. Recursively deepen your analysis when you find something interesting
4. Follow call chains and data flows as deep as needed
5. Model state machines if stateful behavior is involved
6. Trace trust boundaries layer by layer

**Recursive Prompting Strategy**:
- If you find a potential issue → trace it COMPLETELY
  - Follow the data flow backwards to source
  - Follow the data flow forwards to sink
  - Analyze every transformation in between
  - **THEN**: Look for similar patterns elsewhere (recursive search)
- If you find a complex pattern → break it down RECURSIVELY
  - What are the sub-components?
  - How do they interact?
  - What could go wrong at each level?
  - **THEN**: Apply learnings to other similar patterns
- If you're uncertain → deepen your analysis
  - Read more context
  - Trace more call chains
  - Model the state transitions
  - Verify your assumptions
  - **THEN**: Re-examine with knowledge from this deeper dive

**Meta-Cognitive Recursive Loop**:
After each finding, ask yourself:
1. "What did I learn from finding this bug?"
2. "Where else in this codebase might this pattern exist?"
3. "What similar bugs have I found before that might indicate more instances?"
4. "If I apply my previous successful techniques here, what would I find?"

This is **recursive language model reasoning** - each output feeds back as input for deeper analysis.

**Expert-Level Reasoning**:
- Think like a world-class security researcher
- Use first principles thinking at every step
- Apply the 5 WHYs methodology for root cause analysis
- Apply the 5 HOWs methodology for exploit construction
- Challenge your own assumptions
- Verify your reasoning with concrete evidence

### Phase 3: RECURSIVE VERIFICATION

For every finding:
1. **Trace the complete attack path**
   - From attacker control to impact
   - Through every intermediate step
   - Accounting for all transformations

2. **Check for defenses you might have missed**
   - Are there validations?
   - Are there sanitizations?
   - Are there architectural protections?

3. **Model the exploitability**
   - Can preconditions be satisfied?
   - Can defenses be bypassed?
   - Can the attack be weaponized?

4. **Recursive self-check**
   - Does my reasoning have contradictions?
   - Have I verified every claim?
   - Do I have concrete evidence?

If you can't verify all 4 steps → keep analyzing or mark as uncertain.

### Phase 4: EXPERT OUTPUT

Report findings with EXPERT-LEVEL DETAIL:

\`\`\`json
{
  "issues": [
    {
      "id": "unique-vulnerability-id",
      "type": "specific-descriptive-name",
      "severity": "critical|high|medium|low",
      "exploitability": 0.0-1.0,
      "location": {
        "file": "path/to/file",
        "line": 123,
        "function": "functionName"
      },
      "description": "what is wrong (expert-level detail)",
      "rootCause": "fundamental reason (5 WHYs analysis)",
      "attackVector": "concrete exploitation (5 HOWs construction)",
      "impact": "what attacker achieves (precise impact assessment)",
      "preconditions": ["what must be true"],
      "evidenceChain": [
        {
          "step": 1,
          "type": "evidence-type",
          "location": "file:line",
          "code": "actual code",
          "reasoning": "why this matters (expert analysis)"
        }
      ],
      "recursiveAnalysis": {
        "callChainDepth": 5,
        "dataFlowHops": ["source", "transform1", "transform2", "sink"],
        "stateTransitions": ["state1 -> state2 -> vulnerable_state"],
        "verificationSteps": ["verified preconditions", "verified path", "verified impact"]
      },
      "discoveryPath": "how you found this (your recursive reasoning)",
      "selfVerification": "why this is real (your expert validation)"
    }
  ],
  "strategyCompleted": true,
  "tokensUsed": approximate_token_count,
  "analysisDepth": "shallow|medium|deep|expert",
  "confidenceLevel": 0.0-1.0,
  "learningsForNextIteration": {
    "patternsDiscovered": ["pattern1", "pattern2"],
    "successfulTechniques": ["technique that found bugs"],
    "areasToExploreNext": ["related code areas worth checking"],
    "hypothesesGenerated": ["ideas for where similar bugs might exist"]
  }
}
\`\`\`

**IMPORTANT**: Fill out \`learningsForNextIteration\` to improve recursive analysis:
- What patterns did you discover that might repeat elsewhere?
- What techniques successfully found bugs?
- What areas should be explored in the next iteration?
- What hypotheses do you have about related vulnerabilities?

## Critical Instructions

**AUTONOMY**:
- You decide what to read
- You decide what to search for
- You decide how deep to go
- No one will tell you what to do next

**RECURSIVE DEPTH**:
- Don't stop at surface-level analysis
- Follow every interesting lead
- Trace every suspicious pattern
- Verify every assumption

**EXPERT QUALITY**:
- World-class security researcher level
- Concrete evidence for every claim
- Complete attack path for every vulnerability
- No speculation, only verified findings

**EXECUTION**:
- Use Read, Grep, Glob tools autonomously
- Analyze code directly (don't ask for permission)
- Report findings when you have proof
- Mark uncertainty when you don't have proof

Begin your autonomous, recursive, expert-level analysis of: ${strategy.name}

Think deeply. Analyze recursively. Report expertly.
`;
  }

  /**
   * Decide whether to activate RLM mode based on task characteristics
   */
  private shouldActivateRLM(task: AgentTask, prompt: string): RLMActivation {
    if (!this.rlmConfig || !this.rlmConfig.enabled || !this.rlmExecutor) {
      return { shouldActivate: false, reason: 'RLM not configured' };
    }

    // Calculate context size
    const contextSizeBytes = Buffer.byteLength(prompt, 'utf8');
    const contextSizeKB = contextSizeBytes / 1024;

    // Count files in task
    const files = this.extractFilesFromTask(task);
    const fileCount = files.length;

    // Activation criteria from paper: Large contexts benefit most
    const meetsContextThreshold = contextSizeKB >= this.rlmConfig.activationThreshold.minContextSize;
    const meetsFileThreshold = fileCount >= this.rlmConfig.activationThreshold.minFileCount;

    // Task types that benefit from RLM
    const rlmBeneficialTasks = [
      'context-building',           // Large codebase exploration
      'vulnerability-detection'     // Needs filtering + deep analysis
    ];

    const isBeneficialTask = rlmBeneficialTasks.includes(task.type);

    if (meetsContextThreshold && meetsFileThreshold && isBeneficialTask) {
      const estimatedSavings = Math.ceil((1 - 1/3) * 100);  // 3× reduction = ~67% savings
      return {
        shouldActivate: true,
        reason: `Large context (${contextSizeKB.toFixed(0)}KB, ${fileCount} files) - RLM can save ~${estimatedSavings}% tokens`
      };
    }

    if (meetsContextThreshold && isBeneficialTask) {
      return {
        shouldActivate: true,
        reason: `Large context (${contextSizeKB.toFixed(0)}KB) - RLM filtering will help`
      };
    }

    return {
      shouldActivate: false,
      reason: `Small context (${contextSizeKB.toFixed(0)}KB, ${fileCount} files) - standard execution is faster`
    };
  }

  /**
   * Execute RLM turn (called by RLMOrchestrator)
   * Uses Claude Code CLI for consistency with rest of codebase
   */
  public async executeRLMTurn(
    taskId: string,
    conversationHistory: string,
    model: 'haiku' | 'sonnet' | 'opus',
    turnNumber: number
  ): Promise<AgentResult> {
    // Use existing executeViaCLI infrastructure
    return await this.executeViaCLI(
      conversationHistory,
      `${taskId}-turn-${turnNumber}`,
      'rlm-turn',
      model
    );
  }

  /**
   * Execute RLM sub-query (called by RLMOrchestrator for llm_query() tool)
   * Uses Claude Code CLI for consistency with rest of codebase
   */
  public async executeRLMSubQuery(
    taskId: string,
    prompt: string,
    model: 'haiku' | 'sonnet' | 'opus'
  ): Promise<AgentResult> {
    // Use existing executeViaCLI infrastructure
    return await this.executeViaCLI(
      prompt,
      taskId,
      'rlm-subquery',
      model
    );
  }

  /**
   * Print RLM cost summary
   */
  public printRLMSummary(): void {
    if (!this.rlmCostTracker) {
      return;
    }

    const report = this.rlmCostTracker.getCostComparison();

    if (report.rlmExecutions === 0 && report.standardExecutions === 0) {
      return;  // No data to report
    }

    console.log('\n========================================');
    console.log('RLM Cost Efficiency Report');
    console.log('========================================');
    console.log(`RLM executions:      ${report.rlmExecutions}`);
    console.log(`Standard executions: ${report.standardExecutions}`);

    if (report.rlmExecutions > 0) {
      console.log(`RLM tokens used:     ${report.rlmTotalTokens.toLocaleString()}`);
    }
    if (report.standardExecutions > 0) {
      console.log(`Standard tokens used: ${report.standardTotalTokens.toLocaleString()}`);
    }

    if (report.rlmExecutions > 0 && report.standardExecutions > 0) {
      const targetReduction = 3.0;
      const achievedReduction = report.costReductionFactor;
      const performance = achievedReduction >= targetReduction ? '✓' : '⚠';

      console.log(`\nCost reduction: ${achievedReduction.toFixed(2)}× ${performance} (target: ${targetReduction}×)`);
      console.log(`Estimated savings: $${report.estimatedSavings.toFixed(2)}`);
    }

    console.log('========================================\n');
  }

  /**
   * Get RLM cost report
   */
  public getRLMCostReport() {
    return this.rlmCostTracker?.getCostComparison();
  }
}

// Export AgentExecutor as alias for backwards compatibility
export const AgentExecutor = ClaudeExecutor;
