# Sandyaa

Autonomous security bug hunter — scans codebases for real exploitable vulnerabilities using LLMs (Claude + Gemini) instead of traditional static analysis.

## Tech Stack

- **Language**: TypeScript (ESM, Node.js >= 18)
- **UI**: Ink (React for terminal) for dashboard
- **LLM Integration**: Anthropic SDK (`@anthropic-ai/sdk`), Claude Code CLI subprocess, Gemini API
- **CLI**: Commander.js

## Build & Run

```bash
npm install          # install dependencies
npm run build        # tsc → dist/
npm run start -- <target>   # run via tsx (dev)
npx sandyaa <target>        # run built version
```

No test suite exists yet.

## Architecture

The tool runs a multi-phase pipeline orchestrated by `src/orchestrator/orchestrator.ts`:

1. **File Scanning** → `src/utils/file-scanner.ts` (git-based), `src/utils/file-prioritizer.ts`
2. **Context Building** → `src/analyzer/context-analyzer.ts`, `src/analyzer/analysis-planner.ts`
3. **Vulnerability Detection** → `src/detector/vulnerability-detector.ts`, `src/detector/attacker-control-analyzer.ts`
4. **Recursive Verification** → `src/recursive/recursive-strategy.ts` (8 strategies: call-chain-tracing, self-verification, contradiction-detection, etc.)
5. **POC Generation & Validation** → `src/poc-gen/poc-generator.ts`
6. **Blast Radius & Regression** → `src/analyzer/blast-radius.ts`, `src/analyzer/regression-detector.ts`
7. **Reporting** → `src/reporter/reporter.ts` (Markdown + JSON manifest)

### Key abstractions

- `ModelExecutor` (`src/agents/model-executor.ts`): Multi-provider executor abstracting Claude/Gemini with auto-fallback on rate limits
- `ClaudeExecutor` (`src/agents/agent-executor.ts`): Claude-specific executor, uses CLI subprocess (`claude --print`) or Anthropic SDK
- `DynamicChunker` (`src/utils/dynamic-chunker.ts`): Adapts chunk sizes based on learned metrics
- `Checkpoint` (`src/utils/checkpoint.ts`): Persists scan progress for resume capability

### Data model

The core type is `Vulnerability` (defined in `src/detector/vulnerability-detector.ts`) which flows through all phases and gets enriched with:
- `attackerControlled` (entry point, data flow path)
- `verificationStatus` (verified/uncertain/contradicted)
- `blastRadius` (call sites, affected systems)
- `exploitationDependencies` (prerequisites, complexity)
- `poc` (generated exploit code + validation status)

## Conventions

- Config via `.sandyaa/config.yaml` (YAML, snake_case keys)
- Findings output to `findings/` directory with per-scan subdirectories
- Checkpointing to `.sandyaa/checkpoint-<hash>.json`
- Version is `1.0.0` (in `package.json` and `src/index.ts`)

## Constraints

- The tool must never scan its own source directory (guard in `src/index.ts`)
- All Claude CLI calls must run with the target directory as CWD (via `ClaudeExecutor.setGlobalTargetPath`)
- Findings are never silently discarded — contradicted/uncertain findings are kept and marked for review
