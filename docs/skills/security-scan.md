---
name: security-scan
description: "Run a Sandyaa security scan against a target codebase and summarize findings. Use this skill whenever the user says /security-scan, asks to scan a project for security vulnerabilities, wants to run Sandyaa, or asks for a security analysis of a codebase. Also trigger when the user mentions finding exploitable bugs, running a SAST scan, or checking code for vulnerabilities. Supports optional TrustSource upload."
---

# Sandyaa Security Scan

Run an autonomous security scan against a target codebase using Sandyaa. Sandyaa uses LLMs (Claude + Gemini) to find real exploitable vulnerabilities — not pattern-matching, but deep semantic analysis with attacker-control verification, recursive validation, and POC generation.

## Prerequisites

- Sandyaa is cloned and installed (`npm install` in the Sandyaa directory)
- Node.js >= 18
- Claude Code CLI installed and logged in
- For TrustSource upload: `TRUSTSOURCE_API_KEY` environment variable must be set

> **Important:** Edit the `SANDYAA_DIR` variable below to point to your Sandyaa installation path.

```
SANDYAA_DIR=/path/to/sandyaa
```

## Steps

### 1. Determine the target

Ask the user what to scan if not obvious from context. The target can be:
- The current working directory / project
- An explicit path to a codebase
- A git URL (Sandyaa will clone it)

If the user says "scan this project" or "scan the current repo", use the current working directory. Resolve the path to an absolute path.

### 2. Determine scan options

Check what the user wants:

- **Model**: Default is dynamic (Sandyaa picks per task). User can pin with `--model haiku|sonnet|opus`. Opus gives 1M context for large codebases but costs ~5x more.
- **SARIF output**: If the user mentions SARIF, TrustSource, or wants exportable results, add `--sarif`.
- **TrustSource upload**: If the user wants to upload to TrustSource, use `--ts-upload <module-name>` and optionally `--ts-project <project-name>`. Check that `TRUSTSOURCE_API_KEY` is set.
- **Fresh start**: If the user wants to ignore previous checkpoints, add `--fresh`.
- **Config**: Custom config via `-c <path>`. Default is `.sandyaa/config.yaml`.

### 3. Validate before running

Before starting the scan:
- Verify the target path exists (or is a valid git URL)
- If `--ts-upload` is requested, check that `TRUSTSOURCE_API_KEY` is set
- Warn the user that scans can take several minutes for large codebases

### 4. Run the scan

Execute Sandyaa:

```bash
npx tsx $SANDYAA_DIR/src/index.ts [options] <target>
```

Run this in the background with a 10-minute timeout. The scan produces significant output.

Examples:
```bash
# Basic scan
npx tsx $SANDYAA_DIR/src/index.ts /path/to/project

# With SARIF output
npx tsx $SANDYAA_DIR/src/index.ts --sarif /path/to/project

# With TrustSource upload
npx tsx $SANDYAA_DIR/src/index.ts --ts-upload my-module --ts-project my-project /path/to/project

# Pin to Opus for large codebase
npx tsx $SANDYAA_DIR/src/index.ts --model opus --sarif /path/to/project

# Fresh scan ignoring checkpoint
npx tsx $SANDYAA_DIR/src/index.ts --fresh /path/to/project
```

### 5. Summarize results

When the scan completes, read the output and present a summary to the user:

1. **Read the scan output** from the background task output file. Look for:
   - Total files scanned
   - Number of findings and their severities (CRITICAL, HIGH, MEDIUM, LOW)
   - Verification status (verified, uncertain, contradicted)
   - POC validation results
   - Any upload results if `--ts-upload` was used

2. **Read the findings manifest** if it exists:
   ```bash
   find findings/ -name "MANIFEST.json" -newer <scan-start> | head -1
   ```

3. **Read the SARIF report** if `--sarif` was used:
   ```bash
   find findings/ -name "sarif-report.json" -newer <scan-start> | head -1
   ```

4. **Present a summary table** like:
   ```
   Sandyaa Scan Results: <target>
   ----------------------------------------
   Files scanned:    142
   Findings:         5 (2 critical, 2 high, 1 medium)
   Verified:         3
   POC validated:    1
   Duration:         4.2 minutes

   Top findings:
   1. [CRITICAL] SQL injection at api/handler.js:45 - VERIFIED, POC validated
   2. [HIGH] Path traversal at utils/file.js:89 - VERIFIED
   ...
   ```

5. **If findings exist**, offer to show details:
   - "Want me to show the full analysis for any specific finding?"
   - "The SARIF report is at findings/<scan>/sarif-report.json"

### 6. Handle errors

- If the scan times out: inform the user, note that partial results may be in `findings/` and checkpoint is saved for resume
- If POC generation is refused by Claude (safety refusal): this is expected for some exploit types — the finding still stands, just without a POC
- If TrustSource upload fails: show the error, remind user the local SARIF file is still available

## Notes

- Sandyaa will NOT scan its own source directory (hardcoded safety guard)
- Scans are checkpointed — if interrupted, running the same target again will offer to resume
- Large codebases (>1000 files) trigger a two-phase approach: high-priority targets first, then systematic coverage
