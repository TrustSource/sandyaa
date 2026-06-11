import * as fs from 'fs/promises';
import * as path from 'path';
import * as crypto from 'crypto';
import chalk from 'chalk';

export type ScanLogStepName = 'prioritize' | 'detect' | 'verify' | 'poc' | 'sarif';

export interface ScanLogEntry {
  step: ScanLogStepName;
  ts: string;
  chunk?: number;
  files?: string[];
  finding_id?: string;
  result: any;
}

export interface DetectedChunk {
  files: string[];
  findings: any[];
}

export interface ScanState {
  prioritizedFiles: string[] | null;
  /** Keyed by ScanLog.chunkKey(files) — order-independent. */
  detectedChunks: Map<string, DetectedChunk>;
  /** finding_id → saved verify result */
  verifiedFindings: Map<string, any>;
  /** finding_id → saved poc result */
  pocResults: Map<string, any>;
  sarifWritten: boolean;
}

/**
 * Append-only JSONL scan log.  Each completed sub-step appends one line:
 *
 *   {"step":"prioritize","result":{"files":[...]},"ts":"..."}
 *   {"step":"detect","chunk":1,"files":[...],"result":{"findings":[...]},"ts":"..."}
 *   {"step":"verify","finding_id":"CTAE-001","result":{"status":"verified"},"ts":"..."}
 *   {"step":"poc","finding_id":"CTAE-001","result":{"status":"success","poc":{...}},"ts":"..."}
 *
 * On resume: read all lines, replay completed steps, continue from the first
 * missing one.  Partial writes don't corrupt earlier state.
 */
export class ScanLog {
  private logFile: string;
  private writeFailed = false;
  private memState: ScanState = {
    prioritizedFiles: null,
    detectedChunks: new Map(),
    verifiedFindings: new Map(),
    pocResults: new Map(),
    sarifWritten: false,
  };

  constructor(logFile: string) {
    this.logFile = logFile;
  }

  static getLogFile(targetPath: string, sandyaaDir: string): string {
    const hash = crypto.createHash('sha256')
      .update(path.resolve(targetPath))
      .digest('hex')
      .substring(0, 12);
    return path.join(sandyaaDir, `scan-log-${hash}.jsonl`);
  }

  /** Append one step entry.  Safe to call concurrently — each line is atomic. */
  async append(entry: Omit<ScanLogEntry, 'ts'>): Promise<void> {
    const full: ScanLogEntry = { ...entry, ts: new Date().toISOString() } as ScanLogEntry;
    this.applyToMemState(full);
    try {
      const dir = path.dirname(this.logFile);
      await fs.mkdir(dir, { recursive: true });
      const line = JSON.stringify(full) + '\n';
      await fs.appendFile(this.logFile, line, 'utf-8');
    } catch (error) {
      if (!this.writeFailed) {
        this.writeFailed = true;
        console.error(chalk.red(`[scan-log] Write failed — resume capability lost for this run: ${error}`));
      }
    }
  }

  /** Return the current in-memory state (updated on every append, no disk read). */
  getState(): ScanState {
    return this.memState;
  }

  /** Read all entries from disk and materialise a resume-ready ScanState.
   *  Also populates the in-memory state so subsequent getState() calls are free. */
  async loadState(): Promise<ScanState> {
    this.memState = {
      prioritizedFiles: null,
      detectedChunks: new Map(),
      verifiedFindings: new Map(),
      pocResults: new Map(),
      sarifWritten: false,
    };

    try {
      const content = await fs.readFile(this.logFile, 'utf-8');
      const lines = content.split('\n').filter((l: string) => l.trim());

      for (const line of lines) {
        try {
          const entry: ScanLogEntry = JSON.parse(line);
          this.applyToMemState(entry);
        } catch {
          // Skip malformed lines — partial writes don't corrupt prior entries
        }
      }
    } catch {
      // File doesn't exist yet
    }

    return this.memState;
  }

  private applyToMemState(entry: ScanLogEntry): void {
    switch (entry.step) {
      case 'prioritize':
        this.memState.prioritizedFiles = entry.result?.files ?? null;
        break;
      case 'detect':
        if (entry.files) {
          const key = ScanLog.chunkKey(entry.files);
          this.memState.detectedChunks.set(key, {
            files: entry.files,
            findings: entry.result?.findings ?? [],
          });
        }
        break;
      case 'verify':
        if (entry.finding_id) {
          this.memState.verifiedFindings.set(entry.finding_id, entry.result);
        }
        break;
      case 'poc':
        if (entry.finding_id) {
          this.memState.pocResults.set(entry.finding_id, entry.result);
        }
        break;
      case 'sarif':
        this.memState.sarifWritten = entry.result?.written === true;
        break;
    }
  }

  /** Stable, order-independent key for a set of file paths.
   *  Normalises to absolute forward-slash paths so relative vs. absolute
   *  and Windows vs. POSIX paths all produce the same key. */
  static chunkKey(files: string[]): string {
    return [...files]
      .map(f => path.resolve(f).split(path.sep).join('/'))
      .sort()
      .join('\0');
  }

  async exists(): Promise<boolean> {
    try {
      await fs.access(this.logFile);
      return true;
    } catch {
      return false;
    }
  }

  async clear(): Promise<void> {
    try {
      await fs.unlink(this.logFile);
    } catch {
      // Ignore
    }
  }
}
