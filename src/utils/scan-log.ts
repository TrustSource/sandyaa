import * as fs from 'fs/promises';
import * as path from 'path';
import * as crypto from 'crypto';

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
    try {
      const dir = path.dirname(this.logFile);
      await fs.mkdir(dir, { recursive: true });
      const line = JSON.stringify({ ...entry, ts: new Date().toISOString() }) + '\n';
      await fs.appendFile(this.logFile, line, 'utf-8');
    } catch (error) {
      console.warn('Failed to append to scan log:', error);
    }
  }

  /** Read all entries and materialise a resume-ready ScanState. */
  async loadState(): Promise<ScanState> {
    const state: ScanState = {
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
          switch (entry.step) {
            case 'prioritize':
              state.prioritizedFiles = entry.result?.files ?? null;
              break;
            case 'detect':
              if (entry.files) {
                const key = ScanLog.chunkKey(entry.files);
                state.detectedChunks.set(key, {
                  files: entry.files,
                  findings: entry.result?.findings ?? [],
                });
              }
              break;
            case 'verify':
              if (entry.finding_id) {
                state.verifiedFindings.set(entry.finding_id, entry.result);
              }
              break;
            case 'poc':
              if (entry.finding_id) {
                state.pocResults.set(entry.finding_id, entry.result);
              }
              break;
            case 'sarif':
              state.sarifWritten = entry.result?.written === true;
              break;
          }
        } catch {
          // Skip malformed lines — partial writes don't corrupt prior entries
        }
      }
    } catch {
      // File doesn't exist yet
    }

    return state;
  }

  /** Stable, order-independent key for a set of file paths. */
  static chunkKey(files: string[]): string {
    return [...files].sort().join('\0');
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
