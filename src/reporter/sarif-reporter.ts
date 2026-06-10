import { Vulnerability } from '../detector/vulnerability-detector.js';
import { Config } from '../orchestrator/orchestrator.js';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as crypto from 'crypto';
import chalk from 'chalk';

const SARIF_SCHEMA = 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json';
const TOOL_NAME = 'Sandyaa';
const TOOL_VERSION = '1.0.0';
const TOOL_INFO_URI = 'https://github.com/ssk/sandyaa';

export class SarifReporter {
  private config: Config;
  private findingsDir: string;
  private targetPath: string;

  constructor(config: Config, targetPath: string) {
    this.config = config;
    this.targetPath = path.resolve(targetPath);
    const scanName = this.createScanName(targetPath);
    this.findingsDir = path.join(config.output.findings_dir, scanName);
  }

  async generate(vulnerabilities: Vulnerability[]): Promise<void> {
    await fs.mkdir(this.findingsDir, { recursive: true });
    const sarif = this.buildSarif(vulnerabilities);
    const outputPath = path.join(this.findingsDir, 'sarif-report.json');
    await fs.writeFile(outputPath, JSON.stringify(sarif, null, 2));
    console.log(chalk.cyan('SARIF report:'), outputPath);
  }

  private createScanName(targetPath: string): string {
    const baseName = path.basename(targetPath);
    const hash = crypto.createHash('sha256')
      .update(path.resolve(targetPath))
      .digest('hex')
      .substring(0, 8);
    return `${baseName}-${hash}`;
  }

  private buildSarif(vulnerabilities: Vulnerability[]): object {
    // Deduplicate rules by vulnerability type — multiple findings of the same
    // type reference the same rule by index.
    const ruleMap = new Map<string, number>();
    const rules: object[] = [];

    for (const vuln of vulnerabilities) {
      if (!ruleMap.has(vuln.type)) {
        ruleMap.set(vuln.type, rules.length);
        rules.push({
          id: vuln.type,
          fullDescription: { text: vuln.description },
        });
      }
    }

    const results = vulnerabilities.map(vuln => this.buildResult(vuln, ruleMap));

    return {
      version: '2.1.0',
      $schema: SARIF_SCHEMA,
      runs: [
        {
          tool: {
            driver: {
              name: TOOL_NAME,
              version: TOOL_VERSION,
              informationUri: TOOL_INFO_URI,
              rules,
            },
          },
          results,
        },
      ],
    };
  }

  private buildResult(vuln: Vulnerability, ruleMap: Map<string, number>): object {
    const ruleIndex = ruleMap.get(vuln.type) ?? 0;
    const level = this.mapSeverityToLevel(vuln.severity);

    // Combine attackVector and impact into the result message
    let messageText = vuln.attackVector || '';
    if (vuln.impact) {
      messageText += messageText ? `\n\nImpact: ${vuln.impact}` : `Impact: ${vuln.impact}`;
    }

    const relativeUri = this.makeRelativeUri(vuln.location.file);

    const locations: object[] = [
      {
        physicalLocation: {
          artifactLocation: {
            uri: relativeUri,
            uriBaseId: '%SRCROOT%',
          },
          region: {
            startLine: vuln.location.line || 1,
          },
        },
        logicalLocations: [
          {
            name: vuln.location.function || '',
            kind: 'function',
          },
        ],
      },
    ];

    // Each Evidence in evidenceChain becomes a threadFlowLocation
    const codeFlows: object[] = [];
    if (vuln.evidenceChain && vuln.evidenceChain.length > 0) {
      const threadFlowLocations = vuln.evidenceChain.map(evidence => {
        const parsed = this.parseEvidenceLocation(evidence.location);
        const physicalLocation: Record<string, object> = {
          artifactLocation: {
            uri: parsed.uri,
            uriBaseId: '%SRCROOT%',
          },
        };
        if (parsed.line !== undefined) {
          physicalLocation.region = { startLine: parsed.line };
        }
        return {
          location: {
            physicalLocation,
            message: { text: evidence.reasoning || '' },
          },
        };
      });

      codeFlows.push({
        threadFlows: [{ locations: threadFlowLocations }],
      });
    }

    // Property bag: all Sandyaa-specific fields not covered by SARIF standard fields
    const properties: Record<string, unknown> = {
      exploitability: vuln.exploitability,
      verificationStatus: vuln.verificationStatus,
      confidence: vuln.confidence,
      needsManualReview: vuln.needsManualReview ?? false,
    };

    if (vuln.attackerControlled !== undefined) {
      properties.attackerControlled = vuln.attackerControlled;
    }
    if (vuln.blastRadius !== undefined) {
      properties.blastRadius = vuln.blastRadius;
    }
    if (vuln.exploitationDependencies !== undefined) {
      properties.exploitationDependencies = vuln.exploitationDependencies;
    }
    if (vuln.blindspotCategory !== undefined) {
      properties.blindspotCategory = vuln.blindspotCategory;
    }
    if (vuln.regression !== undefined) {
      properties.regression = vuln.regression;
    }
    if (vuln.poc !== undefined) {
      properties.pocValidated = vuln.poc.validated;
      properties.pocLanguage = vuln.poc.language;
    }

    const result: Record<string, unknown> = {
      ruleId: vuln.type,
      ruleIndex,
      level,
      message: { text: messageText },
      locations,
      properties,
    };

    if (codeFlows.length > 0) {
      result.codeFlows = codeFlows;
    }

    return result;
  }

  private mapSeverityToLevel(severity: string): string {
    if (severity === 'critical' || severity === 'high') return 'error';
    if (severity === 'medium') return 'warning';
    return 'note';
  }

  // Returns a forward-slash URI relative to the scan target root
  private makeRelativeUri(filePath: string): string {
    if (!filePath) return '';
    const rel = path.isAbsolute(filePath)
      ? path.relative(this.targetPath, filePath)
      : filePath;
    return rel.split(path.sep).join('/');
  }

  // Parses "file.js:123" or plain "file.js" evidence locations
  private parseEvidenceLocation(location: string): { uri: string; line: number | undefined } {
    if (!location) return { uri: '', line: undefined };
    const lastColon = location.lastIndexOf(':');
    if (lastColon > 0) {
      const potentialLine = parseInt(location.substring(lastColon + 1), 10);
      if (!isNaN(potentialLine) && potentialLine > 0) {
        return {
          uri: this.makeRelativeUri(location.substring(0, lastColon)),
          line: potentialLine,
        };
      }
    }
    return { uri: this.makeRelativeUri(location), line: undefined };
  }
}
