# SARIF Export and TrustSource Integration

**What it does:** Exports Sandyaa findings as a SARIF 2.1.0 file so you can import them into TrustSource (or any other SARIF-consuming tool).

## How it works

When you pass `--sarif` on the command line, Sandyaa generates a `sarif-report.json` file in the scan output directory alongside the existing Markdown reports. The file conforms to SARIF schema version `2.1.0` and contains:

- A `tool.driver` section identifying Sandyaa (name, version `1.0.0`, info URI).
- A deduplicated `rules` array — one entry per unique vulnerability type found in the scan. Multiple findings of the same type reference the same rule by index.
- A `results` array — one entry per finding — with:
  - `level`: `error` for critical/high severity, `warning` for medium, `note` for low.
  - `locations`: the primary file and line number, plus the function name as a logical location.
  - `codeFlows`: each entry in the evidence chain becomes a `threadFlowLocation` with its physical location and the reasoning text as a message.
  - `properties`: Sandyaa-specific fields that have no standard SARIF mapping — `exploitability`, `verificationStatus`, `confidence`, `needsManualReview`, `attackerControlled`, `blastRadius`, `exploitationDependencies`, `blindspotCategory`, `regression`, `pocValidated`, `pocLanguage`.
- All `artifactLocation.uri` values are relative to the scan target root (not absolute paths), with `uriBaseId` set to `%SRCROOT%`.

## Configuration

No configuration file changes are needed. The `--sarif` flag is additive — it generates the SARIF file in addition to the existing Markdown and `MANIFEST.json` output. It does not replace them.

## Example

```bash
# Scan with SARIF output enabled
sandyaa --sarif /path/to/project

# Output location
findings/<scan-name>/sarif-report.json
```

## Uploading to TrustSource

TrustSource accepts SARIF via its REST API. After the scan completes:

```bash
curl -X POST "https://app.trustsource.io/api/v2/sarif/{projectId}" \
  -H "Authorization: Bearer <API_TOKEN>" \
  -H "Content-Type: application/json" \
  -d @findings/<scan-name>/sarif-report.json
```

- `{projectId}` — your TrustSource project identifier (visible in the project URL).
- `<API_TOKEN>` — an API token from your TrustSource account settings.

TrustSource maps the imported results to modules in its Open Threat Model (OTM) using the file paths in `artifactLocation.uri`.

## Known limitations

- CWE mappings are not included in this release (planned as a follow-on task).
- The Sandyaa tool does not call the TrustSource API directly — upload is a manual post-scan step.
- The `--sarif` flag has no effect on the existing Markdown/JSON output structure.
