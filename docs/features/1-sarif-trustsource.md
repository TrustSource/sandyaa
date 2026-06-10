# SARIF Export and TrustSource Integration

**What it does:** Exports Sandyaa findings as a SARIF 2.1.0 file and optionally uploads them directly to TrustSource.

## How it works

When you pass `--sarif` (or `--ts-upload`) on the command line, Sandyaa generates a `sarif-report.json` file in the scan output directory alongside the existing Markdown reports. The file conforms to SARIF schema version `2.1.0` and contains:

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

`--ts-upload` implies `--sarif` — you do not need to pass both flags.

## CLI Flags

| Flag | Type | Description |
|------|------|-------------|
| `--sarif` | boolean | Generate `sarif-report.json` in the findings directory. |
| `--ts-upload <module>` | string | Upload SARIF to TrustSource after the scan. The value is a module name or module UUID. Implies `--sarif`. Requires `TRUSTSOURCE_API_KEY`. |
| `--ts-project <project>` | string | TrustSource project name. Used with `--ts-upload` to auto-create the module inside the named project if it does not exist yet. |

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `TRUSTSOURCE_API_KEY` | When `--ts-upload` is used | — | Bearer token for the TrustSource API. |
| `TRUSTSOURCE_BASE_URL` | No | `https://app.trustsource.io` | Override the TrustSource base URL (for on-prem installations). |

## Example

```bash
# Generate SARIF only
sandyaa --sarif /path/to/project

# Upload by module name (searches existing modules in the company)
sandyaa --ts-upload my-module /path/to/project

# Upload by module name + project (auto-creates module inside project if needed)
sandyaa --ts-upload my-module --ts-project my-project /path/to/project

# Upload by module UUID (direct lookup — most unambiguous)
sandyaa --ts-upload 550e8400-e29b-41d4-a716-446655440000 /path/to/project

# Output location (whether uploading or not)
findings/<scan-name>/sarif-report.json
```

## Module resolution

The TrustSource API resolves the target module in this order of preference:

1. **`moduleId` (UUID)** — direct, unambiguous lookup. Pass a UUID as the `--ts-upload` value.
2. **`projectName` + `moduleName`** — the project must already exist; the module is auto-created within the project if it does not exist.
3. **`moduleName` alone** (no `--ts-project`) — the API searches existing modules in the company by name. The module is NOT created. If multiple modules match, the first one is used. If no module matches, the test is imported unattached.

Sandyaa detects whether the `--ts-upload` value is a UUID by matching it against `/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i`. If it matches, `moduleId` is sent; otherwise `moduleName` (and optionally `projectName`) is sent.

## Upload behaviour

- Module/project identifiers are sent as **URL query parameters** (e.g. `?moduleName=foo&projectName=bar`). The request body is the full SARIF JSON document.
- HTTP 2xx → prints a success message with the module info used.
- HTTP 4xx/5xx → prints the status code and response body as an error. If 404 and no `--ts-project` was given, Sandyaa prints an additional hint to add `--ts-project`.
- No retries — fail fast. The local SARIF file is always available even if the upload fails.

## Known limitations

- CWE mappings are not included in this release (planned as a follow-on task).
- The `--sarif` flag has no effect on the existing Markdown/JSON output structure.
