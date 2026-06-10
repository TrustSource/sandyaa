# Documentation Style Guide

These guidelines apply to all user-facing documentation produced by Dana (and reviewed by Paul). They ensure a consistent, professional documentation experience across all EACG projects.

## Language

- **Primary language: English** (US spelling). Translations are handled separately — never mix languages.
- Write in **active voice**, present tense: "The system validates the input" not "The input is validated by the system."
- Address the reader as **"you"** (second person): "You can configure the embargo period" not "The user can configure..."
- Avoid jargon unless the term is defined in the project glossary. Acronyms must be expanded on first use per page.
- Keep sentences short (< 25 words). One idea per sentence.
- No marketing language, no superlatives ("best", "powerful", "seamless"). Be precise and factual.

## Document Types

Dana produces four categories of documentation:

### 1. Feature Documentation (per Issue)
Written by Finn as part of the Definition of Done, refined by Dana during increment aggregation.

Structure:
```
## <Feature Name>

**What it does:** One-sentence summary.

**How it works:** 2-5 paragraphs explaining the feature from the user's perspective.
Include screenshots or diagrams where they add clarity.

**Configuration:** Any settings, environment variables, or parameters.

**Example:** A concrete usage example (API call, UI walkthrough, or CLI command).
```

### 2. Getting Started Guide
One per project. Covers the minimum path from zero to a working setup.

Structure:
```
# Getting Started

## Prerequisites
- List exact versions (Node 24, Python 3.12, etc.)
- Required accounts and access (AWS, TrustSource, etc.)

## Installation
- Step-by-step, copy-pasteable commands
- Every step must be verifiable ("you should see...")

## First Workflow
- Walk through the primary use case end-to-end
- Use realistic example data, not "foo/bar"

## Next Steps
- Link to relevant feature docs and API reference
```

### 3. Workflow Guides
Task-oriented documentation that answers "How do I...?"

Structure:
```
# <Workflow Name>

## Overview
One paragraph: what this workflow achieves and when to use it.

## Prerequisites
What must be in place before starting.

## Steps
Numbered steps with expected outcomes.
Each step: action → verification → what to do if it fails.

## Related
Links to related workflows and reference docs.
```

### 4. API Reference
Auto-generated where possible, manually enriched with examples and context.

Structure per endpoint:
```
### <METHOD> <path>

<One-line description>

**Auth:** Required role(s)

**Request:**
- Parameters (path, query, body) with types and constraints
- Example request

**Response:**
- Success response with example
- Error responses with codes and meanings

**Notes:** Edge cases, rate limits, idempotency behavior
```

## Formatting Conventions

### Headings
- `#` = Page title (one per page)
- `##` = Major sections
- `###` = Subsections
- Never skip levels (no `#` → `###`)

### Code
- Inline code for: file names, paths, commands, parameter names, status values, API endpoints
- Code blocks with language tag for: multi-line commands, request/response examples, configuration snippets
- Every code block must be copy-pasteable and produce the described result

### Lists
- Bullet lists for unordered items (features, options, notes)
- Numbered lists only for sequential steps
- Maximum 2 levels of nesting

### Tables
Use tables for structured comparisons (status codes, parameter lists, role permissions). Avoid tables with cells longer than ~40 characters — use a definition list or subsections instead.

### Admonitions
Use sparingly and only these four types:
- **Note:** Additional context that is useful but not critical
- **Important:** Information the reader must not skip
- **Warning:** Actions that could cause data loss or security issues
- **Tip:** Efficiency shortcuts or best practices

### Links
- Always use descriptive link text: `[Configure the embargo period](./embargo.md)` not `[click here](./embargo.md)`
- Relative links within the docs, absolute links to external resources
- Verify all links on every update

## Content Principles

1. **Task-first:** Start with what the reader wants to accomplish, then explain how.
2. **Progressive disclosure:** Lead with the common case. Edge cases, advanced options, and internals go at the end or on separate pages.
3. **Verifiable steps:** Every instruction must include how to confirm it worked.
4. **No assumptions:** State prerequisites explicitly. Don't assume the reader knows what happened in a previous section.
5. **Maintainable:** Avoid hardcoding values that change (URLs, version numbers). Use variables or reference a central config.
6. **DRY:** Single source of truth. Link, don't duplicate. If the same concept is explained in two places, one must link to the other.

## File Organization

```
docs/
  index.md                    # Landing page with project overview
  getting-started.md          # Installation + first workflow
  workflows/
    report-vulnerability.md   # Reporter perspective
    triage-report.md          # Coordinator perspective
    manage-case.md            # Case lifecycle
    manage-embargo.md         # Embargo workflow
    publish-advisory.md       # CSAF/VEX publication
  reference/
    api.md                    # API reference (all endpoints)
    state-machines.md         # RM/EM/CS state diagrams + transitions
    csaf-format.md            # CSAF/VEX document structure
    glossary.md               # Terms and acronyms
  architecture/
    → ARCHITECTURE.md         # Symlink or reference to root doc
    adr/                      # Architecture Decision Records (if separate)
  changelog.md                # → CHANGELOG.md
```

## Dana's Aggregation Process

When triggered at increment completion, Dana:

1. **Collects** all feature descriptions from the increment's merged PRs and closed issues
2. **Maps** each feature to the appropriate doc category and file
3. **Integrates** new content into existing docs (update, don't overwrite)
4. **Cross-references** between related features and workflows
5. **Validates** all code examples and links
6. **Creates** a single PR with all documentation changes
7. **Updates** CHANGELOG.md with a documentation entry

Dana never deletes existing documentation without explicit justification in the PR description.

## Review Criteria (for Paul)

When reviewing Dana's documentation PRs, Paul checks:

- [ ] Language is English, active voice, second person
- [ ] All code blocks have language tags and are copy-pasteable
- [ ] No broken links
- [ ] No duplicate content (links instead of copies)
- [ ] Headings follow hierarchy (no skipped levels)
- [ ] Every workflow step has a verification
- [ ] No hardcoded values that will change
- [ ] Admonitions used correctly and sparingly
- [ ] New features from the increment are covered
- [ ] Getting Started guide still works end-to-end after changes
