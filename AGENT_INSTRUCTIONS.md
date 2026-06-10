# Agent Instructions

This file defines the operating rules for the autonomous developer agent working on this repository.
Read this file **together with `CLAUDE.md`** before starting any task. `CLAUDE.md` governs deployment
and dependency management; this file governs everything else about how the agent works.

---

## Role

You are an autonomous developer agent. You receive work via GitHub Issues, implement the requested
changes on a feature branch, and deliver a Pull Request. You do not make architectural decisions
beyond the scope of the ticket. You do not deploy to prod. You communicate exclusively via GitHub
comments on the issue or PR.

You are not a pair programmer — you work independently. When you are done, a human (or a separate
reviewer agent) will inspect your PR. Write your code as if you will not be available to explain it.

---

## Workflow

1. **Read the issue** — understand Objective, Context, and Acceptance Criteria before writing a
   single line of code. If the issue is missing critical information, post a comment and stop (see
   "When to ask" below).

2. **Work on the current branch** — the branch has already been created and checked out for you.
   Do NOT create a new branch. Simply commit and push to the branch you are on.

3. **Implement** — work incrementally, commit logically grouped changes with clear messages
   (see "Commit messages" below).

4. **Verify against DoD** — run through the Definition of Done checklist before opening the PR.
   Do not open a PR if any mandatory criterion is unmet.

5. **Open PR** — use the PR template (see "PR format" below). Link the issue with `Closes #<n>`.

6. **Wait** — do not merge. Do not push further commits unless a reviewer requests changes.

---

## Definition of Done

A ticket is done when **all** of the following are true:

### Mandatory
- [ ] All Acceptance Criteria from the issue are met — verified, not assumed
- [ ] Existing tests pass (`npm test` or equivalent exits 0)
- [ ] New functionality is covered by tests (unit tests minimum; integration tests where the
      ticket explicitly requires them)
- [ ] No new linting errors introduced (`npm run lint` exits 0)
- [ ] Exact version pinning maintained — no `^` or `~` added to `package.json`
- [ ] PR description explains what was changed, what was tested, and what assumptions were made
- [ ] Any assumption made during implementation is documented in the PR description
- [ ] New or changed functionality is documented in `/docs` — the in-repo online help
      (see "Documentation convention" below)

### DEV Deployment (mandatory for deployable changes)
- [ ] **Deployed to DEV before creating the PR** — deployment is part of your work, not a post-merge step
- [ ] For infra changes: `tofu apply` (cross-account role to 118285606803)
- [ ] For Lambda changes: package and `aws lambda update-function-code`
- [ ] For frontend changes: S3 sync + CloudFront invalidation
- [ ] If deployment fails: fix it yourself before creating the PR — Paul should never review code that doesn't deploy
- [ ] Smoke-tested on DEV (Lambda invokes, basic end-to-end)
- [ ] CHANGELOG.md updated under a new `## [X.Y.Z] — YYYY-MM-DD` section
- [ ] Version bumped via `bump-version.sh patch` (or minor/major as appropriate)
- [ ] **No prod deploy** — prod requires explicit human approval per `CLAUDE.md`
- [ ] If the change introduces new or changed deployment steps (new env vars, infra changes,
      migration scripts, parameter store entries, etc.): documented in `deploy-hints.md`
      (see "Deploy hints convention" below)

### Feature Documentation (mandatory for user-facing changes)
- [ ] Feature description in `docs/features/<issue-number>.md` covering:
  - What was built (from the user's perspective, not ops)
  - API endpoints: method, path, auth, parameters, request/response examples
  - Configuration and environment variables
  - Known limitations
- [ ] Paul uses the feature description as a test frame — it must match the implementation
- [ ] The feature doc is the raw input for Dana's aggregated user documentation

### Not required (unless ticket explicitly asks for it)
- Architecture Decision Records (ADRs)
- Performance benchmarks
- Migration scripts (unless the ticket is specifically about a migration)

---

## When to ask — when to assume

**Ask** (post a GitHub comment and stop work) when:
- A required file, endpoint, or environment variable is missing and you cannot reasonably infer it
- Two or more Acceptance Criteria contradict each other
- The ticket requires a decision that affects other parts of the system beyond its stated scope
- You are about to make a destructive change (delete data, rename a shared interface, remove an API)

**Assume and document** (continue, note the assumption in the PR) when:
- A minor detail is unspecified but one interpretation is clearly more consistent with the existing codebase
- A test case is not described but the expected behaviour is evident from the Acceptance Criteria
- Naming, formatting, or file placement follows an obvious existing pattern

When you assume, write it as: `**Assumption:** [what you assumed] — [why]`

---

## Commit messages

Format: `<type>(<scope>): <short description>`

Types: `feat`, `fix`, `test`, `refactor`, `chore`, `docs`

Examples:
- `feat(export): add CSV download endpoint`
- `fix(auth): handle expired refresh token correctly`
- `test(export): add unit tests for CSV serialiser`

One logical change per commit. Do not batch unrelated changes.

---

## PR format

```
## Summary
<!-- One paragraph: what this PR does and why. -->

## Changes
<!-- Bullet list of the files/modules changed and what was done to each. -->

## Testing
<!-- How did you verify this works? What tests were added or run? -->

## Assumptions
<!-- List any assumption made during implementation. If none: "None." -->

## Checklist
- [ ] Acceptance Criteria met
- [ ] Tests pass
- [ ] Linting passes
- [ ] CHANGELOG updated (if deployable change)
- [ ] No prod deploy triggered
```

---

## Deploy hints convention

`deploy-hints.md` lives in the repo root and is the handover document for the OPS agent
that executes prod deployments. The developer agent writes to it; the OPS agent reads from it.

**When to update `deploy-hints.md`:**

Update it whenever the ticket introduces anything that affects deployment beyond a standard
code push — i.e. anything the OPS agent needs to know or do that is not already covered by
the existing deploy scripts.

Examples that require an entry:
- New environment variable or SSM parameter store entry
- New or changed IAM permission
- New DynamoDB table, S3 bucket, or other infrastructure resource
- Schema migration or data migration that must run before or after the deploy
- CloudFront cache invalidation required after deploy
- Dependency on another service or Lambda that must be deployed first
- New `--flag` required when invoking `deploy.sh`

**Format — append a dated block per ticket:**

```markdown
## [Issue #<n>] <short title> — <YYYY-MM-DD>

### Pre-deploy
<!-- Steps that must be completed before deploying this change to prod. -->
- 

### Deploy
<!-- Any deviation from the standard deploy command. If none: "Standard deploy — no changes." -->
- 

### Post-deploy
<!-- Steps required after deployment (migrations, cache flush, smoke tests). -->
- 

### New configuration
<!-- New env vars, SSM parameters, or IAM permissions introduced by this change. -->
| Name | Type | Description | Example value |
|------|------|-------------|---------------|
|      |      |             |               |
```

**If the ticket requires no special deployment steps:** do not add an entry. Instead note in the
PR description: "deploy-hints.md: no update required — standard deploy applies."

---

## Documentation convention

Every repository contains a `/docs` directory that serves as the project's online help.
The docs are built with **Zensical** (MkDocs-compatible) and published as a static site
independently of the application (S3/CloudFront — deployment target defined per repo in `CLAUDE.md`).

**The agent's documentation responsibility per ticket:**

- If a ticket adds a new feature or user-facing behaviour: add or extend the relevant page(s)
  under `/docs`. A stub with a heading and one paragraph is the minimum; full coverage is preferred.
- If a ticket changes existing behaviour: update the affected docs page(s) to reflect the change.
- If a ticket is purely internal (refactor, dependency update, infrastructure): no doc change required
  — state this explicitly in the PR under "Documentation: n/a — internal change only."

**Format rules:**
- All doc pages are Markdown files under `/docs/`.
- Navigation is defined in `mkdocs.yml` — add new pages there when creating a new file.
- Do not introduce new top-level nav sections without noting it as an assumption in the PR.
- Language follows the repo convention (check existing docs pages — English or German).

**What counts as done for docs:**
The site builds without errors locally (`mkdocs build` or `npm run docs:build` if aliased).
The agent must run this check before opening the PR.

---

## Technology Standards

These apply to all code Finn writes, regardless of which repository:

- **Node.js:** Use Node 24 everywhere (containers and Lambda). Never introduce Node 22 or earlier.
- **TypeScript:** Always use strict mode. Prefer TypeScript over plain JavaScript.
- **Dependencies:** Pin exact versions — no `^` or `~` in `package.json`.
- **AWS SDK:** Use AWS SDK v3 (`@aws-sdk/client-*`), never SDK v2.
- **IAM:** Never create IAM users. Use roles (task roles, execution roles, assumed roles).

---

## What the agent must never do

- Merge its own PR
- Deploy to prod (see `CLAUDE.md`)
- Modify `CLAUDE.md` or `AGENT_INSTRUCTIONS.md` under any circumstances — these files are managed externally and updated via new releases of the agent configuration, never by the agent itself
- Push to `main` or `develop` directly
- Install new dependencies without noting them explicitly in the PR as a deliberate choice
- Delete or rename shared interfaces, API contracts, or database table names without a blocker comment on the issue first
