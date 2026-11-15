# Runbook generator

Takes the parameters for `RUNBOOK_MAINTENANCE_AUTOMATION_PROMPT.md`, fills in the prompt, and runs it through Claude (`claude-opus-5-5`) to produce evidence-cited runbooks.

## Setup

```bash
py -m pip install -r requirements.txt
```

Set `ANTHROPIC_API_KEY`, or sign in with `ant auth login`. Then copy `runbook_config.example.toml` to `runbook_config.toml` and fill in the seven parameters.

## First run

```bash
py runbook_generator.py -c runbook_config.toml inventory
```
Phase 0 writes `PHASE0_INVENTORY.md`. Review it, and put any corrections in `OUTPUT_DIR/REVIEW_NOTES.md`.

```bash
py runbook_generator.py -c runbook_config.toml draft
```
Phase 1 drafts one runbook per conversation. Use `--types 4,10` to draft only some types, and `--force` to redo ones already drafted.

```bash
py runbook_generator.py -c runbook_config.toml finalize
```
Phases 2–3 run the cross-checks and write INDEX.md, GAPS_AND_FINDINGS.md and SUMMARY.md.

```bash
py runbook_generator.py -c runbook_config.toml check
```
Runs the acceptance checks without calling the API and writes VALIDATION_REPORT.md.

## Later runs (maintenance)

Point `output_dir` at a new folder and set `previous_run` to the earlier one, then:

```bash
py runbook_generator.py -c runbook_config.toml maintain
```

## Other commands

`render` writes `PROMPT_FILLED.md` without calling the API, for pasting into Claude Code by hand. `all --skip-review` runs everything without stopping for the Phase 0 review.

## Reading code from GitHub (gh)

Instead of cloning, list repositories under `github_repos` (`owner/name`, or `owner/name@ref`). They are read the way the Reliability Assistant scans a repository:

- gh's own sign-in is used (`gh auth login`, or `GH_TOKEN` / `GH_ENTERPRISE_TOKEN`). The program never sees the token.
- Each repository is resolved to one commit and downloaded as a tarball into memory; nothing is written to disk. Repositories too big for one archive are read file by file.
- Each repository also gets `_github/repository-signals.md` (branch protection, rulesets, environments, releases, deployments) and `_github/security-alerts.md` (open Dependabot, code-scanning and secret-scanning alerts; secret values are never collected).
- The commits are pinned in `OUTPUT_DIR/github_refs.json` the first time, so `inventory`, `draft` and `finalize` all cite the same commit. Pass `--refresh-github` to move to the latest commit. A new `output_dir` (maintenance) starts unpinned.

```bash
py runbook_generator.py -c runbook_config.toml github-check
```
Checks the sign-in and that every repository can be read, without downloading anything. If a repository shows "not found", sign gh in with an account that can read it (`gh auth login`, or `gh auth switch`), and authorize gh for the organization if it uses SAML SSO. `--skip-missing-repos` runs with the ones that can be read.

## Providers

Set `provider` in the config (or pass `--provider`), then fill in the matching section of `runbook_config.example.toml`.

| Provider | Model | Credentials | Differences |
|---|---|---|---|
| `anthropic` (default) | Claude, first-party API | `ANTHROPIC_API_KEY` or `ant auth login` | Supports everything, including automatic fallback to another model when a request is declined |
| `foundry` | Claude on Microsoft Foundry (Azure) | `ANTHROPIC_FOUNDRY_API_KEY`, or Entra ID (`auth = "entra"`) | No automatic fallback |
| `bedrock` | Claude on Amazon Bedrock | AWS credentials or a profile | No automatic fallback |
| `vertex` | Claude on Google Vertex AI | GCP application default credentials | No automatic fallback |
| `azure_openai` | Your Azure OpenAI deployment | `AZURE_OPENAI_API_KEY`, or Entra ID | Uses its own tool-calling loop; long runs clear old tool outputs instead of being summarized |

All providers use the same sandboxed tools, safeguards, phases and checks.

The prompt and the JSON fragment format were written for Claude. If you switch to `azure_openai`, run `check` and review a sample of runbooks before you trust the output. In particular, check that every step has a citation and that unknowns are flagged as gaps instead of guessed.

## Safeguards built into the program

- Claude gets read, list and search tools only for the declared inputs (local folders, or GitHub repositories held in memory), and a write tool only for `OUTPUT_DIR`. It has no shell, no network access and cannot execute anything.
- Secret-looking values in inputs are redacted before Claude sees them. Any write containing an e-mail address or a secret is refused.
- `SOURCES.md`/`sources.json` hashes, the `runbooks.json` merge, ServiceNow incident grouping (counts and record numbers only), hand-edit detection and the acceptance checks are all computed in Python, not by the model.
- Claude cannot write the files the program owns (SOURCES.md, sources.json, runbooks.json, github_refs.json, generated_manifest.json, logs/).
- Every tool call is logged (paths only) to `OUTPUT_DIR/logs/`.
