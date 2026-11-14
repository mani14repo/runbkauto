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

- Claude gets read, list and search tools only for the declared inputs, and a write tool only for `OUTPUT_DIR`. It has no shell, no network access and cannot execute anything.
- Secret-looking values in inputs are redacted before Claude sees them. Any write containing an e-mail address or a secret is refused.
- `SOURCES.md`/`sources.json` hashes, the `runbooks.json` merge, ServiceNow incident grouping (counts and record numbers only), hand-edit detection and the acceptance checks are all computed in Python, not by the model.
- Every tool call is logged (paths only) to `OUTPUT_DIR/logs/`.
