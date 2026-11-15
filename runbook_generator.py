#!/usr/bin/env python3
"""
Runbook generator driven by RUNBOOK_MAINTENANCE_AUTOMATION_PROMPT.md.

Fills the prompt's placeholders from a TOML config (or CLI flags) and runs it
through Claude with a sandboxed, read-only tool set:

  * read/list/search only inside the declared inputs (docs, code repos, ops data)
  * write only inside OUTPUT_DIR
  * no shell, no network, no execution tools at all  (ground rule 1)
  * every write is scanned for e-mail addresses and secret-looking strings and
    refused if any are found                          (ground rules 2-3)

Commands (run in this order for a first run):

  render     Fill the prompt and write PROMPT_FILLED.md (no API call). Paste it
             into Claude Code yourself if you prefer.
  inventory  Phase 0: inventory, dependency map, coverage plan -> stop for review.
  draft      Phase 1: one runbook per type (separate conversation per runbook).
  finalize   Phases 2-3: merge JSON, cross-checks, INDEX / GAPS_AND_FINDINGS.
  check      Deterministic acceptance checks on the outputs (no API call).
  maintain   Phase 4: diff sources vs PREVIOUS_RUN, update affected runbooks.
  all        inventory -> draft -> finalize -> check (requires --skip-review).

Python files (SOURCES.md hashes, runbooks.json merge, incident grouping,
acceptance checks) are computed deterministically here, not by the model.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import fnmatch
import hashlib
import io
import json
import os
import posixpath
import re
import sys
import time
import tomllib
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

import gh_source

try:
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    sys.stderr.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
except Exception:
    pass

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

DEFAULT_PROMPT = Path(
    r"C:\Users\rhari\OneDrive\Documents\CVSEvidenceLog\docs\docs"
    r"\RUNBOOK_MAINTENANCE_AUTOMATION_PROMPT.md"
)
DEFAULT_MODEL = "claude-opus-5-5"
# Claude via the Anthropic SDK on four platforms, plus Azure OpenAI via the OpenAI SDK.
PROVIDERS = ("anthropic", "foundry", "bedrock", "vertex", "azure_openai")
AZURE_SCOPE = "https://cognitiveservices.azure.com/.default"

RUNBOOK_TYPES: list[tuple[int, str, str]] = [
    (1, "production-deployment-and-release", "Production deployment and release"),
    (2, "routine-maintenance", "Routine maintenance"),
    (3, "change-management", "Change management"),
    (4, "troubleshooting-and-incident-response", "Troubleshooting and incident response"),
    (5, "disaster-recovery-and-failover", "Disaster recovery and failover"),
    (6, "configuration-management", "Configuration management"),
    (7, "certificate-and-secrets-lifecycle", "Certificate and secrets lifecycle"),
    (8, "ci-cd-pipeline-operations", "CI/CD pipeline operations"),
    (9, "security-testing-and-vulnerability-response", "Security testing and vulnerability response"),
    (10, "batch-jobs-and-scheduled-workloads", "Batch jobs and scheduled workloads"),
    (11, "monitoring-and-alerting", "Monitoring and alerting"),
    (12, "capacity-and-scaling", "Capacity and scaling"),
    (13, "backup-and-restore", "Backup and restore"),
    (14, "access-and-operational-permissions", "Access and operational permissions"),
    (15, "dependency-and-third-party-failures", "Dependency and third-party failures"),
    (16, "other-application-specific-maintenance", "Other application-specific maintenance"),
]

SKIP_DIRS = {
    ".git", ".svn", ".hg", "node_modules", ".venv", "venv", "env", "__pycache__",
    ".idea", ".vs", ".vscode", "bin", "obj", "dist", "build", "target", ".terraform",
    ".gradle", ".mypy_cache", ".pytest_cache", ".tox", "coverage", ".next", "vendor", "site-packages",
}
SKIP_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".zip", ".gz", ".tar", ".7z",
    ".jar", ".war", ".ear", ".class", ".dll", ".exe", ".so", ".dylib", ".pyc", ".whl",
    ".mp4", ".mp3", ".woff", ".woff2", ".ttf", ".eot", ".lock", ".bin", ".pdb", ".nupkg",
    ".map", ".bcmap", ".pyd", ".parquet", ".avro", ".onnx", ".pt", ".pkl", ".npy", ".h5",
}
EXTRACT_EXT = {".docx", ".pptx", ".xlsx", ".xlsm", ".pdf"}
MAX_TEXT_BYTES = 5_000_000
MAX_LINE_CHARS = 600

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
SECRET_PATTERNS = [
    ("private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("Slack token", re.compile(r"\bxox[abpr]-[A-Za-z0-9-]{10,}\b")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("Azure storage key", re.compile(r"AccountKey=[A-Za-z0-9+/=]{20,}")),
    ("connection-string password", re.compile(r"(?i)\b(password|pwd)\s*=\s*[^;<\s'\"]{4,}")),
    ("inline credential", re.compile(
        r"(?i)\b(password|passwd|secret|api[_-]?key|token|client[_-]?secret)\b\s*[:=]\s*"
        r"['\"]?(?!<retrieve)(?!\$\{)(?!UNKNOWN)[A-Za-z0-9/+_\-!@#$%^&*.]{8,}")),
]
def redact(line: str) -> str:
    """Hide secret-looking values in input text; keep the key so the location can be reported."""
    for name, rx in SECRET_PATTERNS:
        if rx.search(line):
            line = rx.sub(lambda m: (m.group(1) + "=" if m.groups() and m.group(1) else "")
                          + f"<REDACTED {name}: report file:line as a security finding>", line)
    return line


PHONE_RE = re.compile(r"(?<!\d)(\+?1[-.\s])?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}(?!\d)")


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

@dataclass
class Config:
    app_name: str
    input_dir: Path
    code_repos: list[Path]
    output_dir: Path
    owner_role: str
    ops_data: list[Path] = field(default_factory=list)
    previous_run: Path | None = None
    prompt_path: Path = DEFAULT_PROMPT
    app_short: str = ""
    model: str = DEFAULT_MODEL
    effort: str = "high"
    max_iterations: int = 150
    knowledge_articles: bool = False
    ops_columns: dict[str, str] = field(default_factory=dict)
    provider: str = "anthropic"
    provider_opts: dict[str, Any] = field(default_factory=dict)
    exclude: list[str] = field(default_factory=list)
    github_repos: list[str] = field(default_factory=list)   # owner/name[@ref], read through gh
    github_host: str = "github.com"
    github_signals: bool = True
    github_alerts: bool = True
    github_max_archive_mb: int = 2048
    github_refresh: bool = False
    skip_missing_repos: bool = False

    @property
    def app_id(self) -> str:
        base = self.app_short or re.sub(r"[^A-Za-z0-9]+", "", self.app_name.split()[0])
        return base.upper()[:12] or "APP"


def _paths(v: Any) -> list[Path]:
    if not v:
        return []
    if isinstance(v, (str, Path)):
        v = [v]
    return [Path(os.path.expandvars(str(p))).expanduser() for p in v]


def load_config(args: argparse.Namespace) -> Config:
    data: dict[str, Any] = {}
    if args.config:
        with open(args.config, "rb") as fh:
            data = tomllib.load(fh)
    for key in ("app_name", "input_dir", "code_repos", "ops_data", "output_dir",
                "owner_role", "previous_run", "prompt_path", "app_short", "model",
                "effort", "max_iterations", "provider", "github_repos"):
        val = getattr(args, key, None)
        if val not in (None, [], ""):
            data[key] = val
    if getattr(args, "knowledge_articles", False):
        data["knowledge_articles"] = True

    missing = [k for k in ("app_name", "input_dir", "output_dir", "owner_role")
               if not data.get(k)]
    if missing:
        sys.exit(f"Missing required parameter(s): {', '.join(missing)} "
                 f"(set them in the TOML config or pass --{missing[0].replace('_', '-')})")

    cfg = Config(
        app_name=str(data["app_name"]),
        input_dir=_paths(data["input_dir"])[0],
        code_repos=_paths(data.get("code_repos")),
        output_dir=_paths(data["output_dir"])[0],
        owner_role=str(data["owner_role"]),
        ops_data=_paths(data.get("ops_data")),
        previous_run=(_paths(data["previous_run"])[0] if data.get("previous_run") else None),
        prompt_path=_paths(data.get("prompt_path") or DEFAULT_PROMPT)[0],
        app_short=str(data.get("app_short", "")),
        model=str(data.get("model", DEFAULT_MODEL)),
        effort=str(data.get("effort", "high")),
        max_iterations=int(data.get("max_iterations", 150)),
        knowledge_articles=bool(data.get("knowledge_articles", False)),
        ops_columns=dict(data.get("ops_columns", {})),
        provider=str(data.get("provider", "anthropic")).lower(),
        exclude=[str(x) for x in data.get("exclude", [])],
        github_repos=[str(x) for x in ([data["github_repos"]] if isinstance(data.get("github_repos"), str)
                                       else data.get("github_repos", []))],
        github_host=str(data.get("github_host", "github.com")).strip().lower(),
        github_signals=bool(data.get("github_signals", True)),
        github_alerts=bool(data.get("github_alerts", True)),
        github_max_archive_mb=int(data.get("github_max_archive_mb", 2048)),
        github_refresh=bool(getattr(args, "refresh_github", False)),
        skip_missing_repos=bool(getattr(args, "skip_missing_repos", False)),
    )
    missing_repos = [r for r in cfg.code_repos if not r.is_dir()]
    if missing_repos and getattr(args, "skip_missing_repos", False):
        print("Skipping missing repos: " + ", ".join(r.name for r in missing_repos))
        cfg.code_repos = [r for r in cfg.code_repos if r.is_dir()]
    if cfg.provider not in PROVIDERS:
        sys.exit(f"Unknown provider '{cfg.provider}'. Choose one of: {', '.join(PROVIDERS)}")
    cfg.provider_opts = dict(data.get(cfg.provider, {}))
    if cfg.provider == "azure_openai" and "model" not in data:
        cfg.model = str(cfg.provider_opts.get("deployment", ""))
        if not cfg.model:
            sys.exit("provider = azure_openai needs [azure_openai] deployment = \"<deployment name>\"")
    return cfg


def validate_config(cfg: Config, need_inputs: bool = True) -> None:
    errs = []
    if need_inputs:
        if not cfg.input_dir.is_dir():
            errs.append(f"INPUT_DIR not found: {cfg.input_dir}")
        for r in cfg.code_repos:
            if not r.is_dir():
                errs.append(f"CODE_REPO not found: {r}")
        for o in cfg.ops_data:
            if not o.exists():
                errs.append(f"OPS_DATA not found: {o}")
    for spec in cfg.github_repos:
        try:
            gh_source.parse_target(spec, cfg.github_host)
        except gh_source.GitHubError as e:
            errs.append(f"github_repos: {e}")
    if not cfg.prompt_path.is_file():
        errs.append(f"Prompt file not found: {cfg.prompt_path}")
    out = cfg.output_dir.resolve()
    for r in cfg.code_repos:
        try:
            if out.is_relative_to(r.resolve()):
                errs.append(f"OUTPUT_DIR must be outside the code repositories ({r})")
        except OSError:
            pass
    if cfg.previous_run and not cfg.previous_run.is_dir():
        errs.append(f"PREVIOUS_RUN not found: {cfg.previous_run}")
    if cfg.previous_run and cfg.previous_run.resolve() == out:
        errs.append("PREVIOUS_RUN and OUTPUT_DIR must differ (approved runbooks are never overwritten)")
    if errs:
        sys.exit("Configuration errors:\n  - " + "\n  - ".join(errs))


# --------------------------------------------------------------------------- #
# Prompt rendering
# --------------------------------------------------------------------------- #

def render_prompt(cfg: Config) -> str:
    raw = cfg.prompt_path.read_text(encoding="utf-8")
    # The agent prompt is everything below the first horizontal rule.
    parts = re.split(r"(?m)^---\s*$", raw, maxsplit=1)
    body = parts[1] if len(parts) == 2 else raw
    repl = {
        "<APP_NAME>": cfg.app_name,
        "<APP>": cfg.app_id,
        "<INPUT_DIR>": str(cfg.input_dir),
        "<CODE_REPOS>": "; ".join([str(p) for p in cfg.code_repos] + [
            "{1}/{0} (GitHub, read through gh at one pinned commit; see github_refs.json)".format(
                *gh_source.parse_target(s, cfg.github_host)[:2]) for s in cfg.github_repos]) or (
            "(none supplied: no code repositories are available for this run. Every fact that "
            "would come from code (pipelines, job definitions, alert rules, manifests, config, "
            "certificate references) must come from the documents or be recorded as a Gap, and "
            "code-versus-document conflicts cannot be checked)"),
        "<OPS_DATA>": "; ".join(str(p) for p in cfg.ops_data) or "(none supplied: skip OPS_DATA steps)",
        "<OUTPUT_DIR>": str(cfg.output_dir),
        "<OWNER_ROLE>": cfg.owner_role,
        "<PREVIOUS_RUN>": str(cfg.previous_run) if cfg.previous_run else "(none: first run)",
    }
    # Replace inside backticks too (`<APP_NAME>` -> `PUMA`); keep template-only
    # placeholders such as <date>, <NN>, <type> for the model to fill.
    for k, v in repl.items():
        body = body.replace(k, v)
    return body.strip() + "\n"


# --------------------------------------------------------------------------- #
# Sandboxed file access
# --------------------------------------------------------------------------- #

def _slug(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", s).strip("-") or "root"


class _Stat:
    def __init__(self, size: int, mtime: float):
        self.st_size, self.st_mtime = size, mtime


class MemFile:
    """A file of a GitHub repository held in memory. Offers the parts of Path the sandbox uses."""
    __slots__ = ("root", "rel")

    def __init__(self, root: gh_source.GhRepo, rel: str):
        self.root, self.rel = root, rel

    name = property(lambda self: PurePosixPath(self.rel).name)
    suffix = property(lambda self: PurePosixPath(self.rel).suffix)

    def is_file(self) -> bool:
        return True

    def is_dir(self) -> bool:
        return False

    def resolve(self) -> "MemFile":
        return self

    def read_bytes(self) -> bytes:
        return self.root.files[self.rel]

    def stat(self) -> _Stat:
        return _Stat(len(self.root.files[self.rel]), self.root.mtime)

    def is_relative_to(self, base: Any) -> bool:
        if isinstance(base, MemFile):
            return base == self
        return (isinstance(base, MemDir) and base.root is self.root
                and (not base.prefix or self.rel.startswith(base.prefix + "/")))

    def __eq__(self, other: object) -> bool:
        return isinstance(other, MemFile) and other.root is self.root and other.rel == self.rel

    def __hash__(self) -> int:
        return hash((id(self.root), self.rel))

    def __str__(self) -> str:
        return f"{self.root.label}/{self.rel}"


class MemDir:
    """A folder inside an in-memory GitHub repository (it may not exist; then nothing is under it)."""

    def __init__(self, root: gh_source.GhRepo, prefix: str):
        self.root, self.prefix = root, prefix

    def is_file(self) -> bool:
        return False

    def is_dir(self) -> bool:
        return True

    def resolve(self) -> "MemDir":
        return self


# One download per repository per process; later phases reuse the commit pinned in OUTPUT_DIR/github_refs.json.
_GH_CACHE: dict[str, gh_source.GhRepo] = {}
GITHUB_REFS = "github_refs.json"


def _keep_repo_file(rel: str, size: int) -> bool:
    p = PurePosixPath(rel)
    if any(d in SKIP_DIRS for d in p.parts[:-1]):
        return False
    ext = p.suffix.lower()
    if ext in SKIP_EXT:
        return False
    return size <= (50_000_000 if ext in EXTRACT_EXT else MAX_TEXT_BYTES)


def load_github(cfg: Config, spec: str) -> gh_source.GhRepo:
    if spec in _GH_CACHE:
        return _GH_CACHE[spec]
    refs_path = cfg.output_dir / GITHUB_REFS
    pins = {}
    if refs_path.is_file():
        try:
            pins = json.loads(refs_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            pins = {}
    pinned = None if cfg.github_refresh else (pins.get(spec) or {}).get("sha")
    repo = gh_source.fetch(spec, _keep_repo_file, host=cfg.github_host, sha=pinned, signals=cfg.github_signals,
                           alerts=cfg.github_alerts, max_archive_mb=cfg.github_max_archive_mb)
    if pins.get(spec, {}).get("sha") not in (None, repo.sha):
        print(f"  ! {repo.repository}: moved from pinned {pins[spec]['sha'][:12]} to {repo.sha[:12]} (--refresh-github)")
    print(f"  ✓ {repo.label}: {len(repo.files)} files ({repo.fetch}), {repo.skipped} left out by type or size"
          + (f"; {len(repo.notes)} note(s)" if repo.notes else ""))
    pins[spec] = repo.pin()
    cfg.output_dir.mkdir(parents=True, exist_ok=True)
    refs_path.write_text(json.dumps(pins, indent=2, sort_keys=True), encoding="utf-8")
    _GH_CACHE[spec] = repo
    return repo


def _github_failed(cfg: Config, spec: str, err: Exception) -> None:
    msg = f"GitHub repository {spec}: {err}"
    if cfg.skip_missing_repos:
        print(f"  ! skipping {msg}")
        return
    hint = ""
    if isinstance(err, gh_source.GitHubError) and "cannot read it" in str(err):
        hint = ("\n  Sign gh in with an account that can read it (`gh auth login`, or `gh auth switch` if you have "
                "several), and if the organization uses SAML SSO authorize gh for it. Run `github-check` to test "
                "access, or pass --skip-missing-repos.")
    sys.exit(msg + hint)


class Sandbox:
    """Maps short aliases (docs/, <repo-name>/, ops/, prev/) to real paths or in-memory GitHub repositories."""

    def __init__(self, cfg: Config, include_prev: bool = False):
        self.cfg = cfg
        self.roots: dict[str, Any] = {}       # Path, or gh_source.GhRepo for a repository read through gh
        self.kinds: dict[str, str] = {}
        self._alias_of: dict[int, str] = {}
        self._add("docs", cfg.input_dir, "documents")
        for r in cfg.code_repos:
            self._add(_slug(r.name), r, "code repository")
        if cfg.github_repos:
            account = None
            try:
                account = gh_source.check_auth(cfg.github_host)
            except gh_source.GitHubError as e:
                sys.exit(str(e))
            print(f"Reading {len(cfg.github_repos)} GitHub repositor{'y' if len(cfg.github_repos) == 1 else 'ies'} "
                  f"through gh as {account} on {cfg.github_host}…")
            for spec in cfg.github_repos:
                try:
                    repo = load_github(cfg, spec)
                except gh_source.GitHubError as e:
                    _github_failed(cfg, spec, e)
                    continue
                self._add(_slug(repo.name), repo, f"code repository (GitHub via gh, commit {repo.label})")
        for o in cfg.ops_data:
            self._add("ops" if o.is_dir() else f"ops-{_slug(o.stem)}", o, "ops data")
        if include_prev and cfg.previous_run:
            self._add("prev", cfg.previous_run, "previous run (read-only)")
        self.out = cfg.output_dir.resolve()
        self._extract_cache: dict[Any, list[str]] = {}

    def _add(self, alias: str, path: Any, kind: str) -> None:
        a, n = alias, 2
        while a in self.roots:
            a, n = f"{alias}-{n}", n + 1
        self.roots[a] = path if isinstance(path, gh_source.GhRepo) else path.resolve()
        self.kinds[a] = kind
        self._alias_of[id(self.roots[a])] = a

    # -- resolution ---------------------------------------------------------
    def resolve(self, vpath: str) -> Any:
        vpath = vpath.replace("\\", "/").strip().lstrip("/")
        alias, _, rest = vpath.partition("/")
        if alias not in self.roots:
            raise ValueError(f"Unknown root '{alias}'. Valid roots: {', '.join(self.roots)}")
        root = self.roots[alias]
        if isinstance(root, gh_source.GhRepo):
            rel = posixpath.normpath(rest.strip("/")) if rest.strip("/") else ""
            if rel == ".":
                rel = ""
            if rel.startswith("../") or rel == "..":
                raise ValueError("Path escapes its root")
            return MemFile(root, rel) if rel in root.files else MemDir(root, rel)
        if root.is_file():
            if rest:
                raise ValueError(f"'{alias}' is a single file; use just '{alias}'")
            return root
        p = (root / rest).resolve()
        if not p.is_relative_to(root):
            raise ValueError("Path escapes its root")
        if p.is_relative_to(self.out):
            raise ValueError("Use the output tools for OUTPUT_DIR")
        return p

    def virtual(self, real: Any) -> str:
        if isinstance(real, MemFile):
            return f"{self._alias_of.get(id(real.root), real.root.name)}/{real.rel}"
        real = real.resolve()
        for alias, root in self.roots.items():
            if real == root:
                return alias
            if root.is_dir() and real.is_relative_to(root):
                return f"{alias}/{real.relative_to(root).as_posix()}"
        return str(real)

    # -- walking --------------------------------------------------------------
    def iter_files(self, alias: str | None = None):
        roots = [alias] if alias else list(self.roots)
        for a in roots:
            root = self.roots[a]
            if isinstance(root, gh_source.GhRepo):
                for rel in sorted(root.files):
                    f = MemFile(root, rel)
                    if f.suffix.lower() in SKIP_EXT:
                        continue
                    if self.cfg.exclude and any(fnmatch.fnmatch(f"{a}/{rel}", pat) or fnmatch.fnmatch(f.name, pat)
                                                for pat in self.cfg.exclude):
                        continue
                    yield f
                continue
            if root.is_file():
                yield root
                continue
            for dirpath, dirnames, filenames in os.walk(root):
                dp = Path(dirpath)
                dirnames[:] = [d for d in dirnames
                               if d not in SKIP_DIRS and not (dp / d).resolve().is_relative_to(self.out)]
                for f in filenames:
                    p = dp / f
                    if p.suffix.lower() in SKIP_EXT:
                        continue
                    if self.cfg.exclude:
                        v = self.virtual(p)
                        if any(fnmatch.fnmatch(v, pat) or fnmatch.fnmatch(f, pat) for pat in self.cfg.exclude):
                            continue
                    yield p

    # -- reading --------------------------------------------------------------
    def lines(self, p: Path) -> list[str]:
        if p in self._extract_cache:
            return self._extract_cache[p]
        if not p.is_file():
            raise ValueError("Not a file (use list_files to see what is there)")
        ext = p.suffix.lower()
        if ext in EXTRACT_EXT:
            out = extract_document(p)
        else:
            if p.stat().st_size > MAX_TEXT_BYTES:
                raise ValueError(f"File too large to read ({p.stat().st_size} bytes)")
            data = p.read_bytes()
            if b"\x00" in data[:8192]:
                raise ValueError("Binary file; not readable")
            out = data.decode("utf-8", errors="replace").splitlines()
        out = [redact(l) for l in out]
        self._extract_cache[p] = out
        return out


def extract_document(p: Any) -> list[str]:
    ext = p.suffix.lower()
    lines: list[str] = []
    if isinstance(p, MemFile):          # the libraries all read from a file object as well as a path
        p = io.BytesIO(p.read_bytes())
    try:
        if ext == ".docx":
            import docx  # python-docx
            d = docx.Document(p if isinstance(p, io.BytesIO) else str(p))
            body = d.element.body
            for child in body.iterchildren():
                tag = child.tag.rsplit("}", 1)[-1]
                if tag == "p":
                    para = docx.text.paragraph.Paragraph(child, d)
                    t = para.text.strip()
                    if not t:
                        continue
                    style = (para.style.name if para.style is not None else "") or ""
                    m = re.match(r"Heading (\d)", style)
                    lines.append(("#" * int(m.group(1)) + " " + t) if m else t)
                elif tag == "tbl":
                    tbl = docx.table.Table(child, d)
                    for row in tbl.rows:
                        lines.append("| " + " | ".join(c.text.strip().replace("\n", " ") for c in row.cells) + " |")
        elif ext == ".pptx":
            from pptx import Presentation
            prs = Presentation(p if isinstance(p, io.BytesIO) else str(p))
            for i, slide in enumerate(prs.slides, 1):
                lines.append(f"--- Slide {i} ---")
                for shape in slide.shapes:
                    if getattr(shape, "has_text_frame", False) and shape.has_text_frame:
                        for para in shape.text_frame.paragraphs:
                            t = "".join(r.text for r in para.runs).strip()
                            if t:
                                lines.append(t)
                    if getattr(shape, "has_table", False) and shape.has_table:
                        for row in shape.table.rows:
                            lines.append("| " + " | ".join(c.text.strip() for c in row.cells) + " |")
                if slide.has_notes_slide:
                    notes = slide.notes_slide.notes_text_frame.text.strip()
                    if notes:
                        lines.append(f"[Speaker notes] {notes}")
        elif ext in (".xlsx", ".xlsm"):
            import openpyxl
            wb = openpyxl.load_workbook(p if isinstance(p, io.BytesIO) else str(p), read_only=True, data_only=True)
            for ws in wb.worksheets:
                lines.append(f"--- Sheet {ws.title} ---")
                for row in ws.iter_rows(values_only=True):
                    if any(v not in (None, "") for v in row):
                        lines.append(" | ".join("" if v is None else str(v) for v in row))
            wb.close()
        elif ext == ".pdf":
            from pypdf import PdfReader
            reader = PdfReader(p if isinstance(p, io.BytesIO) else str(p))
            for i, page in enumerate(reader.pages, 1):
                lines.append(f"--- Page {i} ---")
                lines.extend((page.extract_text() or "").splitlines())
    except ImportError as e:
        raise ValueError(f"Missing library to read {ext}: {e.name}. pip install -r requirements.txt")
    return lines


# --------------------------------------------------------------------------- #
# Source inventory + hashes (deterministic; feeds SOURCES.md and maintenance)
# --------------------------------------------------------------------------- #

def sha256_file(p: Any) -> str:
    if isinstance(p, MemFile):
        return hashlib.sha256(p.read_bytes()).hexdigest()
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def build_sources(sb: Sandbox) -> list[dict[str, Any]]:
    rows = []
    for alias, kind in sb.kinds.items():
        if alias == "prev":
            continue
        for p in sb.iter_files(alias):
            try:
                st = p.stat()
                rows.append({
                    "path": sb.virtual(p),
                    "root_kind": kind,
                    "type": p.suffix.lower().lstrip(".") or "(none)",
                    "modified": dt.datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d"),
                    "bytes": st.st_size,
                    "sha256": sha256_file(p),
                })
            except OSError as e:
                rows.append({"path": sb.virtual(p), "root_kind": kind, "error": str(e)})
    rows.sort(key=lambda r: (r.get("modified", ""), r["path"]))
    return rows


def write_sources(cfg: Config, rows: list[dict[str, Any]], roots: dict[str, Path]) -> None:
    out = cfg.output_dir
    out.mkdir(parents=True, exist_ok=True)
    (out / "sources.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    md = [f"# {cfg.app_name}: Sources", "",
          f"Generated {dt.date.today().isoformat()}. Ordered oldest first. "
          "Hashes are SHA-256 of file content and drive maintenance mode.", "",
          "## Roots", "", "| Alias | Path |", "|---|---|"]
    md += [f"| `{a}` | `{p}` |" for a, p in roots.items() if a != "prev"]
    md += ["", "## Files", "", "| Path | Type | Modified | Bytes | SHA-256 |", "|---|---|---|---|---|"]
    for r in rows:
        if "error" in r:
            md.append(f"| `{r['path']}` | | | | UNREADABLE: {r['error']} |")
        else:
            md.append(f"| `{r['path']}` | {r['type']} | {r['modified']} | {r['bytes']} | `{r['sha256']}` |")
    (out / "SOURCES.md").write_text("\n".join(md) + "\n", encoding="utf-8")


def load_previous_sources(prev: Path) -> dict[str, str]:
    j = prev / "sources.json"
    if j.is_file():
        return {r["path"]: r.get("sha256", "") for r in json.loads(j.read_text(encoding="utf-8"))}
    md = prev / "SOURCES.md"
    result: dict[str, str] = {}
    if md.is_file():
        for line in md.read_text(encoding="utf-8").splitlines():
            m = re.match(r"\|\s*`([^`]+)`\s*\|.*`([0-9a-f]{64})`\s*\|", line)
            if m:
                result[m.group(1)] = m.group(2)
    return result


def source_tree_summary(rows: list[dict[str, Any]], limit: int = 400) -> str:
    by_kind = defaultdict(int)
    for r in rows:
        by_kind[r.get("root_kind", "?")] += 1
    lines = [f"{len(rows)} files: " + ", ".join(f"{k}={v}" for k, v in by_kind.items())]
    for r in rows[:limit]:
        lines.append(f"- {r['path']}  ({r.get('modified', '?')}, {r.get('bytes', '?')} B)")
    if len(rows) > limit:
        lines.append(f"... {len(rows) - limit} more (use list_files / search)")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Ops data: recurring incident patterns (counts and record numbers only)
# --------------------------------------------------------------------------- #

OPS_COLUMN_HINTS = {
    "number": ["number", "incident", "task", "record", "id"],
    "short_description": ["short_description", "short description", "summary", "title"],
    "ci": ["cmdb_ci", "configuration item", "ci", "business service", "service"],
    "opened": ["opened_at", "opened", "created", "sys_created_on", "start"],
    "close_code": ["close_code", "resolution code", "close code", "resolution"],
    "close_notes": ["close_notes", "close notes", "resolution notes"],
    "problem": ["problem_id", "problem", "related problem", "parent"],
    "group": ["assignment_group", "assignment group", "group"],
    "priority": ["priority", "severity"],
}


def _read_table(p: Path) -> list[dict[str, str]]:
    if p.suffix.lower() == ".csv":
        with open(p, newline="", encoding="utf-8-sig", errors="replace") as fh:
            return [{k or "": (v or "") for k, v in row.items()} for row in csv.DictReader(fh)]
    if p.suffix.lower() in (".xlsx", ".xlsm"):
        import openpyxl
        wb = openpyxl.load_workbook(str(p), read_only=True, data_only=True)
        ws = wb.worksheets[0]
        it = ws.iter_rows(values_only=True)
        header = [str(h or "") for h in next(it, [])]
        rows = [{header[i]: ("" if v is None else str(v)) for i, v in enumerate(r) if i < len(header)}
                for r in it]
        wb.close()
        return rows
    return []


def _pick(header: list[str], key: str, overrides: dict[str, str]) -> str | None:
    if key in overrides:
        return overrides[key] if overrides[key] in header else None
    low = {h.lower().strip(): h for h in header}
    for hint in OPS_COLUMN_HINTS[key]:
        if hint in low:
            return low[hint]
    for hint in OPS_COLUMN_HINTS[key]:
        for lh, h in low.items():
            if hint in lh:
                return h
    return None


def _normalize_desc(s: str) -> str:
    s = s.lower()
    s = EMAIL_RE.sub("<email>", s)
    s = re.sub(r"\b[0-9a-f]{8}-[0-9a-f-]{27,}\b", "<guid>", s)
    s = re.sub(r"\d{1,4}[-/]\d{1,2}[-/]\d{1,4}([ t]\d{1,2}:\d{2}(:\d{2})?)?", "<date>", s)
    s = re.sub(r"\b\d+\b", "<n>", s)
    s = re.sub(r"[^a-z<>_ ]+", " ", s)
    return re.sub(r"\s+", " ", s).strip()[:120]


def _parse_date(s: str) -> str | None:
    s = s.strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%m/%d/%Y %H:%M:%S", "%m/%d/%Y %I:%M:%S %p",
                "%m/%d/%Y %H:%M", "%m/%d/%Y", "%d-%m-%Y %H:%M:%S"):
        try:
            return dt.datetime.strptime(s, fmt).date().isoformat()
        except ValueError:
            continue
    m = re.match(r"(\d{4}-\d{2}-\d{2})", s)
    return m.group(1) if m else None


def incident_patterns(cfg: Config, sb: Sandbox, min_count: int = 2) -> str:
    files = []
    for o in cfg.ops_data:
        if o.is_file():
            files.append(o)
        elif o.is_dir():
            files += [p for p in o.rglob("*") if p.suffix.lower() in (".csv", ".xlsx", ".xlsm")]
    if not files:
        return "No OPS_DATA supplied."
    report = []
    for f in files:
        try:
            rows = _read_table(f)
        except Exception as e:  # noqa: BLE001
            report.append(f"## {sb.virtual(f)}\nUNREADABLE: {e}")
            continue
        if not rows:
            continue
        header = list(rows[0].keys())
        cols = {k: _pick(header, k, cfg.ops_columns) for k in OPS_COLUMN_HINTS}
        kind = ("problem" if "prb" in f.name.lower() or "problem" in f.name.lower() else
                "change" if "chg" in f.name.lower() or "change" in f.name.lower() else "incident")
        groups: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
        for r in rows:
            desc = r.get(cols["short_description"] or "", "")
            ci = r.get(cols["ci"] or "", "") or "(no CI)"
            groups[(_normalize_desc(desc), ci)].append(r)
        ranked = sorted(groups.items(), key=lambda kv: -len(kv[1]))
        out = [f"## {sb.virtual(f)}  ({kind} export, {len(rows)} rows)",
               "Detected columns: " + ", ".join(f"{k}={v}" for k, v in cols.items() if v),
               "",
               "| # | Normalized short description | CI | Count | First | Last | Close codes | Problem linked | Sample records |",
               "|---|---|---|---|---|---|---|---|---|"]
        for i, ((desc, ci), rs) in enumerate(ranked, 1):
            if len(rs) < min_count:
                break
            dates = sorted(d for d in (_parse_date(r.get(cols["opened"] or "", "")) for r in rs) if d)
            codes = defaultdict(int)
            for r in rs:
                codes[(r.get(cols["close_code"] or "", "") or "(blank)")[:40]] += 1
            prob = sum(1 for r in rs if (r.get(cols["problem"] or "", "") or "").strip())
            nums = [r.get(cols["number"] or "", "") for r in rs if r.get(cols["number"] or "")]
            out.append(
                f"| {i} | {desc or '(blank)'} | {ci} | {len(rs)} | {dates[0] if dates else '?'} | "
                f"{dates[-1] if dates else '?'} | "
                + "; ".join(f"{k}:{v}" for k, v in sorted(codes.items(), key=lambda kv: -kv[1])[:3])
                + f" | {prob}/{len(rs)} | {', '.join(nums[:5])} |")
            if i >= 60:
                out.append(f"| ... | {len(ranked) - 60} more groups | | | | | | | |")
                break
        # How recurring incidents were closed (close-note phrases), no free text copied.
        if cols["close_notes"]:
            phrase = defaultdict(int)
            for r in rows:
                n = _normalize_desc(r.get(cols["close_notes"], ""))[:60]
                if n:
                    phrase[n] += 1
            top = sorted(phrase.items(), key=lambda kv: -kv[1])[:10]
            out += ["", "Most common normalized close-note openings (count): "
                    + "; ".join(f"'{k}' ({v})" for k, v in top)]
        report.append("\n".join(out))
    return "\n\n".join(report)


# --------------------------------------------------------------------------- #
# Output guard
# --------------------------------------------------------------------------- #

def scan_text(text: str) -> tuple[list[str], list[str]]:
    """Return (blocking problems, warnings)."""
    block, warn = [], []
    emails = {e for e in EMAIL_RE.findall(text) if not e.lower().endswith(("example.com", "example.org"))}
    if emails:
        block.append(f"{len(emails)} e-mail address(es) found; refer to people by role")
    for name, rx in SECRET_PATTERNS:
        for m in rx.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            block.append(f"possible {name} at line {line}; use "
                         "`<retrieve from approved secrets store: NAME>` instead of the value")
            break
    phones = PHONE_RE.findall(text)
    if phones:
        warn.append(f"{len(phones)} phone-number-like string(s); check they are not personal data")
    return block, warn


# --------------------------------------------------------------------------- #
# Tools exposed to Claude
# --------------------------------------------------------------------------- #

class RunLog:
    def __init__(self, out: Path, label: str):
        (out / "logs").mkdir(parents=True, exist_ok=True)
        ts = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        self.path = out / "logs" / f"{ts}-{label}.jsonl"

    def write(self, **rec: Any) -> None:
        rec["t"] = dt.datetime.now().isoformat(timespec="seconds")
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, default=str) + "\n")


def make_tools(sb: Sandbox, cfg: Config, log: RunLog, verbose: bool):
    from anthropic import beta_tool

    out_root = cfg.output_dir.resolve()
    manifest_path = out_root / "generated_manifest.json"

    def note(tool: str, **kw: Any) -> None:
        log.write(tool=tool, **kw)
        if verbose:
            print(f"   · {tool} {json.dumps(kw, default=str)[:160]}")

    @beta_tool
    def list_roots() -> str:
        """List the read-only input roots (aliases) you can read from, and the output directory.

        Every input path you pass to other tools starts with one of these aliases,
        e.g. 'docs/architecture/overview.docx' or '<repo-alias>/helm/values.yaml'.
        """
        note("list_roots")
        lines = [f"{a}/  ->  {sb.kinds[a]}" + (" (single file)" if p.is_file() else "")
                 for a, p in sb.roots.items()]
        lines.append("OUTPUT (write with write_output; read back with read_output)")
        return "\n".join(lines)

    @beta_tool
    def list_files(path: str = "", pattern: str = "*", max_results: int = 500) -> str:
        """List files under an input root or sub-folder, recursively.

        Args:
            path: Root alias or alias/sub/folder. Empty string lists every root.
            pattern: Glob on the file name, e.g. '*.yaml', 'Jenkinsfile*', '*.docx'.
            max_results: Maximum number of entries to return (default 500).
        """
        note("list_files", path=path, pattern=pattern)
        try:
            if not path:
                files = list(sb.iter_files())
            else:
                base = sb.resolve(path)
                if base.is_file():
                    files = [base]
                else:
                    alias = path.replace("\\", "/").split("/")[0]
                    files = [p for p in sb.iter_files(alias) if p.resolve().is_relative_to(base)]
            hits = [p for p in files if fnmatch.fnmatch(p.name.lower(), pattern.lower())]
            res = [f"{sb.virtual(p)}  ({p.stat().st_size} B, "
                   f"{dt.datetime.fromtimestamp(p.stat().st_mtime):%Y-%m-%d})" for p in hits[:max_results]]
            if len(hits) > max_results:
                res.append(f"... {len(hits) - max_results} more; narrow path or pattern")
            return "\n".join(res) or "(no matches)"
        except Exception as e:  # noqa: BLE001
            return f"ERROR: {e}"

    @beta_tool
    def read_file(path: str, offset: int = 1, limit: int = 400) -> str:
        """Read an input file with line numbers (cite as path:line).

        .docx/.pptx/.xlsx/.pdf files are converted to text first: headings become
        '#' lines, slides/pages/sheets are marked '--- Slide N ---' etc. For those,
        cite the document and section (heading, slide, page or sheet) rather than
        the extracted line number.

        Args:
            path: alias/relative/path of the file.
            offset: First line to return (1-based).
            limit: Number of lines to return (max 2000).
        """
        note("read_file", path=path, offset=offset, limit=limit)
        try:
            p = sb.resolve(path)
            lines = sb.lines(p)
            limit = max(1, min(limit, 2000))
            start = max(1, offset)
            chunk = lines[start - 1:start - 1 + limit]
            body = "\n".join(f"{i:>6}\t{(l[:MAX_LINE_CHARS] + ' …') if len(l) > MAX_LINE_CHARS else l}"
                             for i, l in enumerate(chunk, start))
            tail = (f"\n[lines {start}-{start + len(chunk) - 1} of {len(lines)}; "
                    f"call again with offset={start + len(chunk)} for more]"
                    if start + len(chunk) - 1 < len(lines) else f"\n[end of file, {len(lines)} lines]")
            return (body or "(empty)") + tail
        except Exception as e:  # noqa: BLE001
            return f"ERROR: {e}"

    @beta_tool
    def search(pattern: str, path: str = "", file_glob: str = "*", ignore_case: bool = True,
               max_results: int = 200) -> str:
        """Regex search across input files; returns path:line: text matches.

        Searches extracted text of office/PDF documents too.

        Args:
            pattern: Python regular expression, e.g. 'cron|schedule_interval' or 'kind:\\s*CronJob'.
            path: Root alias or alias/sub/folder to limit the search. Empty searches everything.
            file_glob: Glob on file name, e.g. '*.yaml'.
            ignore_case: Case-insensitive match (default true).
            max_results: Maximum matches to return.
        """
        note("search", pattern=pattern, path=path, file_glob=file_glob)
        try:
            rx = re.compile(pattern, re.IGNORECASE if ignore_case else 0)
        except re.error as e:
            return f"ERROR: bad regex: {e}"
        try:
            if path:
                base = sb.resolve(path)
                alias = path.replace("\\", "/").split("/")[0]
                files = [base] if base.is_file() else [
                    p for p in sb.iter_files(alias) if p.resolve().is_relative_to(base)]
            else:
                files = list(sb.iter_files())
            hits: list[str] = []
            for p in files:
                if not fnmatch.fnmatch(p.name.lower(), file_glob.lower()):
                    continue
                try:
                    lines = sb.lines(p)
                except Exception:  # noqa: BLE001
                    continue
                for i, l in enumerate(lines, 1):
                    if rx.search(l):
                        hits.append(f"{sb.virtual(p)}:{i}: {l.strip()[:300]}")
                        if len(hits) >= max_results:
                            return "\n".join(hits) + "\n[max_results reached; narrow the search]"
            return "\n".join(hits) or "(no matches)"
        except Exception as e:  # noqa: BLE001
            return f"ERROR: {e}"

    @beta_tool
    def recurring_incidents(min_count: int = 2) -> str:
        """Group the OPS_DATA ServiceNow exports into recurring patterns.

        Groups by normalized short description + CI and returns count, date span,
        close codes, how many link to a Problem, and up to five record numbers.
        No free text, names or e-mail addresses are returned.

        Args:
            min_count: Smallest group size to report (default 2; the prompt's
                recurring-defect threshold is 5).
        """
        note("recurring_incidents", min_count=min_count)
        try:
            return incident_patterns(cfg, sb, min_count=min_count)
        except Exception as e:  # noqa: BLE001
            return f"ERROR: {e}"

    def _out_path(rel: str) -> Path:
        rel = rel.replace("\\", "/").lstrip("/")
        p = (out_root / rel).resolve()
        if not p.is_relative_to(out_root):
            raise ValueError("Path escapes OUTPUT_DIR")
        return p

    def _program_owned(p: Path) -> bool:
        rel = p.relative_to(out_root)
        return rel.as_posix() in PROGRAM_FILES or (rel.parts and rel.parts[0] == "logs")

    @beta_tool
    def write_output(relative_path: str, content: str, append: bool = False) -> str:
        """Write a file under OUTPUT_DIR (the only place you may write).

        Content is scanned before it is saved: writes containing e-mail addresses
        or secret-looking values are refused. Files ending .json must be valid JSON.
        For a long runbook, write the first part and then call again with append=true.

        Args:
            relative_path: Path relative to OUTPUT_DIR, e.g. 'runbooks/04-troubleshooting-and-incident-response.md'.
            content: Full file content (or the part to append).
            append: Append to the existing file instead of replacing it.
        """
        try:
            p = _out_path(relative_path)
            if _program_owned(p):
                note("write_output", path=relative_path, refused="program-owned file")
                return (f"REFUSED, nothing written: {relative_path} is written by the program, not by you "
                        "(SOURCES.md, sources.json, runbooks.json, github_refs.json, generated_manifest.json, logs/)")
            block, warn = scan_text(content)
            if block:
                note("write_output", path=relative_path, refused=block)
                return "REFUSED, nothing written: " + "; ".join(block)
            if p.suffix == ".json" and not append:
                json.loads(content)
            p.parent.mkdir(parents=True, exist_ok=True)
            with open(p, "a" if append else "w", encoding="utf-8", newline="\n") as fh:
                fh.write(content)
            # Record the generated hash so maintenance mode can detect hand edits.
            man = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {}
            man[p.relative_to(out_root).as_posix()] = sha256_file(p)
            manifest_path.write_text(json.dumps(man, indent=2, sort_keys=True), encoding="utf-8")
            note("write_output", path=relative_path, bytes=len(content.encode()), append=append)
            print(f"   ✎ wrote {relative_path}" + (" (append)" if append else ""))
            return "OK" + ("; warnings: " + "; ".join(warn) if warn else "")
        except json.JSONDecodeError as e:
            return f"REFUSED: invalid JSON ({e}); nothing written"
        except Exception as e:  # noqa: BLE001
            return f"ERROR: {e}"

    @beta_tool
    def read_output(relative_path: str, offset: int = 1, limit: int = 800) -> str:
        """Read back a file you (or an earlier phase) wrote under OUTPUT_DIR.

        Args:
            relative_path: Path relative to OUTPUT_DIR. Use '' to list all output files.
            offset: First line (1-based).
            limit: Number of lines.
        """
        note("read_output", path=relative_path)
        try:
            if not relative_path:
                return "\n".join(sorted(p.relative_to(out_root).as_posix()
                                        for p in out_root.rglob("*")
                                        if p.is_file() and "logs" not in p.parts)) or "(empty)"
            p = _out_path(relative_path)
            lines = p.read_text(encoding="utf-8").splitlines()
            chunk = lines[offset - 1:offset - 1 + limit]
            return "\n".join(f"{i:>6}\t{l}" for i, l in enumerate(chunk, offset)) + \
                f"\n[{len(lines)} lines total]"
        except Exception as e:  # noqa: BLE001
            return f"ERROR: {e}"

    return [list_roots, list_files, read_file, search, recurring_incidents, write_output, read_output]


# --------------------------------------------------------------------------- #
# Claude conversation
# --------------------------------------------------------------------------- #

PROGRAM_FILES = {"SOURCES.md", "sources.json", "runbooks.json", "generated_manifest.json", GITHUB_REFS}

HARNESS = """\
# Harness notes (from the runbook generator program)

You are running inside a Python program, not an interactive coding agent. You
have only these tools: list_roots, list_files, read_file, search,
recurring_incidents, write_output, read_output. There is no shell and no network:
ground rule 1 is enforced by the harness. Input paths are virtual
(`<alias>/<relative path>`); cite them exactly as the tools print them, e.g.
`{example}:42`.

The program has already written SOURCES.md and sources.json (SHA-256 hashes) to
OUTPUT_DIR; don't rewrite them. It also merges per-runbook JSON fragments into
runbooks.json, so write the fragment for each runbook as instructed below.

Each runbook's machine-readable fragment goes to `runbooks/<NN>.json`:
{{
  "id": "RB-{app_id}-<NN>", "number": <int>, "type": "<Runbook type>",
  "file": "runbooks/<NN>-<slug>.md", "applicable": true,
  "not_applicable_reason": null, "version": "0.1",
  "status": "Draft: SME review required", "generated": "{today}",
  "next_review_due": "{review_due}", "last_evidence_date": "YYYY-MM-DD",
  "sources": ["<alias/path>", ...],
  "steps": [{{"step": 1, "section": "<heading>", "action": "...",
             "command": "<command or UI path or null>", "expected": "...",
             "source": "<alias/path:line | doc § section | null>",
             "confidence": "Evidenced|Inferred|Gap", "destructive": false,
             "approval": null, "precheck": null, "rollback": null,
             "verification": null, "blocked": false}}],
  "gaps": [{{"gap": "...", "why": "...", "who": "<role>"}}],
  "findings": [{{"kind": "security|doc_code_conflict|recurring_defect|pipeline_truth|automation_candidate|unreadable",
                "detail": "...", "location": "<alias/path:line>"}}]
}}
For a non-applicable type set "applicable": false, give the reason, and leave steps empty.

Generated date: {today}. Next review due: {review_due}.
Work efficiently: use search to find evidence before reading whole files, and
read only the parts you need. Finish with a short plain-text summary.
"""


def _azure_token_provider(scope: str):
    try:
        from azure.identity import DefaultAzureCredential, get_bearer_token_provider
    except ImportError:
        sys.exit("auth = \"entra\" needs azure-identity: py -m pip install azure-identity")
    return get_bearer_token_provider(DefaultAzureCredential(), scope)


def make_claude_client(cfg: Config):
    """Anthropic SDK client for the configured Claude platform."""
    import anthropic

    o = cfg.provider_opts
    if cfg.provider == "anthropic":
        return anthropic.Anthropic(max_retries=5)
    if cfg.provider == "foundry":
        kw: dict[str, Any] = {"max_retries": 5}
        if o.get("base_url"):
            kw["base_url"] = o["base_url"]
        else:
            kw["resource"] = o.get("resource") or os.environ.get("ANTHROPIC_FOUNDRY_RESOURCE")
            if not kw["resource"]:
                sys.exit("provider = foundry needs [foundry] resource = \"<Foundry resource name>\" (or base_url)")
        if str(o.get("auth", "api_key")).lower() == "entra":
            kw["azure_ad_token_provider"] = _azure_token_provider(o.get("scope", AZURE_SCOPE))
        else:
            key = os.environ.get(o.get("api_key_env", "ANTHROPIC_FOUNDRY_API_KEY"))
            if not key:
                sys.exit(f"Set {o.get('api_key_env', 'ANTHROPIC_FOUNDRY_API_KEY')} or use auth = \"entra\"")
            kw["api_key"] = key
        return anthropic.AnthropicFoundry(**kw)
    if cfg.provider == "bedrock":
        kw = {"aws_region": o.get("aws_region") or os.environ.get("AWS_REGION"), "max_retries": 5}
        if not kw["aws_region"]:
            sys.exit("provider = bedrock needs [bedrock] aws_region")
        if o.get("aws_profile"):
            kw["aws_profile"] = o["aws_profile"]
        return anthropic.AnthropicBedrockMantle(**kw)
    if cfg.provider == "vertex":
        if not (o.get("project_id") and o.get("region")):
            sys.exit("provider = vertex needs [vertex] project_id and region")
        return anthropic.AnthropicVertex(project_id=o["project_id"], region=o["region"], max_retries=5)
    raise ValueError(cfg.provider)


def _claude_model_id(cfg: Config) -> str:
    if cfg.provider == "bedrock" and not cfg.model.startswith(("anthropic.", "arn:", "us.", "eu.", "global.")):
        return "anthropic." + cfg.model
    return cfg.model


def run_agent(cfg: Config, sb: Sandbox, label: str, user_msg: str, verbose: bool) -> dict[str, Any]:
    log = RunLog(cfg.output_dir, label)
    today = dt.date.today()
    example = next(iter(sb.roots)) + "/path/to/file"
    system = render_prompt(cfg) + "\n\n" + HARNESS.format(
        example=example, app_id=cfg.app_id, today=today.isoformat(),
        review_due=(today + dt.timedelta(days=90)).isoformat())
    tools = make_tools(sb, cfg, log, verbose)
    print(f"\n▶ {label}: provider={cfg.provider} model={cfg.model} effort={cfg.effort}  (log: {log.path})")
    t0 = time.time()
    if cfg.provider == "azure_openai":
        res = _run_azure_openai(cfg, system, user_msg, tools, log, verbose)
    else:
        res = _run_claude(cfg, system, user_msg, tools, log, verbose)
    usage = res["usage"]
    secs = int(time.time() - t0)
    print(f"✔ {label} done in {secs}s · tokens in={usage.get('input_tokens', 0):,} "
          f"(cache read {usage.get('cache_read_input_tokens', 0):,}) out={usage.get('output_tokens', 0):,}")
    log.write(event="done", stop_reason=res["stop_reason"], usage=usage, seconds=secs,
              summary=res["summary"][:4000])
    return res


def _run_claude(cfg: Config, system: str, user_msg: str, tools: list, log: RunLog,
                verbose: bool) -> dict[str, Any]:
    import anthropic

    client = make_claude_client(cfg)
    first_party = cfg.provider == "anthropic"
    betas = ["compact-2026-01-12"]
    extra: dict[str, Any] = {}
    if first_party:
        # Server-side refusal fallback exists only on the first-party Claude API.
        betas.append("server-side-fallback-2026-07-01")
        extra["fallbacks"] = "default"
    usage: dict[str, int] = defaultdict(int)
    final_text = ""
    stop = None
    runner = client.beta.messages.tool_runner(
        model=_claude_model_id(cfg),
        max_tokens=64000,
        system=system,
        messages=[{"role": "user", "content": user_msg}],
        tools=tools,
        max_iterations=cfg.max_iterations,
        stream=True,
        thinking={"type": "adaptive"},
        output_config={"effort": cfg.effort},
        cache_control={"type": "ephemeral"},
        betas=betas,
        context_management={"edits": [{"type": "compact_20260112"}]},
        **extra,
    )
    try:
        for stream in runner:
            msg = stream.get_final_message()
            stop = msg.stop_reason
            u = msg.usage
            for k in ("input_tokens", "output_tokens", "cache_read_input_tokens",
                      "cache_creation_input_tokens"):
                usage[k] += getattr(u, k, 0) or 0
            texts = [b.text for b in msg.content if getattr(b, "type", "") == "text" and b.text.strip()]
            if texts:
                final_text = "\n".join(texts)
                if verbose:
                    print("   » " + final_text[:300].replace("\n", " "))
            log.write(event="turn", stop_reason=stop, usage=dict(usage))
            if stop == "refusal":
                det = getattr(msg, "stop_details", None)
                print(f"   ! request declined ({getattr(det, 'category', None)}); stopping this step")
                break
    except anthropic.APIConnectionError as e:
        sys.exit(f"Network error talking to the API: {_root_cause(e)}")
    except anthropic.AuthenticationError:
        sys.exit(f"Authentication failed for provider '{cfg.provider}'. Check its credentials "
                 "(ANTHROPIC_API_KEY / ant auth login, Foundry key or Entra login, AWS or GCP login).")
    except anthropic.NotFoundError as e:
        sys.exit(f"Model or deployment not found ({_claude_model_id(cfg)}): {e.message}")
    except anthropic.RateLimitError as e:
        sys.exit(f"Rate limited: {e}")
    except anthropic.APIStatusError as e:
        sys.exit(f"API error {e.status_code}: {e.message}")

    if stop == "tool_use":
        print(f"   ! stopped at max_iterations={cfg.max_iterations}; re-run this step or raise --max-iterations")
    return {"usage": dict(usage), "summary": final_text, "stop_reason": stop}


def make_azure_openai_client(cfg: Config):
    try:
        from openai import AzureOpenAI
    except ImportError:
        sys.exit("provider = azure_openai needs the OpenAI SDK: py -m pip install openai")
    o = cfg.provider_opts
    endpoint = o.get("endpoint") or os.environ.get("AZURE_OPENAI_ENDPOINT")
    api_version = o.get("api_version") or os.environ.get("OPENAI_API_VERSION")
    if not endpoint or not api_version:
        sys.exit("provider = azure_openai needs [azure_openai] endpoint and api_version "
                 "(or AZURE_OPENAI_ENDPOINT / OPENAI_API_VERSION)")
    kw: dict[str, Any] = {"azure_endpoint": endpoint, "api_version": api_version, "max_retries": 5}
    if str(o.get("auth", "api_key")).lower() == "entra":
        kw["azure_ad_token_provider"] = _azure_token_provider(o.get("scope", AZURE_SCOPE))
    elif str(o.get("auth", "api_key")).lower() == "api_key":
        key = os.environ.get(o.get("api_key_env", "AZURE_OPENAI_API_KEY"))
        if not key:
            sys.exit(f"Set {o.get('api_key_env', 'AZURE_OPENAI_API_KEY')} or use auth = \"entra\"")
        kw["api_key"] = key
    else:
        sys.exit('[azure_openai] auth must be "api_key" or "entra". Keep the key itself out of '
                 "the config: put it in the AZURE_OPENAI_API_KEY environment variable.")
    return AzureOpenAI(**kw)


def _clear_old_tool_results(messages: list[dict[str, Any]], keep_last: int) -> int:
    """Context editing for providers without server-side compaction: blank out
    older tool outputs (the model can re-read a file if it needs it again)."""
    idx = [i for i, m in enumerate(messages) if m.get("role") == "tool"
           and not str(m.get("content", "")).startswith("[cleared")]
    cleared = 0
    for i in idx[:-keep_last] if keep_last else idx:
        messages[i]["content"] = "[cleared to save context; call the tool again if you still need this]"
        cleared += 1
    return cleared


def _run_azure_openai(cfg: Config, system: str, user_msg: str, tools: list, log: RunLog,
                      verbose: bool) -> dict[str, Any]:
    """Manual tool-calling loop over Azure OpenAI Chat Completions, reusing the
    same sandboxed tool objects (their JSON schemas and .call())."""
    import openai

    client = make_azure_openai_client(cfg)
    o = cfg.provider_opts
    by_name = {t.name: t for t in tools}
    oa_tools = [{"type": "function",
                 "function": {"name": t.name, "description": t.description, "parameters": t.input_schema}}
                for t in tools]
    messages: list[dict[str, Any]] = [
        {"role": o.get("system_role", "system"), "content": system},
        {"role": "user", "content": user_msg},
    ]
    params: dict[str, Any] = {"model": cfg.model, "tools": oa_tools,
                              "max_completion_tokens": int(o.get("max_completion_tokens", 32000))}
    reasoning = o.get("reasoning_effort", cfg.effort if o.get("reasoning_model", True) else None)
    if reasoning:
        # Reasoning models accept low/medium/high; map the Claude-style extremes.
        params["reasoning_effort"] = {"xhigh": "high", "max": "high"}.get(reasoning, reasoning)
    context_limit = int(o.get("context_limit_tokens", 200_000))
    usage: dict[str, int] = defaultdict(int)
    final_text, stop = "", None

    for _ in range(cfg.max_iterations):
        try:
            resp = client.chat.completions.create(messages=messages, **params)
        except openai.AuthenticationError:
            sys.exit("Azure OpenAI authentication failed: check the API key or Entra ID login.")
        except openai.NotFoundError as e:
            sys.exit(f"Azure OpenAI deployment '{cfg.model}' not found: {e.message}")
        except openai.BadRequestError as e:
            sys.exit(f"Azure OpenAI rejected the request (check reasoning_effort / api_version "
                     f"for this deployment): {e.message}")
        except openai.RateLimitError as e:
            sys.exit(f"Azure OpenAI rate limited: {e}")
        except openai.APIConnectionError as e:
            sys.exit(f"Network error talking to Azure OpenAI: {_root_cause(e)}")
        except openai.APIStatusError as e:
            sys.exit(f"Azure OpenAI error {e.status_code}: {e.message}")

        choice = resp.choices[0]
        msg = choice.message
        stop = choice.finish_reason
        if resp.usage:
            usage["input_tokens"] += resp.usage.prompt_tokens or 0
            usage["output_tokens"] += resp.usage.completion_tokens or 0
            det = getattr(resp.usage, "prompt_tokens_details", None)
            usage["cache_read_input_tokens"] += (getattr(det, "cached_tokens", 0) or 0) if det else 0
        if msg.content and msg.content.strip():
            final_text = msg.content
            if verbose:
                print("   » " + final_text[:300].replace("\n", " "))
        log.write(event="turn", stop_reason=stop, usage=dict(usage))

        assistant: dict[str, Any] = {"role": "assistant", "content": msg.content or ""}
        if msg.tool_calls:
            assistant["tool_calls"] = [
                {"id": tc.id, "type": "function",
                 "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                for tc in msg.tool_calls]
        messages.append(assistant)

        if stop == "content_filter":
            print("   ! Azure content filter stopped the response; stopping this step")
            break
        if not msg.tool_calls:
            if stop == "length":
                print("   ! response hit max_completion_tokens; raise it in [azure_openai]")
            break
        for tc in msg.tool_calls:
            tool = by_name.get(tc.function.name)
            if tool is None:
                out = f"ERROR: unknown tool {tc.function.name}"
            else:
                try:
                    args = json.loads(tc.function.arguments or "{}")
                    out = tool.call(args)
                except json.JSONDecodeError as e:
                    out = f"ERROR: tool arguments were not valid JSON ({e}); send them again"
                except Exception as e:  # noqa: BLE001  (schema/type errors from the tool wrapper)
                    out = f"ERROR: {e}"
            messages.append({"role": "tool", "tool_call_id": tc.id, "content": str(out)})

        last_prompt = resp.usage.prompt_tokens if resp.usage else 0
        if last_prompt > 0.75 * context_limit:
            n = _clear_old_tool_results(messages, keep_last=8)
            if verbose and n:
                print(f"   · cleared {n} old tool results (prompt was {last_prompt:,} tokens)")
    else:
        stop = "max_iterations"
        print(f"   ! stopped at max_iterations={cfg.max_iterations}; re-run this step or raise --max-iterations")
    return {"usage": dict(usage), "summary": final_text, "stop_reason": stop}


def roots_block(sb: Sandbox) -> str:
    return "\n".join(f"- `{a}/` → {sb.kinds[a]}" for a in sb.roots)


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #

def prepare(cfg: Config, include_prev: bool = False) -> tuple[Sandbox, list[dict[str, Any]]]:
    sb = Sandbox(cfg, include_prev=include_prev)
    print(f"Hashing sources under {len(sb.roots)} root(s)…")
    rows = build_sources(sb)
    write_sources(cfg, rows, sb.roots)
    print(f"  {len(rows)} files → {cfg.output_dir / 'SOURCES.md'}")
    return sb, rows


def cmd_render(cfg: Config, args: argparse.Namespace) -> None:
    cfg.output_dir.mkdir(parents=True, exist_ok=True)
    p = cfg.output_dir / "PROMPT_FILLED.md"
    p.write_text(render_prompt(cfg), encoding="utf-8")
    print(f"Filled prompt written to {p}")


def cmd_inventory(cfg: Config, args: argparse.Namespace) -> None:
    sb, rows = prepare(cfg)
    msg = f"""Run **Phase 0 only** (Inventory). Don't write any runbook yet.

Input roots:
{roots_block(sb)}

Source list (from SOURCES.md, oldest first):
{source_tree_summary(rows)}

{"OPS_DATA is supplied: call recurring_incidents for step 4." if cfg.ops_data else "No OPS_DATA: skip step 4 and say so."}

Write `PHASE0_INVENTORY.md` to OUTPUT_DIR with these sections:
1. Inputs (name, type, date, one-line purpose; oldest first)
2. Code inventory (languages/frameworks, deployable units, IaC/manifests, pipelines and stages, config files, monitoring/alert definitions, job schedules, certificate/key/secret references by name only, external endpoints and queues), each item cited
3. Document inventory (components, data flows, dependencies, environments, SLAs/SLOs, DR statements, support model, escalation paths, existing procedures), cited
4. Recurring incident patterns (if OPS_DATA)
5. Component and dependency map (Mermaid diagram plus text list with sources)
6. Coverage plan: a table with all 16 runbook types: evidence available, main unknowns, can draft (Yes / Partial / Not applicable + reason)
7. Doc versus code conflicts found so far
8. Security findings so far (file:line only, never values)
9. Files you could not read, and why
Then stop: the SME reviews this before drafting."""
    res = run_agent(cfg, sb, "phase0-inventory", msg, args.verbose)
    print(f"\nReview {cfg.output_dir / 'PHASE0_INVENTORY.md'}; put corrections in "
          f"{cfg.output_dir / 'REVIEW_NOTES.md'} (optional), then run `draft`.")
    if res["summary"]:
        print("\n" + res["summary"])


def _selected_types(spec: str | None) -> list[tuple[int, str, str]]:
    if not spec:
        return RUNBOOK_TYPES
    wanted = {int(x) for x in re.split(r"[,\s]+", spec) if x.strip()}
    return [t for t in RUNBOOK_TYPES if t[0] in wanted]


def cmd_draft(cfg: Config, args: argparse.Namespace) -> None:
    inv = cfg.output_dir / "PHASE0_INVENTORY.md"
    if not inv.is_file():
        sys.exit("PHASE0_INVENTORY.md not found: run `inventory` first and review it.")
    sb = Sandbox(cfg)
    if not (cfg.output_dir / "sources.json").is_file():
        prepare(cfg)
    notes = cfg.output_dir / "REVIEW_NOTES.md"
    notes_txt = notes.read_text(encoding="utf-8") if notes.is_file() else "(none)"
    inventory = inv.read_text(encoding="utf-8")
    for num, slug, title in _selected_types(args.types):
        frag = cfg.output_dir / "runbooks" / f"{num:02d}.json"
        if frag.exists() and not args.force:
            print(f"• skip {num:02d} {title} (exists; --force to redo)")
            continue
        ka = ("\nAlso write a ServiceNow knowledge-article version to "
              f"`knowledge_articles/{num:02d}-{slug}.html` (title, short description, "
              "body in plain HTML, category). Don't upload it." if cfg.knowledge_articles else "")
        msg = f"""Run **Phase 1 for one runbook type only**: #{num} **{title}** (see the runbook types table).

Input roots:
{roots_block(sb)}

Reviewed Phase 0 inventory (treat as your map; verify each fact against the source before citing it):
<phase0_inventory>
{inventory}
</phase0_inventory>

SME review notes on the inventory (these override the inventory where they conflict):
<review_notes>
{notes_txt}
</review_notes>

Do this:
1. Gather the evidence for this runbook type with search/read_file. Cite every step.
2. If the type applies, write `runbooks/{num:02d}-{slug}.md` using the template exactly
   (Runbook ID RB-{cfg.app_id}-{num:02d}). If it doesn't apply, still write that file with a
   one-paragraph "Not applicable" statement and the reason.
3. Write `runbooks/{num:02d}.json` (the fragment schema in the harness notes) with every step,
   gap and finding from this runbook.{ka}
4. Reply with a 3-line summary: steps by confidence, open gaps, findings."""
        run_agent(cfg, sb, f"phase1-{num:02d}-{slug}", msg, args.verbose)
    print("\nDrafting done. Next: `finalize`.")


def merge_fragments(cfg: Config) -> list[dict[str, Any]]:
    rbdir = cfg.output_dir / "runbooks"
    items = []
    for num, slug, title in RUNBOOK_TYPES:
        f = rbdir / f"{num:02d}.json"
        if f.is_file():
            try:
                items.append(json.loads(f.read_text(encoding="utf-8")))
            except json.JSONDecodeError as e:
                print(f"  ! {f.name} is not valid JSON: {e}")
    doc = {"app": cfg.app_name, "app_id": cfg.app_id, "generated": dt.date.today().isoformat(),
           "runbooks": items}
    (cfg.output_dir / "runbooks.json").write_text(json.dumps(doc, indent=2), encoding="utf-8")
    return items


def coverage_table(items: list[dict[str, Any]]) -> str:
    rows = ["| Runbook ID | # | Type | Status | Steps | Evidenced | Inferred | Gap | Open gaps | Not applicable reason |",
            "|---|---|---|---|---|---|---|---|---|---|"]
    by_num = {it.get("number"): it for it in items}
    for num, slug, title in RUNBOOK_TYPES:
        it = by_num.get(num)
        if not it:
            rows.append(f"| — | {num} | {title} | NOT GENERATED | | | | | | |")
            continue
        steps = it.get("steps", [])
        c = defaultdict(int)
        for s in steps:
            c[s.get("confidence", "?")] += 1
        n = len(steps) or 1
        pct = lambda k: f"{100 * c[k] // n}%" if steps else "—"  # noqa: E731
        rows.append(f"| {it.get('id', '')} | {num} | {title} | {it.get('status', '')} | {len(steps)} | "
                    f"{pct('Evidenced')} | {pct('Inferred')} | {pct('Gap')} | {len(it.get('gaps', []))} | "
                    f"{'' if it.get('applicable', True) else it.get('not_applicable_reason', '')} |")
    return "\n".join(rows)


def cmd_finalize(cfg: Config, args: argparse.Namespace) -> None:
    items = merge_fragments(cfg)
    print(f"Merged {len(items)} runbook fragment(s) → runbooks.json")
    sb = Sandbox(cfg)
    findings = [dict(f, runbook=it.get("id")) for it in items for f in it.get("findings", [])]
    gaps = [dict(g, runbook=it.get("id")) for it in items for g in it.get("gaps", [])]
    msg = f"""Run **Phase 2 (cross-checks) and Phase 3 (outputs)**. The runbooks are already drafted
under `runbooks/` (use read_output to read them). runbooks.json and SOURCES.md are already written by
the program; don't rewrite them.

Input roots:
{roots_block(sb)}

Coverage computed by the program from the fragments (use these numbers in INDEX.md):
{coverage_table(items)}

Gaps collected from fragments ({len(gaps)}):
{json.dumps(gaps, indent=1)[:60000]}

Findings collected from fragments ({len(findings)}):
{json.dumps(findings, indent=1)[:60000]}

Do this:
1. Perform all seven Phase 2 cross-checks against the inputs (re-search the code for alert rules,
   scheduled jobs, certificate/secret references, pipeline security stages) and the drafted runbooks.
   Where a runbook misses something, fix that runbook file and its `runbooks/<NN>.json` fragment.
2. Write `INDEX.md`: the coverage table above (updated if you changed runbooks) plus not-applicable reasons.
3. Write `GAPS_AND_FINDINGS.md`: gaps grouped by owner role; security findings (locations only);
   doc vs code conflicts; recurring defects recommended for Problem records; automation or
   elimination candidates (advisory); and a "Phase 2 cross-check results" section with one
   pass/fail line per check.
4. Write `SUMMARY.md` with the "What to hand back" item 3 and 4 content.
5. Reply with that summary."""
    run_agent(cfg, sb, "phase2-3-finalize", msg, args.verbose)
    items = merge_fragments(cfg)  # pick up any fixes
    print(f"Re-merged runbooks.json ({len(items)} runbooks). Next: `check`.")


def cmd_maintain(cfg: Config, args: argparse.Namespace) -> None:
    if not cfg.previous_run:
        sys.exit("maintain needs previous_run (config) or --previous-run")
    prev = cfg.previous_run
    old = load_previous_sources(prev)
    if not old:
        sys.exit(f"No sources.json/SOURCES.md found in {prev}")
    sb, rows = prepare(cfg, include_prev=True)
    new = {r["path"]: r.get("sha256", "") for r in rows}
    added = sorted(set(new) - set(old))
    removed = sorted(set(old) - set(new))
    changed = sorted(p for p in set(new) & set(old) if new[p] != old[p])

    prev_rb = {}
    pj = prev / "runbooks.json"
    if pj.is_file():
        prev_rb = json.loads(pj.read_text(encoding="utf-8"))
    affected = defaultdict(list)
    touched = set(changed) | set(removed)
    for it in prev_rb.get("runbooks", []):
        for s in it.get("steps", []):
            src = (s.get("source") or "")
            for t in touched:
                if src.startswith(t):
                    affected[it.get("id")].append({"step": s.get("step"), "source": src,
                                                   "change": "removed" if t in removed else "changed"})
    # Hand-edit detection: previous output files whose content differs from what was generated.
    hand_edits = []
    man_p = prev / "generated_manifest.json"
    if man_p.is_file():
        man = json.loads(man_p.read_text(encoding="utf-8"))
        for rel, h in man.items():
            f = prev / rel
            if f.is_file() and sha256_file(f) != h:
                hand_edits.append(rel)
    # Stale: past next review due.
    today = dt.date.today().isoformat()
    stale = [it.get("id") for it in prev_rb.get("runbooks", [])
             if (it.get("next_review_due") or "9999") < today]

    diff_md = ["# Source changes since previous run", "",
               f"Previous run: `{prev}`", "",
               f"## Added ({len(added)})", *[f"- `{p}`" for p in added], "",
               f"## Changed ({len(changed)})", *[f"- `{p}`" for p in changed], "",
               f"## Removed ({len(removed)})", *[f"- `{p}`" for p in removed], "",
               "## Previously cited steps affected", "```json", json.dumps(affected, indent=1), "```", "",
               f"## Hand-edited after generation ({len(hand_edits)})", *[f"- `prev/{p}`" for p in hand_edits], "",
               f"## Past next-review-due ({len(stale)})", *[f"- {s}" for s in stale]]
    (cfg.output_dir / "SOURCE_DIFF.md").write_text("\n".join(diff_md) + "\n", encoding="utf-8")
    print(f"Sources: +{len(added)} ~{len(changed)} -{len(removed)}; "
          f"{sum(len(v) for v in affected.values())} cited steps affected; "
          f"{len(hand_edits)} hand edits → SOURCE_DIFF.md")

    msg = f"""Run **Phase 4 (maintenance mode)**. The previous run is readable under the `prev/` root
(its runbooks, runbooks.json, INDEX.md, GAPS_AND_FINDINGS.md). Write the new version to OUTPUT_DIR;
never modify `prev/`.

Input roots:
{roots_block(sb)}

The program already compared hashes (do not recompute):
{chr(10).join(diff_md)}

Do this:
1. For every changed/removed source, re-check each affected step against the new content; for
   added sources, decide which runbooks they affect.
2. Write `CHANGES.md`: per runbook, steps now wrong, new steps, steps whose source disappeared,
   each with old text, proposed text and cited evidence.
3. For every runbook (changed or not) write the new `runbooks/<NN>-<slug>.md` and `runbooks/<NN>.json`
   to OUTPUT_DIR: unchanged ones are copied as-is; changed ones get the version raised (0.x → 0.x+1;
   an approved runbook becomes a new draft version) and Status reset to "Draft: SME review required".
4. Hand-edited files listed above: keep the SME's edit, and list each for reconciliation in CHANGES.md.
5. Flag stale runbooks (past next review due, or citing a source older than the newest architecture doc).
6. Rewrite INDEX.md and GAPS_AND_FINDINGS.md for the new version.
7. Reply with a short summary."""
    run_agent(cfg, sb, "phase4-maintain", msg, args.verbose)
    merge_fragments(cfg)


def cmd_check(cfg: Config, args: argparse.Namespace) -> int:
    out = cfg.output_dir
    items = merge_fragments(cfg)
    problems: list[str] = []
    warns: list[str] = []
    by_num = {it.get("number"): it for it in items}
    for num, slug, title in RUNBOOK_TYPES:
        it = by_num.get(num)
        if not it:
            problems.append(f"AC1: runbook {num:02d} ({title}) has no fragment")
            continue
        if not (out / it.get("file", f"runbooks/{num:02d}-{slug}.md")).is_file():
            problems.append(f"AC1: {it.get('file')} missing")
        if not it.get("applicable", True) and not it.get("not_applicable_reason"):
            problems.append(f"AC1: {it.get('id')} not applicable without a reason")
        for s in it.get("steps", []):
            sid = f"{it.get('id')} step {s.get('step')}"
            conf = s.get("confidence")
            if conf not in ("Evidenced", "Inferred", "Gap"):
                problems.append(f"AC2: {sid} has no valid confidence label")
            if conf == "Evidenced" and not s.get("source"):
                problems.append(f"AC2: {sid} is Evidenced without a citation")
            if s.get("destructive") and not s.get("blocked"):
                miss = [k for k in ("approval", "precheck", "rollback", "verification") if not s.get(k)]
                if miss:
                    problems.append(f"AC4: {sid} destructive, not BLOCKED, missing {', '.join(miss)}")
    for f in out.rglob("*"):
        if not f.is_file() or "logs" in f.parts or f.suffix not in (".md", ".json", ".html"):
            continue
        if f.name in ("SOURCES.md", "sources.json", "generated_manifest.json", "PROMPT_FILLED.md", GITHUB_REFS):
            continue
        block, warn = scan_text(f.read_text(encoding="utf-8", errors="replace"))
        rel = f.relative_to(out).as_posix()
        problems += [f"AC3: {rel}: {b}" for b in block]
        warns += [f"AC3: {rel}: {w}" for w in warn]
    for name in ("INDEX.md", "GAPS_AND_FINDINGS.md", "runbooks.json", "SOURCES.md"):
        if not (out / name).is_file():
            problems.append(f"Phase 3: {name} missing")

    md = [f"# {cfg.app_name}: Validation report", "", f"Run {dt.datetime.now():%Y-%m-%d %H:%M}", "",
          "## Coverage", "", coverage_table(items), "",
          f"## Problems ({len(problems)})", *[f"- {p}" for p in problems], "",
          f"## Warnings ({len(warns)})", *[f"- {w}" for w in warns], "",
          "Checks AC5-AC8 (alert/job coverage, conflicts, recurring defects, maintenance tracing) "
          "need judgement; see the Phase 2 section of GAPS_AND_FINDINGS.md."]
    (out / "VALIDATION_REPORT.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(coverage_table(items))
    print(f"\n{len(problems)} problem(s), {len(warns)} warning(s) → {out / 'VALIDATION_REPORT.md'}")
    for p in problems[:40]:
        print("  ✗", p)
    return 1 if problems else 0


def cmd_github_check(cfg: Config, args: argparse.Namespace) -> int:
    """Check gh's sign-in and access to each github_repos entry. Reads repository metadata only; downloads nothing."""
    if not cfg.github_repos:
        print("No github_repos in the config.")
        return 0
    try:
        account = gh_source.check_auth(cfg.github_host)
    except gh_source.GitHubError as e:
        print(f"✗ {e}")
        return 1
    print(f"gh is signed in to {cfg.github_host} as {account}\n")
    pins = {}
    refs = cfg.output_dir / GITHUB_REFS
    if refs.is_file():
        pins = json.loads(refs.read_text(encoding="utf-8"))
    bad = 0
    for spec in cfg.github_repos:
        repo, host, ref = gh_source.parse_target(spec, cfg.github_host)
        gh = gh_source.Gh(host)
        try:
            m = gh.api(f"repos/{repo}") or {}
            pin = (pins.get(spec) or {}).get("sha", "")
            print(f"✓ {m.get('full_name', repo):45} {ref or m.get('default_branch', '?'):12} "
                  f"{int(m.get('size') or 0) // 1024:>6} MB  {'archived ' if m.get('archived') else ''}"
                  f"{'pinned ' + pin[:12] if pin else 'not pinned yet'}")
        except gh_source.GhApiError as e:
            bad += 1
            why = "not found, or this account cannot read it" if e.http in (403, 404) else str(e)
            print(f"✗ {repo:45} {why}")
    if bad:
        print(f"\n{bad} of {len(cfg.github_repos)} not readable as {account}. Sign gh in with an account that can read "
              "them (`gh auth login`, or `gh auth switch`), and if the organization uses SAML SSO, authorize gh for it.")
    return 1 if bad else 0


def cmd_all(cfg: Config, args: argparse.Namespace) -> int:
    if not args.skip_review:
        sys.exit("`all` skips the Phase 0 SME review stop. Pass --skip-review to confirm, "
                 "or run inventory, review, then draft/finalize/check.")
    cmd_inventory(cfg, args)
    cmd_draft(cfg, args)
    cmd_finalize(cfg, args)
    return cmd_check(cfg, args)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="Generate and maintain evidence-cited runbooks with Claude, "
                    "from RUNBOOK_MAINTENANCE_AUTOMATION_PROMPT.md.")
    ap.add_argument("command", choices=["render", "inventory", "draft", "finalize", "check",
                                        "maintain", "all", "github-check"])
    ap.add_argument("-c", "--config", help="TOML config file with the prompt parameters")
    g = ap.add_argument_group("prompt parameters (override the config file)")
    g.add_argument("--app-name", dest="app_name")
    g.add_argument("--app-short", dest="app_short", help="Short ID used in RB-<APP>-<NN>")
    g.add_argument("--input-dir", dest="input_dir")
    g.add_argument("--code-repo", dest="code_repos", action="append", help="Repeat per repository")
    g.add_argument("--github-repo", dest="github_repos", action="append",
                   help="owner/name[@ref] read through gh instead of a local clone; repeatable")
    g.add_argument("--ops-data", dest="ops_data", action="append", help="CSV/XLSX file or folder; repeatable")
    g.add_argument("--output-dir", dest="output_dir")
    g.add_argument("--owner-role", dest="owner_role")
    g.add_argument("--previous-run", dest="previous_run")
    g.add_argument("--prompt", dest="prompt_path", help=f"Prompt file (default {DEFAULT_PROMPT})")
    r = ap.add_argument_group("run options")
    r.add_argument("--provider", choices=PROVIDERS,
                   help="LLM provider (default anthropic); platform settings go in the config's "
                        "[foundry] / [bedrock] / [vertex] / [azure_openai] section")
    r.add_argument("--model", help=f"Model ID or deployment name (default {DEFAULT_MODEL}; "
                                   "for azure_openai, the deployment)")
    r.add_argument("--effort", choices=["low", "medium", "high", "xhigh", "max"])
    r.add_argument("--max-iterations", dest="max_iterations", type=int,
                   help="Tool-call rounds per conversation (default 150)")
    r.add_argument("--types", help="Runbook numbers to draft, e.g. '1,4,10' (default all 16)")
    r.add_argument("--force", action="store_true", help="Redraft runbooks that already exist")
    r.add_argument("--knowledge-articles", action="store_true",
                   help="Also write ServiceNow knowledge-article HTML (not uploaded)")
    r.add_argument("--skip-review", action="store_true", help="Allow `all` to skip the Phase 0 review stop")
    r.add_argument("--skip-missing-repos", action="store_true",
                   help="Run with the code repos that exist instead of failing on missing ones")
    r.add_argument("--refresh-github", dest="refresh_github", action="store_true",
                   help="Read the latest commit of each GitHub repository instead of the one pinned in github_refs.json")
    r.add_argument("-v", "--verbose", action="store_true", help="Print every tool call")
    return ap


def use_os_trust_store() -> None:
    """Verify TLS against the OS certificate store instead of Python's bundled CAs.

    Needed where antivirus or a corporate proxy re-signs HTTPS traffic (e.g. Norton
    Web/Mail Shield, Zscaler): Windows trusts that root, Python's certifi bundle doesn't,
    and every API call fails with CERTIFICATE_VERIFY_FAILED ("Connection error")."""
    if os.environ.get("RUNBOOK_GEN_NO_TRUSTSTORE"):
        return
    try:
        import truststore
        truststore.inject_into_ssl()
    except ImportError:
        pass


def _root_cause(e: BaseException) -> str:
    c: BaseException | None = e
    while c is not None and (c.__cause__ or c.__context__):
        c = c.__cause__ or c.__context__
    msg = f"{type(c).__name__}: {c}" if c is not None and c is not e else str(e)
    if "CERTIFICATE_VERIFY_FAILED" in msg:
        msg += ("\n  TLS interception (antivirus or proxy) is likely: run "
                "`py -m pip install truststore` so the Windows certificate store is used.")
    return msg


def check_provider_sdk(cfg: Config) -> None:
    """Fail before any download if the provider's SDK isn't in this Python."""
    import importlib.util
    need = ["openai"] if cfg.provider == "azure_openai" else ["anthropic"]
    if str((getattr(cfg, "provider_opts", None) or {}).get("auth", "api_key")).lower() == "entra":
        need.append("azure.identity")

    def present(m: str) -> bool:
        try:
            return importlib.util.find_spec(m) is not None
        except ModuleNotFoundError:
            return False
    missing = [m for m in need if not present(m)]
    if missing:
        pkgs = " ".join({"azure.identity": "azure-identity"}.get(m, m) for m in missing)
        sys.exit(f"provider = {cfg.provider!r} needs {', '.join(missing)}, which this Python "
                 f"({sys.executable}) doesn't have.\nInstall it with:\n"
                 f"  \"{sys.executable}\" -m pip install {pkgs}")


def main(argv: list[str] | None = None) -> int:
    use_os_trust_store()
    args = build_parser().parse_args(argv)
    cfg = load_config(args)
    validate_config(cfg, need_inputs=args.command not in ("render", "check", "github-check"))
    if args.command not in ("render", "check", "github-check"):
        check_provider_sdk(cfg)
    cfg.output_dir.mkdir(parents=True, exist_ok=True)
    if args.command not in ("render", "check", "github-check") and cfg.provider == "anthropic" and not (
            os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN")):
        print("Note: ANTHROPIC_API_KEY is not set; relying on an `ant auth login` profile if present.")
    handlers = {"render": cmd_render, "inventory": cmd_inventory, "draft": cmd_draft,
                "finalize": cmd_finalize, "check": cmd_check, "maintain": cmd_maintain, "all": cmd_all,
                "github-check": cmd_github_check}
    rc = handlers[args.command](cfg, args)
    return int(rc or 0)


if __name__ == "__main__":
    sys.exit(main())
