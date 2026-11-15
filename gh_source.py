"""Read GitHub repositories through the GitHub CLI (gh), the way the Reliability Assistant's scan does.

    repo = fetch("owner/name", host="github.com", keep=lambda path, size: True)

- The commit is resolved first (default branch, or owner/name@ref), so every citation points at one fixed commit.
- Files come from the commit's tarball, read in memory and never written to disk. When the repository is too big for
  one archive, the file list comes from the git trees API and only the kept files are downloaded, one by one.
- Two documents are added under `_github/`: repository signals (default branch, branch protection and rulesets,
  environments and their protection rules, recent releases and deployments) and open security alerts (Dependabot,
  code scanning, secret scanning). For a secret-scanning alert only the secret type and location are kept, never the
  secret itself.

Authentication is gh's own: `gh auth login`, or GH_TOKEN / GH_ENTERPRISE_TOKEN in the environment. This module never
reads, passes or logs a token. Only `gh api` GET requests are made; nothing is cloned, built or run.
"""
from __future__ import annotations

import io
import json
import os
import re
import shutil
import subprocess
import tarfile
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Callable
from urllib.parse import quote

REPO = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$")
HOST = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?(?::\d{1,5})?$")
REF = re.compile(r"^(?!-)(?!.*\.\.)[A-Za-z0-9._/+-]{1,250}$")
URL = re.compile(r"^(?:https?://|git@)([^/:]+)[/:]([^/]+/[^/@]+?)(?:\.git)?/?(?:@(.+))?$")
SHA = re.compile(r"^[0-9a-f]{40}$")
GH_DIR = "_github"            # where the signals and alerts documents appear inside the repository's root

Keep = Callable[[str, int], bool]       # (path in the repository, size in bytes) -> read it?


class GitHubError(Exception):
    """The repository could not be read as asked."""


class GhUnavailable(GitHubError):
    """gh is not installed, or not signed in to the host."""


class ArchiveTooLarge(GitHubError):
    pass


class GhApiError(GitHubError):
    def __init__(self, msg: str, http: int | None = None):
        super().__init__(msg)
        self.http = http


# --------------------------------------------------------------------------- gh
def gh_binary() -> str:
    path = os.environ.get("RUNBOOK_GEN_GH") or shutil.which("gh")
    if not path or not os.path.exists(path):
        raise GhUnavailable("The GitHub CLI (gh) was not found. Install it (winget install GitHub.cli) or set "
                            "RUNBOOK_GEN_GH to gh.exe.")
    return path


def _env(host: str) -> dict:
    env = dict(os.environ)
    env.update({"GH_HOST": host, "GH_PROMPT_DISABLED": "1", "GH_NO_UPDATE_NOTIFIER": "1", "GH_SPINNER_DISABLED": "1",
                "NO_COLOR": "1", "CLICOLOR": "0"})
    return env


def _run(args: list[str], host: str, max_bytes: int | None = None, timeout: int = 120) -> bytes:
    """Run gh and return stdout (never logged: it can be file content). stderr goes into error messages; gh does not
    print tokens there."""
    try:
        proc = subprocess.Popen([gh_binary(), *args], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env=_env(host))
    except OSError as exc:
        raise GhUnavailable(f"gh could not be started: {exc.strerror or exc}") from None
    err: list[bytes] = []
    reader = threading.Thread(target=lambda: err.append(proc.stderr.read()), daemon=True)
    reader.start()
    timer = threading.Timer(timeout, proc.kill)
    timer.start()
    out, n, too_big = [], 0, False
    try:
        while chunk := proc.stdout.read(1 << 16):
            n += len(chunk)
            if max_bytes and n > max_bytes:
                too_big = True
                proc.kill()
                break
            out.append(chunk)
        proc.wait()
    finally:
        timed_out = not timer.is_alive() and not too_big
        timer.cancel()
        reader.join(5)
    if too_big:
        raise ArchiveTooLarge(f"response larger than {max_bytes // 1024 // 1024} MB")
    if proc.returncode != 0:
        if timed_out:
            raise GhApiError(f"gh {args[0]} did not finish within {timeout} s")
        text = " ".join(x.strip() for x in b"".join(err).decode("utf-8", "replace").splitlines() if x.strip())
        text = text[:400] or f"exit code {proc.returncode}"
        m = re.search(r"HTTP (\d{3})", text)
        raise GhApiError(f"gh {args[0]} failed: {text}", int(m.group(1)) if m else None)
    return b"".join(out)


def check_auth(host: str) -> str:
    """The account gh is signed in with on this host (raises GhUnavailable if none). The token is never read."""
    try:
        p = subprocess.run([gh_binary(), "auth", "status", "--hostname", host], capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=30, env=_env(host))
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GhUnavailable(f"gh auth status failed: {exc}") from None
    text = (p.stdout or "") + "\n" + (p.stderr or "")
    accounts = re.findall(r"Logged in to \S+ (?:account|as) ([^\s(]+)", text)
    if p.returncode != 0 or not accounts:
        raise GhUnavailable(f"gh is not signed in to {host}. Run `gh auth login --hostname {host}` in your own "
                            "terminal (or set GH_TOKEN / GH_ENTERPRISE_TOKEN).")
    blocks = re.split(r"(?=✓ Logged in to|X Failed to log in to)", text)
    active = next((b for b in blocks if re.search(r"Active account:\s*true", b)), "")
    m = re.search(r"(?:account|as) ([^\s(]+)", active)
    return m.group(1) if m else accounts[0]


def _json_values(raw: bytes) -> list:
    """gh --paginate prints one JSON document per page; decode them all."""
    text, dec, pos, out = raw.decode("utf-8", "replace"), json.JSONDecoder(), 0, []
    while True:
        while pos < len(text) and text[pos].isspace():
            pos += 1
        if pos >= len(text):
            return out
        val, pos = dec.raw_decode(text, pos)
        out.append(val)


class Gh:
    def __init__(self, host: str):
        self.host = host

    def api(self, path: str, paginate: bool = False, **params):
        """GET path. Query parameters go as -f fields, so no '&' or '?' is ever part of an argument we build."""
        args = ["api", "-H", "Accept: application/vnd.github+json", "-H", "X-GitHub-Api-Version: 2022-11-28"]
        if params:
            args += ["--method", "GET"] + [x for k, v in params.items() for x in ("-f", f"{k}={v}")]
        vals = _json_values(_run(args + (["--paginate"] if paginate else []) + [path], self.host))
        if paginate:
            return [x for v in vals for x in (v if isinstance(v, list) else [v])]
        return vals[0] if vals else None

    def raw(self, path: str, max_bytes: int, accept: str = "application/vnd.github+json", timeout: int = 120) -> bytes:
        return _run(["api", "-H", f"Accept: {accept}", path], self.host, max_bytes=max_bytes, timeout=timeout)


# --------------------------------------------------------------------------- targets
def parse_target(spec: str, default_host: str = "github.com") -> tuple[str, str, str]:
    """(owner/name, host, ref) from 'owner/name', 'owner/name@ref', 'host/owner/name' or a clone URL."""
    s = (spec or "").strip()
    host, ref = default_host, ""
    m = URL.match(s)
    if m:
        host, s, ref = m.group(1), m.group(2), m.group(3) or ""
    else:
        if "@" in s:
            s, ref = s.split("@", 1)
        parts = s.split("/")
        if len(parts) == 3 and "." in parts[0]:
            host, s = parts[0], "/".join(parts[1:])
    host = host.strip().lower()
    if not REPO.match(s):
        raise GitHubError(f"Not a GitHub repository: {spec!r} (expected owner/name or owner/name@ref)")
    if not HOST.match(host):
        raise GitHubError(f"Not a host name: {host!r}")
    if ref and not REF.match(ref):
        raise GitHubError(f"Not a git ref: {ref!r}")
    return s, host, ref


# --------------------------------------------------------------------------- the repository in memory
@dataclass
class GhRepo:
    spec: str
    repository: str
    host: str
    ref: str
    sha: str
    committed: str                                # ISO timestamp of the commit
    files: dict[str, bytes] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    skipped: int = 0
    fetch: str = ""                               # "archive" or "files"
    alerts: dict[str, int | None] = field(default_factory=dict)
    meta: dict = field(default_factory=dict)

    @property
    def label(self) -> str:
        return f"{self.host}/{self.repository}@{self.sha[:12]}"

    @property
    def name(self) -> str:
        return self.repository.split("/", 1)[1]

    @property
    def mtime(self) -> float:
        try:
            return datetime.fromisoformat(self.committed.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return 0.0

    # The sandbox treats a root as a folder.
    def is_file(self) -> bool:
        return False

    def is_dir(self) -> bool:
        return True

    def __str__(self) -> str:
        return self.label

    def pin(self) -> dict:
        return {"repository": self.repository, "host": self.host, "ref": self.ref, "sha": self.sha,
                "committed": self.committed, "fetch": self.fetch, "files": len(self.files),
                "skipped": self.skipped, "alerts": self.alerts, "notes": self.notes}


class _Capped(io.RawIOBase):
    """gh's stdout, stopping (ArchiveTooLarge) once more than `limit` bytes have come through."""

    def __init__(self, stream, limit: int):
        self.stream, self.limit, self.n = stream, limit, 0

    def readable(self) -> bool:
        return True

    def readinto(self, b) -> int:
        data = self.stream.read(len(b))
        self.n += len(data)
        if self.n > self.limit:
            raise ArchiveTooLarge(f"archive larger than {self.limit // 1024 // 1024} MB")
        b[:len(data)] = data
        return len(data)


def _stream_archive(gh: Gh, repo: str, sha: str, keep: Keep, limit: int, timeout: int = 1800,
                    log: Callable[[str], None] = print) -> tuple[dict[str, bytes], int]:
    """Stream the commit's tarball from gh and keep only the files `keep` accepts. The archive is read once, in order,
    and never held whole in memory or written to disk."""
    try:
        proc = subprocess.Popen([gh_binary(), "api", "-H", "Accept: application/vnd.github+json",
                                 f"repos/{repo}/tarball/{sha}"], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env=_env(gh.host))
    except OSError as exc:
        raise GhUnavailable(f"gh could not be started: {exc.strerror or exc}") from None
    err: list[bytes] = []
    reader = threading.Thread(target=lambda: err.append(proc.stderr.read()), daemon=True)
    reader.start()
    timer = threading.Timer(timeout, proc.kill)
    timer.start()
    src = _Capped(proc.stdout, limit)
    files, skipped, seen, failure = {}, 0, 0, None
    try:
        with tarfile.open(fileobj=io.BufferedReader(src, 1 << 20), mode="r|*") as tar:
            for m in tar:
                if not m.isfile():
                    continue
                seen += 1
                if seen % 5000 == 0:
                    log(f"    … {seen} files, {src.n // 1024 // 1024} MB downloaded, {len(files)} kept")
                rel = m.name.split("/", 1)[1] if "/" in m.name else ""      # drop the <owner>-<name>-<sha>/ folder
                if not rel or rel.startswith("/") or ".." in PurePosixPath(rel).parts:
                    continue
                if keep(rel, m.size):
                    files[rel] = tar.extractfile(m).read()
                else:
                    skipped += 1
    except ArchiveTooLarge:
        proc.kill()
        raise
    except (tarfile.TarError, EOFError, OSError) as exc:
        failure = exc
    finally:
        proc.kill() if proc.poll() is None else None
        proc.wait()
        timer.cancel()
        reader.join(5)
    if failure is not None or (proc.returncode not in (0, None) and not files):
        text = " ".join(x.strip() for x in b"".join(err).decode("utf-8", "replace").splitlines() if x.strip())[:400]
        raise GhApiError(f"The repository archive could not be read: {text or failure}")
    log(f"    {seen} files in the archive ({src.n // 1024 // 1024} MB), {len(files)} kept")
    return files, skipped


def _from_tree(gh: Gh, repo: str, sha: str, keep: Keep, notes: list[str], workers: int = 8,
               max_file: int = 60 * 1024 * 1024) -> tuple[dict[str, bytes], int]:
    tree = gh.api(f"repos/{repo}/git/trees/{sha}", recursive=1) or {}
    if tree.get("truncated"):
        notes.append("GitHub listed only part of this very large repository (git trees API limit)")
    blobs = {e["path"]: (int(e.get("size") or 0), e["sha"]) for e in tree.get("tree") or []
             if e.get("type") == "blob" and e.get("mode") != "120000" and e.get("path")
             and ".." not in e["path"].split("/")}
    wanted = [p for p, (size, _) in blobs.items() if keep(p, size)]
    failed: list[str] = []

    def one(rel: str):
        try:
            return rel, gh.raw(f"repos/{repo}/git/blobs/{blobs[rel][1]}", max_file,
                               accept="application/vnd.github.raw+json")
        except GitHubError as exc:
            failed.append(f"{rel}: {exc}"[:200])
            return rel, None

    with ThreadPoolExecutor(workers) as ex:
        files = {r: d for r, d in ex.map(one, wanted) if d is not None}
    notes.append(f"Read {len(files)} of {len(blobs)} files one by one (repository too large for one archive)"
                 + (f"; {len(failed)} could not be read, e.g. {failed[0]}" if failed else ""))
    return files, len(blobs) - len(wanted) + len(failed)


def fetch(spec: str, keep: Keep, *, host: str = "github.com", sha: str | None = None, signals: bool = True,
          alerts: bool = True, max_archive_mb: int = 300, log: Callable[[str], None] = print) -> GhRepo:
    """Read one repository at one commit. `sha` pins the commit (e.g. the one an earlier phase used)."""
    repo, host, ref = parse_target(spec, host)
    gh = Gh(host)
    try:
        meta = gh.api(f"repos/{repo}") or {}
    except GhApiError as exc:
        if exc.http in (403, 404):
            raise GitHubError(f"{repo} was not found on {host}, or the gh account cannot read it") from None
        raise
    full = meta.get("full_name") or repo
    ref = ref or meta.get("default_branch") or "HEAD"
    target = sha if sha and SHA.match(sha) else ref
    try:
        commit = gh.api(f"repos/{repo}/commits/{quote(target, safe='')}") or {}
    except GhApiError as exc:
        if exc.http in (404, 422):
            raise GitHubError(f"{'Commit' if target == sha else 'Ref'} {target!r} was not found in {full}") from None
        raise
    resolved = commit.get("sha", "")
    if not SHA.match(resolved):
        raise GitHubError(f"Could not resolve {target!r} in {full} to a commit")
    committed = ((commit.get("commit") or {}).get("committer") or {}).get("date") or ""
    out = GhRepo(spec=spec, repository=full, host=host, ref=ref, sha=resolved, committed=committed, meta=meta)

    limit = max_archive_mb * 1024 * 1024
    big = False
    try:
        log(f"  ↓ {full}@{resolved[:12]} (streaming the archive, up to {max_archive_mb} MB)")
        out.files, out.skipped = _stream_archive(gh, repo, resolved, keep, limit, log=log)
        out.fetch = "archive"
    except ArchiveTooLarge:
        out.notes.append(f"The archive is over {max_archive_mb} MB; files were read one by one")
        big = True
    if big:
        log(f"  ↓ {full}@{resolved[:12]} (file by file)")
        out.files, out.skipped = _from_tree(gh, repo, resolved, keep, out.notes)
        out.fetch = "files"

    if alerts:
        out.files[f"{GH_DIR}/security-alerts.md"] = alerts_document(gh, repo, out).encode()
    if signals:
        out.files[f"{GH_DIR}/repository-signals.md"] = signals_document(gh, repo, out).encode()
    return out


# --------------------------------------------------------------------------- generated documents
def _yes(v) -> str:
    return "yes" if v else "no"


def _unavailable(what: str, exc: GhApiError) -> str:
    why = {403: "no access (needs security alert read access, or the feature is off)",
           404: "not enabled for this repository, or no access"}.get(exc.http or 0, str(exc))
    return f"{what}: not available ({f'HTTP {exc.http}: ' if exc.http else ''}{why})"


def _cell(s) -> str:
    return str(s if s is not None else "").replace("|", "\\|").replace("\n", " ")[:160]


def alerts_document(gh: Gh, repo: str, r: GhRepo) -> str:
    lines = [f"# Open security alerts: {r.repository}", "",
             f"Source: gh api on {r.host}, read {datetime.now(timezone.utc):%Y-%m-%d} (commit {r.sha[:12]}). "
             "Alerts are the repository's current state, not tied to the commit. Secret values are never collected.",
             ""]
    try:
        dep = gh.api(f"repos/{repo}/dependabot/alerts", paginate=True, state="open", per_page=100)
        r.alerts["dependabot"] = len(dep)
        lines += [f"## Dependabot ({len(dep)} open)", ""]
        if dep:
            lines += ["| # | Severity | Package | Ecosystem | Manifest | Advisory | Fixed in |", "|---|---|---|---|---|---|---|"]
            for a in dep[:200]:
                d, adv, v = a.get("dependency") or {}, a.get("security_advisory") or {}, a.get("security_vulnerability") or {}
                pkg = d.get("package") or v.get("package") or {}
                lines.append(f"| {a.get('number')} | {_cell(v.get('severity') or adv.get('severity'))} | "
                             f"{_cell(pkg.get('name'))} | {_cell(pkg.get('ecosystem'))} | {_cell(d.get('manifest_path'))} | "
                             f"{_cell(adv.get('cve_id') or adv.get('ghsa_id'))} | "
                             f"{_cell((v.get('first_patched_version') or {}).get('identifier'))} |")
    except GhApiError as exc:
        r.alerts["dependabot"] = None
        r.notes.append(_unavailable("Dependabot alerts", exc))
        lines += ["## Dependabot", "", "- " + r.notes[-1]]
    lines.append("")
    try:
        cs = gh.api(f"repos/{repo}/code-scanning/alerts", paginate=True, state="open", per_page=100)
        r.alerts["code_scanning"] = len(cs)
        lines += [f"## Code scanning ({len(cs)} open)", ""]
        if cs:
            lines += ["| # | Tool | Rule | Severity | Location |", "|---|---|---|---|---|"]
            for a in cs[:200]:
                rule, loc = a.get("rule") or {}, (a.get("most_recent_instance") or {}).get("location") or {}
                lines.append(f"| {a.get('number')} | {_cell((a.get('tool') or {}).get('name'))} | {_cell(rule.get('id'))} | "
                             f"{_cell(rule.get('security_severity_level') or rule.get('severity'))} | "
                             f"{_cell(loc.get('path'))}:{loc.get('start_line') or ''} |")
    except GhApiError as exc:
        r.alerts["code_scanning"] = None
        r.notes.append(_unavailable("Code-scanning alerts", exc))
        lines += ["## Code scanning", "", "- " + r.notes[-1]]
    lines.append("")
    try:
        ss = gh.api(f"repos/{repo}/secret-scanning/alerts", paginate=True, state="open", per_page=100)
        for a in ss:
            a.pop("secret", None)                 # dropped at once, never kept
        r.alerts["secret_scanning"] = len(ss)
        lines += [f"## Secret scanning ({len(ss)} open)", ""]
        if ss:
            lines += ["| # | Secret type | Location |", "|---|---|---|"]
            for a in ss[:50]:
                where = ""
                if len(ss) <= 25:
                    try:
                        found = gh.api(f"repos/{repo}/secret-scanning/alerts/{int(a.get('number'))}/locations",
                                       per_page=1) or []
                        det = found[0].get("details") or {} if found and found[0].get("type") == "commit" else {}
                        where = f"{det.get('path', '')}:{det.get('start_line', '')}" if det else ""
                    except (GhApiError, TypeError, ValueError):
                        pass
                lines.append(f"| {a.get('number')} | {_cell(a.get('secret_type_display_name') or a.get('secret_type'))} | "
                             f"{_cell(where)} |")
    except GhApiError as exc:
        r.alerts["secret_scanning"] = None
        r.notes.append(_unavailable("Secret-scanning alerts", exc))
        lines += ["## Secret scanning", "", "- " + r.notes[-1]]
    return "\n".join(lines) + "\n"


def _protection_lines(p: dict) -> list[str]:
    out = []
    rv = p.get("required_pull_request_reviews")
    if rv:
        out.append(f"- Required pull request reviews: {rv.get('required_approving_review_count', 0)} approving review(s); "
                   f"code owner review required: {_yes(rv.get('require_code_owner_reviews'))}; "
                   f"stale reviews dismissed: {_yes(rv.get('dismiss_stale_reviews'))}")
    else:
        out.append("- Required pull request reviews: none")
    sc = p.get("required_status_checks")
    if sc:
        checks = sc.get("contexts") or [c.get("context") for c in sc.get("checks") or []]
        out.append(f"- Required status checks: {', '.join(c for c in checks if c) or 'none listed'} "
                   f"(branch must be up to date: {_yes(sc.get('strict'))})")
    else:
        out.append("- Required status checks: none")
    ea = p.get("enforce_admins")
    out.append(f"- Enforced for administrators: {_yes(ea.get('enabled') if isinstance(ea, dict) else ea)}")
    for key, label in (("allow_force_pushes", "Force pushes allowed"), ("allow_deletions", "Branch deletion allowed"),
                       ("required_linear_history", "Linear history required"),
                       ("required_signatures", "Signed commits required")):
        v = p.get(key)
        if v is not None:
            out.append(f"- {label}: {_yes(v.get('enabled') if isinstance(v, dict) else v)}")
    return out


def signals_document(gh: Gh, repo: str, r: GhRepo) -> str:
    meta = r.meta
    branch = meta.get("default_branch") or r.ref
    lines = [f"# GitHub repository signals: {r.repository}", "",
             f"Source: gh api on {r.host}, commit {r.sha} (ref {r.ref}, committed {r.committed or 'unknown'}). "
             f"Read {datetime.now(timezone.utc):%Y-%m-%d}.", "",
             "## Repository", "",
             f"- Default branch: {branch}; visibility: {meta.get('visibility') or ('private' if meta.get('private') else 'public')}; "
             f"archived: {_yes(meta.get('archived'))}; last push: {meta.get('pushed_at') or 'unknown'}",
             f"- Files read: {len(r.files)} ({r.fetch}); left out by type or size: {r.skipped}"]
    saa = meta.get("security_and_analysis") or {}
    if saa:
        lines.append("- Security and analysis: " + "; ".join(f"{k.replace('_', ' ')}: {(v or {}).get('status', 'unknown')}"
                                                            for k, v in sorted(saa.items())))
    lines += ["", f"## Branch protection ({branch})", ""]
    try:
        b = gh.api(f"repos/{repo}/branches/{quote(branch, safe='')}") or {}
        lines.append(f"- Protected: {_yes(b.get('protected'))}")
        try:
            lines += _protection_lines(gh.api(f"repos/{repo}/branches/{quote(branch, safe='')}/protection") or {})
        except GhApiError as exc:
            if b.get("protected"):
                checks = ((b.get("protection") or {}).get("required_status_checks") or {}).get("contexts") or []
                lines.append(f"- Required status checks: {', '.join(checks) or 'none listed'}")
                lines.append(f"- Protection details: not readable ({'needs admin access' if exc.http in (403, 404) else exc})")
    except GhApiError as exc:
        r.notes.append(_unavailable("Branch protection", exc))
        lines.append("- Not available")
    try:
        rules = gh.api(f"repos/{repo}/rules/branches/{quote(branch, safe='')}", paginate=True) or []
        lines.append("- Rulesets: " + ("; ".join(x.get("type", "?") for x in rules) if rules
                                        else "none apply to this branch"))
    except GhApiError:
        pass                                      # older GitHub Enterprise versions have no rulesets API

    lines += ["", "## Environments", ""]
    try:
        envs = (gh.api(f"repos/{repo}/environments") or {}).get("environments") or []
        for e in envs:
            rules = []
            for x in e.get("protection_rules") or []:
                if x.get("type") == "required_reviewers":
                    rules.append(f"{len(x.get('reviewers') or [])} required reviewer(s)")
                elif x.get("type") == "wait_timer":
                    rules.append(f"wait timer {x.get('wait_timer')} min")
                elif x.get("type") == "branch_policy":
                    rules.append("deployment branch policy")
            if (e.get("deployment_branch_policy") or {}).get("protected_branches"):
                rules.append("protected branches only")
            lines.append(f"- {e.get('name')}: {', '.join(rules) or 'no protection rules'}")
        if not envs:
            lines.append("- None configured")
    except GhApiError as exc:
        r.notes.append(_unavailable("Environments", exc))
        lines.append("- Not available")

    lines += ["", "## Releases (most recent 10)", ""]
    try:
        rels = gh.api(f"repos/{repo}/releases", per_page=10) or []
        if rels:
            lines += ["| Tag | Name | Published | Pre-release |", "|---|---|---|---|"]
            lines += [f"| {_cell(x.get('tag_name'))} | {_cell(x.get('name'))} | {x.get('published_at') or 'draft'} | "
                      f"{_yes(x.get('prerelease'))} |" for x in rels]
        else:
            lines.append("- No releases")
    except GhApiError as exc:
        r.notes.append(_unavailable("Releases", exc))
        lines.append("- Not available")

    lines += ["", "## Deployments (most recent 10)", ""]
    try:
        deps = gh.api(f"repos/{repo}/deployments", per_page=10) or []
        if deps:
            lines += ["| Environment | Ref | Created | Latest status |", "|---|---|---|---|"]
            for d in deps:
                try:
                    st = gh.api(f"repos/{repo}/deployments/{int(d.get('id'))}/statuses", per_page=1) or []
                    state = st[0].get("state") if st else "none"
                except (GhApiError, TypeError, ValueError):
                    state = "unknown"
                lines.append(f"| {_cell(d.get('environment'))} | {_cell(d.get('ref'))} | {d.get('created_at')} | {state} |")
        else:
            lines.append("- No deployments recorded through the GitHub Deployments API")
    except GhApiError as exc:
        r.notes.append(_unavailable("Deployments", exc))
        lines.append("- Not available")

    if r.alerts:
        label = {"dependabot": "Dependabot", "code_scanning": "Code scanning", "secret_scanning": "Secret scanning"}
        lines += ["", "## Security alerts (open; details in security-alerts.md)", ""]
        lines += [f"- {label[k]}: {'not available' if v is None else v}" for k, v in r.alerts.items()]
    if r.notes:
        lines += ["", "## Not collected", ""] + [f"- {n}" for n in r.notes]
    return "\n".join(lines) + "\n"
