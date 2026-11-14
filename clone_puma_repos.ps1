# Shallow-clones the PUMA / PFME / PUMACE repositories the runbook generator reads.
# Read-only use: HEAD only (--depth 1), nothing is built or run.
# Run in your own terminal so Git can use your GitHub sign-in (SSO).
#
#   .\clone_puma_repos.ps1                       # default destination
#   .\clone_puma_repos.ps1 -Dest D:\src\puma     # somewhere else
#   .\clone_puma_repos.ps1 -All                  # include empty/archived/demo repos too

param(
    [string]$Dest = 'C:\Users\rhari\source\repos\CVS_PUMA_src',
    [string]$Org  = 'cvs-health-source-code',
    [switch]$All
)

# Runtime, data, UI, ops tooling, plus the two archived repos production still deploys from
# (pnl-engine-rewrite = Comp Engine release pipeline, puma-eos-ui-web = EOS UI).
$core = @(
    'pfme-java', 'pfme-gitops',
    'puma-data-hub', 'puma-data-governance', 'puma-ae-artifact-etl', 'pumace-starrocks-admin',
    'puma-libs', 'pumace-aks-monitor',
    'pnl-engine-rewrite', 'puma-eos-ui-web',
    'pfme-python'
)
# Empty, placeholder, superseded or archived migration/demo repos (mostly noise for runbooks).
$extra = @(
    'PUMA-UI-QA', 'pumace-migration-pipeline', 'puma_edp_migration',
    'puma-dsmart-spark-demo-cmpsr3', 'puma-dsmart-dag-demo-cmpsr3', 'pumace-deployment-testing',
    'pumace-schema-cloner', 'pumace-starrocks-migration-tools', 'puma-comp-dsmart-gke-demo',
    'puma-architecture_architecture_diagrams'
)
$repos = if ($All) { $core + $extra } else { $core }

New-Item -ItemType Directory -Force -Path $Dest | Out-Null
$ok = @(); $failed = @()
foreach ($r in $repos) {
    $target = Join-Path $Dest $r
    if (Test-Path (Join-Path $target '.git')) { Write-Host "skip  $r (already cloned)"; $ok += $r; continue }
    Write-Host "clone $r"
    git clone --depth 1 --single-branch --quiet "https://github.com/$Org/$r.git" $target
    if ($LASTEXITCODE -eq 0) { $ok += $r } else { $failed += $r }
}
Write-Host ""
Write-Host "Cloned: $($ok.Count)   Failed: $($failed.Count)"
if ($failed.Count) { Write-Host "Failed (no access, renamed, or SSO not authorized): $($failed -join ', ')" }
