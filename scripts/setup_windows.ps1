#Requires -Version 5.1
<#
.SYNOPSIS
    One-shot local setup for the CTF-Solver Beta on Windows.

.DESCRIPTION
    Creates (or reuses) a virtual environment, installs the package from this source tree
    with the in-tree stdlib-only build backend, deploys the six Skills into the target
    workspace, generates the project-scoped Manager MCP config, and runs read-only smoke
    checks.

    It never uses administrator rights, never disables the Harness sandbox, never edits
    global Harness profiles/plugins, and never installs third-party packages. Everything
    is local; no package index is contacted.

.PARAMETER Workspace
    Harness project workspace to receive the Skills and the MCP config.
    Default: this repository directory.

.PARAMETER Python
    Python launcher to create the venv (e.g. "py -3.14" or full path to python.exe).
    Default: autodetect python / py -3.14 / py -3.13.

.PARAMETER Venv
    Virtual environment directory. Default: <workspace>\.venv

.PARAMETER LeadSessionsRoot
    Live Harness sessions root for Lead-session evidence.
    Default: $env:DSH_HOME\sessions or $env:USERPROFILE\.dsh\sessions

.PARAMETER CaptureMode
    Manager screenshot capture mode: real-window (default), desktop, fake, fake-blank.

.PARAMETER TargetWindowPid
    Optional explicit target window PID for real-window capture.

.PARAMETER RunTests
    Also run the offline pytest suite. Requires pytest in the venv (not installed here).

.PARAMETER Force
    Reinstall the package and overwrite the generated MCP config.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\setup_windows.ps1
#>
[CmdletBinding()]
param(
    [string]$Workspace = "",
    [string]$Python = "",
    [string]$Venv = "",
    [string]$LeadSessionsRoot = "",
    [ValidateSet("real-window", "desktop", "fake", "fake-blank")]
    [string]$CaptureMode = "real-window",
    [int]$TargetWindowPid = 0,
    [switch]$RunTests,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

function Write-Step([string]$Text) {
    Write-Host ""
    Write-Host "== $Text ==" -ForegroundColor Cyan
}

$RepoRoot = Split-Path -Parent $PSScriptRoot
if (-not $Workspace) { $Workspace = $RepoRoot }
$Workspace = (Resolve-Path -LiteralPath $Workspace).Path
if (-not $Venv) { $Venv = Join-Path $Workspace ".venv" }

Write-Step "CTF-Solver Beta setup"
Write-Host "repository : $RepoRoot"
Write-Host "workspace  : $Workspace"
Write-Host "venv       : $Venv"
Write-Host "capture    : $CaptureMode"

# --- 1. Find a Python >= 3.11 -------------------------------------------------
Write-Step "1/6 locate Python"
$launcherExe = $null
$launcherArgs = @()
if ($Python) {
    $launcherExe = $Python
} else {
    $candidates = @(
        @{ Exe = "python"; Args = @() },
        @{ Exe = "py"; Args = @("-3.14") },
        @{ Exe = "py"; Args = @("-3.13") },
        @{ Exe = "py"; Args = @("-3.12") },
        @{ Exe = "py"; Args = @("-3.11") }
    )
    $versionProbe = "import sys;print(sys.version_info[0]*1000+sys.version_info[1])"
    foreach ($candidate in $candidates) {
        if (-not (Get-Command $candidate.Exe -ErrorAction SilentlyContinue)) { continue }
        try {
            $probeArgs = @($candidate.Args) + @("-c", $versionProbe)
            $text = & $candidate.Exe @probeArgs 2>$null
            $ver = 0
            [void][int]::TryParse(([string]$text).Trim(), [ref]$ver)
            if ($ver -ge 3011) { $launcherExe = $candidate.Exe; $launcherArgs = $candidate.Args; break }
        } catch { }
    }
}
if (-not $launcherExe) {
    throw "No Python 3.11+ found. Install Python 3.14 (recommended) or pass -Python <path-to-python.exe>."
}
Write-Host ("using: {0} {1}" -f $launcherExe, ($launcherArgs -join " "))

# --- 2. Virtual environment ---------------------------------------------------
Write-Step "2/6 create / reuse virtual environment"
$VenvPython = Join-Path $Venv "Scripts\python.exe"
$VenvPip = Join-Path $Venv "Scripts\pip.exe"
if (-not (Test-Path -LiteralPath $VenvPython)) {
    $venvArgs = @($launcherArgs) + @("-m", "venv", $Venv)
    & $launcherExe @venvArgs
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $VenvPython)) {
        # Restricted TEMP/ACL environments can make ensurepip fail while the
        # interpreter itself is usable. Retry without pip and bootstrap below.
        Write-Warning "standard venv creation failed; retrying with --without-pip"
        if (Test-Path -LiteralPath $Venv) { Remove-Item -LiteralPath $Venv -Recurse -Force }
        $venvArgs = @($launcherArgs) + @("-m", "venv", "--without-pip", $Venv)
        & $launcherExe @venvArgs
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $VenvPython)) {
            throw "venv creation failed; check the Python launcher, TEMP permissions and the workspace ACL."
        }
    }
    Write-Host "created venv"
} else {
    Write-Host "reusing existing venv"
}

# Make sure pip is usable; otherwise fall back to the launcher's pip --python mode.
$UseBasePip = $false
if (-not (Test-Path -LiteralPath $VenvPip)) {
    & $VenvPython -m ensurepip --upgrade --default-pip 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $VenvPip)) {
        Write-Warning "pip bootstrap in the venv failed; using the launcher's pip --python mode"
        $UseBasePip = $true
    }
}

# --- 3. Install the package offline ------------------------------------------
Write-Step "3/6 install ctf-solver from this source tree (offline)"
$pipFlags = @("install", "--no-build-isolation", "--no-deps", "--disable-pip-version-check")
if ($Force) { $pipFlags = @("install", "--force-reinstall", "--no-build-isolation", "--no-deps", "--disable-pip-version-check") }
if ($UseBasePip) {
    $installArgs = @($launcherArgs) + @("-m", "pip", "--python", $VenvPython) + $pipFlags + @($RepoRoot)
    & $launcherExe @installArgs
} else {
    $installArgs = @("-m", "pip") + $pipFlags + @($RepoRoot)
    & $VenvPython @installArgs
}
if ($LASTEXITCODE -ne 0) {
    throw "pip install failed. Re-run manually: `"$VenvPython`" -m pip install --no-build-isolation --no-deps `"$RepoRoot`""
}

# --- 4. Deploy Skills ---------------------------------------------------------
Write-Step "4/6 deploy the six Skills"
& $VenvPython (Join-Path $RepoRoot "scripts\deploy_skills.py") --workspace $Workspace --source (Join-Path $RepoRoot ".dsh\skills")
if ($LASTEXITCODE -ne 0) { throw "Skill deployment failed." }

# --- 5. Generate project MCP config ------------------------------------------
Write-Step "5/6 generate project-scoped Manager MCP config"
$leadRoot = $LeadSessionsRoot
if (-not $leadRoot) {
    if ($env:DSH_HOME) { $leadRoot = Join-Path $env:DSH_HOME "sessions" }
    else { $leadRoot = Join-Path $env:USERPROFILE ".dsh\sessions" }
}
$genArgs = @(
    (Join-Path $RepoRoot "scripts\gen_mcp_config.py"),
    "--workspace", $Workspace,
    "--python", $VenvPython,
    "--capture-mode", $CaptureMode,
    "--lead-sessions-root", $leadRoot
)
if ($TargetWindowPid -gt 0) { $genArgs += @("--target-window-pid", "$TargetWindowPid") }
if ($Force) { $genArgs += "--force" }
& $VenvPython @genArgs
if ($LASTEXITCODE -ne 0) { throw "MCP config generation failed." }

# --- 6. Read-only smoke checks -----------------------------------------------
Write-Step "6/6 smoke checks (read-only, no model calls)"
& $VenvPython -m ctf_solver version
& $VenvPython -m ctf_solver skills --root $Workspace
& $VenvPython -m ctf_solver preflight --root $Workspace --quiet
if ($LASTEXITCODE -ne 0) { Write-Warning "preflight reported problems; inspect its output before use." }

if ($RunTests) {
    Write-Step "optional: offline test suite"
    & $VenvPython -m pytest (Join-Path $RepoRoot "tests") -q -p no:cacheprovider
    if ($LASTEXITCODE -ne 0) { Write-Warning "pytest failed or pytest is not installed in the venv." }
}

Write-Step "done"
Write-Host "Next:"
Write-Host "  1. Open $Workspace as a DeepSeek Harness workspace (Workspace MCP Bridge plugin required)."
Write-Host "  2. Start a conversation and confirm 18 mcp__ctf-solver__* tools."
Write-Host "  3. Call /ctf-solver and follow QUICKSTART.md."
Write-Host ""
Write-Host "Security note: do not disable the sandbox and do not use danger-full-access for this project."
