$ErrorActionPreference = "Stop"
$projectRoot = $PSScriptRoot
Set-Location -LiteralPath $projectRoot
$venvPath = Join-Path $projectRoot ".venv"
$python = Join-Path $venvPath "Scripts\python.exe"
$basePython = $null
$installDependencies = $false

$candidates = @()
$pyLauncher = Get-Command py -ErrorAction SilentlyContinue
if ($pyLauncher) {
    foreach ($line in (& py -0p 2>$null)) {
        # Ignore launcher tags such as 3.13t: CFFI and some other dependencies
        # do not yet support the free-threaded interpreter build.
        if ($line -match '^\s*-V:(?<tag>\d+(?:\.\d+)+)(?:\s+\*)?\s+(?<path>.+?python(?:w)?\.exe)\s*$') {
            $candidatePath = $Matches.path.Trim()
            $candidateVersion = [version]$Matches.tag
            if ($candidateVersion -ge [version]'3.11' -and (Test-Path -LiteralPath $candidatePath)) {
                & $candidatePath -c "import sysconfig; raise SystemExit(1 if sysconfig.get_config_var('Py_GIL_DISABLED') else 0)" 2>$null
                if ($LASTEXITCODE -eq 0) {
                    $candidates += [pscustomobject]@{ Version = $candidateVersion; Path = $candidatePath }
                }
            }
        }
    }
} else {
    $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if ($pythonCommand) {
        & $pythonCommand.Source -c "import sys,sysconfig; raise SystemExit(0 if sys.version_info >= (3,11) and not sysconfig.get_config_var('Py_GIL_DISABLED') else 1)" 2>$null
        if ($LASTEXITCODE -eq 0) {
            $versionText = (& $pythonCommand.Source -c "import sys; print('.'.join(map(str,sys.version_info[:3])))").Trim()
            $candidates += [pscustomobject]@{ Version = [version]$versionText; Path = $pythonCommand.Source }
        }
    }
}

if ($candidates.Count -eq 0) {
    throw "SafeRun needs regular (non-free-threaded) Python 3.11 or newer. Install standard Python, then run this launcher again."
}
$basePython = ($candidates | Sort-Object -Property Version -Descending | Select-Object -First 1).Path

$venvCompatible = $false
if (Test-Path -LiteralPath $python) {
    & $python -c "import sys,sysconfig; raise SystemExit(0 if sys.version_info >= (3,11) and not sysconfig.get_config_var('Py_GIL_DISABLED') else 1)" 2>$null
    $venvCompatible = $LASTEXITCODE -eq 0
}

if ((Test-Path -LiteralPath $venvPath) -and -not $venvCompatible) {
    $resolvedVenv = [System.IO.Path]::GetFullPath($venvPath)
    $resolvedParent = [System.IO.Path]::GetFullPath($projectRoot)
    if ([System.IO.Path]::GetDirectoryName($resolvedVenv) -ne $resolvedParent) {
        throw "Refusing to replace a virtual environment outside the SafeRun project folder."
    }
    Remove-Item -LiteralPath $resolvedVenv -Recurse -Force
}

if (-not (Test-Path -LiteralPath $python)) {
    & $basePython -m venv $venvPath
    if ($LASTEXITCODE -ne 0) { throw "Could not create the SafeRun virtual environment." }
    $installDependencies = $true
} else {
    & $python -c "import fastapi, uvicorn, jinja2, multipart, argon2"
    if ($LASTEXITCODE -ne 0) { $installDependencies = $true }
}

if ($installDependencies) {
    & $python -m pip install --disable-pip-version-check -r (Join-Path $projectRoot "requirements.txt")
    if ($LASTEXITCODE -ne 0) { throw "Could not install SafeRun's free Python dependencies." }
}

& $python -m uvicorn saferun.web:app --host 127.0.0.1 --port 8000
