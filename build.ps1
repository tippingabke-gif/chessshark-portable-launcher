param([string]$Python = 'python')
$ErrorActionPreference = 'Stop'

function Invoke-BuildPython {
    param([string[]]$Arguments)
    & $Python @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Python build step failed with exit code $LASTEXITCODE"
    }
}

Push-Location -LiteralPath $PSScriptRoot
try {
    Invoke-BuildPython -Arguments @('-X', 'utf8', 'build_bundle.py')
    Invoke-BuildPython -Arguments @('-X', 'utf8', '-m', 'unittest', 'test_portable', 'test_presentation')
    Invoke-BuildPython -Arguments @('-X', 'utf8', '-m', 'PyInstaller', '--noconfirm', '--distpath', 'dist', '--workpath', 'build', 'portable_launcher.spec')
    $launchers = @(Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'dist') -Filter 'ChessShark_*.exe' -File)
    if ($launchers.Count -ne 1) {
        throw 'Expected exactly one built launcher in dist/'
    }
    & $launchers[0].FullName --diagnose --no-dialog
    if ($LASTEXITCODE -ne 0) {
        throw "Packaged runtime self-check failed with exit code $LASTEXITCODE"
    }
    Write-Output 'Build and runtime self-check passed. See dist/.'
} finally {
    Pop-Location
}
