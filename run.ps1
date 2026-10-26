param(
    [string]$PythonPath = "",
    [int]$Port = 8502
)

$ErrorActionPreference = "Stop"
Push-Location -LiteralPath $PSScriptRoot
try {
    if ($PythonPath) {
        $dependencyPython = (Resolve-Path -LiteralPath $PythonPath).Path
    } else {
        $dependencyPython = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
        if (-not (Test-Path -LiteralPath $dependencyPython)) {
            & python -m venv .venv
            if ($LASTEXITCODE -ne 0) { throw "Unable to create the virtual environment." }
            & $dependencyPython -m pip install -r requirements.txt
            if ($LASTEXITCODE -ne 0) { throw "Dependency installation failed." }
        }
    }
    & $dependencyPython -m streamlit run app.py --server.address 127.0.0.1 --server.port $Port --browser.gatherUsageStats false
    if ($LASTEXITCODE -ne 0) { throw "Streamlit stopped with an error." }
} finally {
    Pop-Location
}
