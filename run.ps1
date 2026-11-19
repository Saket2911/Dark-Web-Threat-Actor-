# One-command setup for the Dark Web Threat Actor Intelligence Platform
# Resolves directories from $PSScriptRoot (no hardcoded paths).
# After running this script, start the servers manually:
#   Backend:  cd backend && $env:PYTHONPATH='.venv'; .venv\Scripts\python.exe -m uvicorn app.main:app --port 8000
#   Frontend: cd frontend && npm run dev

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"

$scriptDir = $PSScriptRoot
$backendDir = Join-Path $scriptDir "backend"
$frontendDir = Join-Path $scriptDir "frontend"
$venvPython = Join-Path $backendDir ".venv\Scripts\python.exe"

Write-Host "== Dark Web Threat Actor Intelligence Platform ==" -ForegroundColor Cyan
Write-Host "Project root: $scriptDir" -ForegroundColor Gray

# ---------------------------------------------------------------------------
# 1. Ensure backend virtual environment exists
# ---------------------------------------------------------------------------
if (-not (Test-Path -LiteralPath $venvPython)) {
    Write-Host "Creating backend virtual environment..." -ForegroundColor Cyan
    & python -m venv "$backendDir\.venv"
    if ($LASTEXITCODE -ne 0) { Write-Host "Failed to create venv" -ForegroundColor Red; exit 1 }
}

# ---------------------------------------------------------------------------
# 2. Install backend requirements
# ---------------------------------------------------------------------------
Write-Host "Installing backend dependencies..." -ForegroundColor Cyan
$install = & $venvPython -m pip install --upgrade pip >$null 2>&1
$install = & $venvPython -m pip install -r "$backendDir\requirements.txt"
if ($LASTEXITCODE -ne 0) {
    Write-Host "Backend dependency installation FAILED:" -ForegroundColor Red
    $install | Select-Object -Last 15
    exit 1
}
Write-Host "Backend dependencies installed." -ForegroundColor Green

# ---------------------------------------------------------------------------
# 3. Seed the database
# ---------------------------------------------------------------------------
Write-Host "Seeding database..." -ForegroundColor Cyan
$seed = & $venvPython "$backendDir\scripts\seed.py"
if ($LASTEXITCODE -ne 0) {
    Write-Host "Database seeding FAILED:" -ForegroundColor Red
    $seed | Select-Object -Last 20
    exit 1
}
Write-Host "Database seeded." -ForegroundColor Green

# ---------------------------------------------------------------------------
# 4. Install frontend dependencies if node_modules missing
# ---------------------------------------------------------------------------
if (-not (Test-Path -LiteralPath (Join-Path $frontendDir "node_modules"))) {
    Write-Host "Installing frontend dependencies..." -ForegroundColor Cyan
    & npm install --prefix $frontendDir
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Frontend dependency installation FAILED." -ForegroundColor Red
        exit 1
    }
    Write-Host "Frontend dependencies installed." -ForegroundColor Green
} else {
    Write-Host "Frontend node_modules present." -ForegroundColor Gray
}

# ---------------------------------------------------------------------------
# 5. Start instructions
# ---------------------------------------------------------------------------
Write-Host "" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  SETUP COMPLETE" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "To start the application, open TWO PowerShell windows and run:"
Write-Host ""
Write-Host "  WINDOW 1 (Backend):"
Write-Host "    cd ""$backendDir"""
Write-Host "    $env:PYTHONPATH=""$backendDir\.venv""; .venv\Scripts\python.exe -m uvicorn app.main:app --host 0.0.0.0 --port 8000"
Write-Host ""
Write-Host "  WINDOW 2 (Frontend):"
Write-Host "    cd ""$frontendDir"""
Write-Host "    npm run dev"
Write-Host ""
Write-Host "Then open http://localhost:5173 in your browser."
Write-Host "Login: admin / admin123"
Write-Host "API docs: http://localhost:8000/docs"
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
