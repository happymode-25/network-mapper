# start-all.ps1 — One-click demo launcher for Network Mapper
#
# 1. Starts the local FastAPI backend (SQLite + inline scans, no Docker).
# 2. Starts a free Cloudflare Quick Tunnel (downloads cloudflared if missing).
# 3. Captures the new *.trycloudflare.com URL.
# 4. Updates the GitHub Pages frontend to point at the tunnel and re-deploys
#    (only when gh is available and -SkipGitHub is not given).
#
# Usage:
#   .\start-all.ps1              # full flow (backend + tunnel + redeploy)
#   .\start-all.ps1 -SkipGitHub  # local only — prints the URL for manual use
#
# Logs and PIDs are kept in %LOCALAPPDATA%\network-mapper-demo.

param(
    [switch]$SkipGitHub
)

$ErrorActionPreference = "Stop"
$Root      = $PSScriptRoot
$Repo      = "happymode-25/network-mapper"
$SiteUrl   = "https://happymode-25.github.io/network-mapper/"

# --- directories / logs -----------------------------------------------
$ProgDir  = Join-Path $env:LOCALAPPDATA "cloudflared"
$LogDir   = Join-Path $env:LOCALAPPDATA "network-mapper-demo"
New-Item -ItemType Directory -Force -Path $ProgDir, $LogDir | Out-Null
$Cloudflared = Join-Path $ProgDir "cloudflared.exe"
$BackendOut  = Join-Path $LogDir "backend.out.log"
$BackendErr  = Join-Path $LogDir "backend.err.log"
$TunnelOut   = Join-Path $LogDir "tunnel.out.log"
$TunnelErr   = Join-Path $LogDir "tunnel.err.log"
$PidFile     = Join-Path $LogDir "pids.txt"
foreach ($f in @($BackendOut, $BackendErr, $TunnelOut, $TunnelErr)) { Remove-Item -Force $f -ErrorAction SilentlyContinue }

Write-Host "== Network Mapper demo launcher ==" -ForegroundColor Cyan

# --- 1. cloudflared ----------------------------------------------------
if (-not (Test-Path $Cloudflared)) {
    Write-Host "Downloading cloudflared..." -ForegroundColor Yellow
    Invoke-WebRequest -Uri "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe" -OutFile $Cloudflared -UseBasicParsing
}

# --- 2. stop previous instances we manage ------------------------------
# Any python process running our uvicorn app, on any port.
Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -match "uvicorn" -and $_.CommandLine -match "backend\.app\.main" } |
    ForEach-Object {
        Write-Host "Stopping old backend (PID $($_.ProcessId))..." -ForegroundColor Yellow
        Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
    }
# Tunnel: any cloudflared.exe binary matching ours.
Get-Process cloudflared -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $Cloudflared } | ForEach-Object {
    Write-Host "Stopping old tunnel (PID $($_.Id))..." -ForegroundColor Yellow
    Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
}
Start-Sleep -Seconds 2

# --- 3. start backend ---------------------------------------------------
Write-Host "Starting backend..." -ForegroundColor Green
$env:DATABASE_URL    = "sqlite:///./local.db"
$env:INLINE_SCANS    = "true"
$env:USE_SAMPLE_CVES = "true"
$env:SECRET_KEY      = "dev-key"
# Change this to YOUR network subnet to scan the LAN for real findings.
$env:ALLOWED_TARGETS = "127.0.0.1, 192.168.0.0/16, 172.16.0.0/12, 10.0.0.0/8"

$py = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path $py)) { throw "Python venv not found at $py. Run: python -m venv .venv && pip install -r backend/requirements.txt" }
$backend = Start-Process -FilePath $py `
    -ArgumentList "-m", "uvicorn", "backend.app.main:app", "--host", "127.0.0.1", "--port", "8000" `
    -WorkingDirectory $Root -WindowStyle Hidden `
    -RedirectStandardOutput $BackendOut -RedirectStandardError $BackendErr -PassThru

# wait for /health (max ~30 s)
$healthy = $false
for ($i = 0; $i -lt 30; $i++) {
    Start-Sleep -Seconds 1
    try {
        $r = Invoke-WebRequest -Uri "http://127.0.0.1:8000/health" -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
        if ($r.StatusCode -eq 200) { $healthy = $true; break }
    } catch { }
}
if (-not $healthy) {
    Write-Host "Backend did not become healthy in time. See $BackendErr" -ForegroundColor Red
    exit 1
}
Write-Host "Backend up: http://127.0.0.1:8000/health" -ForegroundColor Green

# --- 4. start tunnel ----------------------------------------------------
Write-Host "Starting Cloudflare tunnel..." -ForegroundColor Green
$tunnel = Start-Process -FilePath $Cloudflared `
    -ArgumentList "tunnel", "--url", "http://127.0.0.1:8000", "--no-autoupdate" `
    -WorkingDirectory $Root -WindowStyle Hidden `
    -RedirectStandardOutput $TunnelOut -RedirectStandardError $TunnelErr -PassThru

$tunnelUrl = $null
for ($i = 0; $i -lt 30; $i++) {
    Start-Sleep -Seconds 2
    $m = Select-String -Path $TunnelOut, $TunnelErr -Pattern "https://[a-z0-9-]+\.trycloudflare\.com" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($m) { $tunnelUrl = $m.Matches[0].Value; break }
}
if (-not $tunnelUrl) {
    Write-Host "Tunnel did not start in time. See $TunnelErr" -ForegroundColor Red
    exit 1
}
Write-Host "Tunnel up: $tunnelUrl" -ForegroundColor Green

# --- 5. verify tunnel reaches the backend -------------------------------
# New trycloudflare subdomains can take a few seconds to propagate through
# the local DNS resolver, so poll until the tunnel actually responds.
$tunnelOk = $false
for ($i = 0; $i -lt 15; $i++) {
    try {
        $r = Invoke-WebRequest -Uri "$tunnelUrl/health" -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
        if ($r.StatusCode -eq 200) { $tunnelOk = $true; break }
    } catch {
        Write-Host ("  waiting for tunnel DNS/propagation... ({0}/15)" -f ($i + 1)) -ForegroundColor DarkGray
        Start-Sleep -Seconds 6
    }
}
if ($tunnelOk) {
    Write-Host "Tunnel -> backend OK." -ForegroundColor Green
} else {
    Write-Host "Tunnel never became reachable. Check $TunnelErr" -ForegroundColor Yellow
}

# save PIDs for future cleanup
Set-Content -Path $PidFile -Value "backend=$($backend.Id)`ntunnel=$($tunnel.Id)"

# --- 6. repoint + redeploy the hosted frontend ---------------------------
if ($SkipGitHub) {
    Write-Host "Skipped GitHub redeploy. To point the site at this URL run:" -ForegroundColor Yellow
    Write-Host "  gh variable set VITE_API_URL --repo $Repo --body $tunnelUrl/api" -ForegroundColor Gray
    Write-Host "  gh workflow run 'Deploy frontend to GitHub Pages' --repo $Repo" -ForegroundColor Gray
} else {
    if (Get-Command gh -ErrorAction SilentlyContinue) {
        Write-Host "Updating VITE_API_URL and triggering redeploy..." -ForegroundColor Green
        gh variable set VITE_API_URL --repo $Repo --body "$tunnelUrl/api"
        gh workflow run "Deploy frontend to GitHub Pages" --repo $Repo
        Write-Host "Redeploy triggered. The site will be live in ~1 minute:" -ForegroundColor Green
    } else {
        Write-Host "gh CLI not found. Set VITE_API_URL to $tunnelUrl/api and redeploy manually." -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host " Dashboard : $SiteUrl" -ForegroundColor White
Write-Host " API URL   : $tunnelUrl" -ForegroundColor White
Write-Host " Login     : admin / admin" -ForegroundColor White
Write-Host " Stopping  : Stop-Process -Id $($backend.Id),$($tunnel.Id) -Force" -ForegroundColor White
Write-Host "==================================================" -ForegroundColor Cyan