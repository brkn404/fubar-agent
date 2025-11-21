# Build Windows bundle (.msi or .exe installer)
# Run with: powershell -ExecutionPolicy Bypass -File scripts/build-windows.ps1

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir
$BuildDir = "$ProjectRoot\build\windows"
$DistDir = "$ProjectRoot\dist"

# Get version
$Version = python -c "from src.fubar_agent.version import __version__; print(__version__)"
$Arch = $env:PROCESSOR_ARCHITECTURE

Write-Host "🪟 Building Windows bundle (v$Version)..." -ForegroundColor Cyan
Write-Host ""

# Clean build directories
Write-Host "🧹 Cleaning build directories..." -ForegroundColor Yellow
if (Test-Path $BuildDir) { Remove-Item -Recurse -Force $BuildDir }
if (Test-Path $DistDir) { Remove-Item -Recurse -Force $DistDir }
New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null
New-Item -ItemType Directory -Force -Path $DistDir | Out-Null

# Create build directory
$BundleDir = "$BuildDir\fubar-agent-$Version"
New-Item -ItemType Directory -Force -Path $BundleDir | Out-Null

# Copy source files
Write-Host "📋 Copying source files..." -ForegroundColor Yellow
Copy-Item -Recurse "$ProjectRoot\src" "$BundleDir\"
Copy-Item -Recurse "$ProjectRoot\rules-master" "$BundleDir\"
Copy-Item "$ProjectRoot\setup.py" "$BundleDir\"
Copy-Item "$ProjectRoot\README.md" "$BundleDir\"

# Create install script
$InstallScript = @"
@echo off
REM Installation script for fubar-agent (Windows)

echo 🚀 Installing fubar-agent...
echo.

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python is required but not installed
    echo    Install from: https://www.python.org/downloads/
    pause
    exit /b 1
)

REM Install dependencies
echo 📦 Installing dependencies...
python -m pip install --user --upgrade pip
python -m pip install --user aiohttp click pyyaml pywin32

REM Install agent
echo 📦 Installing fubar-agent...
cd /d "%~dp0"
python -m pip install --user .

echo.
echo ✅ Installation complete!
echo.
echo Next steps:
echo   1. Configure agent: python -m fubar_agent.cli configure
echo   2. Start agent: python -m fubar_agent.cli start
echo.
pause
"@

Set-Content -Path "$BundleDir\install.bat" -Value $InstallScript

# Create README
$Readme = @"
Fubar Agent Installation Guide (Windows)
========================================

Version: $Version
Platform: Windows ($Arch)

Quick Install:
--------------
1. Extract this archive to a folder (e.g., C:\Program Files\fubar-agent)

2. Run install.bat as Administrator (right-click > Run as administrator)

3. Configure agent:
   python -m fubar_agent.cli configure

4. Start agent:
   python -m fubar_agent.cli start

Manual Install:
---------------
1. Install dependencies:
   python -m pip install --user aiohttp click pyyaml pywin32

2. Install agent:
   python -m pip install --user .

3. Configure and start (see Quick Install steps 3-4)

Windows Service:
---------------
To run as a Windows Service, use NSSM (Non-Sucking Service Manager):
1. Download NSSM from https://nssm.cc/download
2. Install service:
   nssm install fubar-agent "python" "-m fubar_agent.cli start --config-file C:\ProgramData\fubar\agent_config.yaml"
3. Start service:
   nssm start fubar-agent

For more information, see the main README.md
"@

Set-Content -Path "$BundleDir\INSTALL.txt" -Value $Readme

# Create ZIP archive
Write-Host "📦 Creating ZIP archive..." -ForegroundColor Yellow
$ZipFile = "$DistDir\fubar-agent-$Version-windows-$Arch.zip"
Compress-Archive -Path "$BundleDir\*" -DestinationPath $ZipFile -Force

Write-Host "✅ Windows bundle created: fubar-agent-$Version-windows-$Arch.zip" -ForegroundColor Green

# Check for WiX Toolset for MSI creation
if (Get-Command candle.exe -ErrorAction SilentlyContinue) {
    Write-Host ""
    Write-Host "💿 WiX Toolset found, creating MSI installer..." -ForegroundColor Yellow
    # TODO: Create MSI installer using WiX
    Write-Host "⚠️  MSI creation not yet implemented" -ForegroundColor Yellow
}

