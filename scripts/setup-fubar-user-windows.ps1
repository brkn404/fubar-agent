# Setup script for FUBAR Agent Service Account on Windows
#
# This script creates a dedicated service account for the FUBAR agent
# with appropriate permissions and directory structure.
#
# Usage:
#   .\scripts\setup-fubar-user-windows.ps1 [-Uid UID] [-Gid GID] [-HomeDir HOME_DIR] [-Password PASSWORD]
#
# Parameters:
#   -Uid UID        Specify UID for FubarService user (optional, auto-assigned if not specified)
#   -Gid GID        Specify GID for FubarService group (optional, uses Administrators group)
#   -HomeDir DIR    Specify home directory (default: C:\ProgramData\FUBAR)
#   -Password PWD   Specify password for service account (default: auto-generated)
#   -Help           Show this help message
#
# Note: This script must be run as Administrator

param(
    [int]$Uid = 0,
    [int]$Gid = 0,
    [string]$HomeDir = "C:\ProgramData\FUBAR",
    [string]$Password = $null,
    [switch]$Help
)

# Colors for output
$ErrorColor = "Red"
$SuccessColor = "Green"
$WarningColor = "Yellow"

function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
}

# Show help
if ($Help) {
    Write-Host "Usage: .\scripts\setup-fubar-user-windows.ps1 [options]"
    Write-Host ""
    Write-Host "Creates a dedicated service account for FUBAR agent on Windows"
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  -Uid UID        Specify UID for FubarService user"
    Write-Host "  -Gid GID        Specify GID for FubarService group"
    Write-Host "  -HomeDir DIR    Specify home directory (default: C:\ProgramData\FUBAR)"
    Write-Host "  -Password PWD   Specify password for service account (auto-generated if not specified)"
    Write-Host "  -Help           Show this help message"
    exit 0
}

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-ColorOutput "Error: This script must be run as Administrator" $ErrorColor
    Write-ColorOutput "Right-click PowerShell and select 'Run as Administrator'" $WarningColor
    exit 1
}

# Check if running on Windows
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-ColorOutput "Error: This script requires PowerShell 5.1 or higher" $ErrorColor
    exit 1
}

$FUBAR_USER = "FubarService"
$FUBAR_GROUP = "Administrators"

Write-ColorOutput "🔧 Setting up FUBAR Agent Service Account on Windows" "White"
Write-ColorOutput "===================================================" "White"
Write-Host ""

# Generate password if not provided
if (-not $Password) {
    $Password = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 32 | ForEach-Object {[char]$_})
    Write-ColorOutput "🔐 Generated secure password for service account" "Green"
}

# Check if user already exists
$existingUser = Get-LocalUser -Name $FUBAR_USER -ErrorAction SilentlyContinue
if ($existingUser) {
    Write-ColorOutput "⚠️  User $FUBAR_USER already exists" $WarningColor
    $response = Read-Host "Do you want to continue? This will update the existing user. (y/N)"
    if ($response -ne "y" -and $response -ne "Y") {
        Write-ColorOutput "Aborted." "Yellow"
        exit 0
    }
    Write-ColorOutput "📝 Updating existing user..." "Yellow"
    
    # Update password
    $securePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
    Set-LocalUser -Name $FUBAR_USER -Password $securePassword -PasswordNeverExpires $true -UserMayNotChangePassword $true
    Write-ColorOutput "✅ Updated user password" "Green"
} else {
    Write-ColorOutput "📝 Creating $FUBAR_USER user..." "White"
    
    # Create user
    $securePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
    $userParams = @{
        Name = $FUBAR_USER
        Password = $securePassword
        Description = "FUBAR Agent Service Account"
        UserMayNotChangePassword = $true
        PasswordNeverExpires = $true
        AccountNeverExpires = $true
    }
    
    New-LocalUser @userParams | Out-Null
    Write-ColorOutput "✅ Created user $FUBAR_USER" "Green"
    
    # Add to Administrators group
    try {
        Add-LocalGroupMember -Group $FUBAR_GROUP -Member $FUBAR_USER -ErrorAction Stop
        Write-ColorOutput "✅ Added $FUBAR_USER to $FUBAR_GROUP group" "Green"
    } catch {
        if ($_.Exception.Message -like "*already a member*") {
            Write-ColorOutput "⚠️  User is already a member of $FUBAR_GROUP" "Warning"
        } else {
            Write-ColorOutput "⚠️  Failed to add user to $FUBAR_GROUP: $($_.Exception.Message)" "Warning"
        }
    }
}

# Create directory structure
Write-Host ""
Write-ColorOutput "📁 Creating directory structure..." "White"

$directories = @(
    "$HomeDir",
    "$HomeDir\quarantine",
    "$HomeDir\logs",
    "$HomeDir\config",
    "$HomeDir\tmp",
    "$HomeDir\venv"
)

foreach ($dir in $directories) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-ColorOutput "  ✅ Created: $dir" "Green"
    } else {
        Write-ColorOutput "  ⚠️  Already exists: $dir" "Yellow"
    }
}

# Set permissions
Write-Host ""
Write-ColorOutput "🔐 Setting directory permissions..." "White"
try {
    icacls "$HomeDir" /grant "${FUBAR_USER}:(OI)(CI)F" /T | Out-Null
    Write-ColorOutput "✅ Set permissions for $FUBAR_USER" "Green"
} catch {
    Write-ColorOutput "⚠️  Failed to set permissions: $($_.Exception.Message)" "Warning"
    Write-ColorOutput "   You may need to set permissions manually" "Yellow"
}

# Create Python virtual environment
Write-Host ""
Write-ColorOutput "🐍 Setting up Python virtual environment..." "White"

$pythonExe = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonExe) {
    $pythonExe = Get-Command python3 -ErrorAction SilentlyContinue
}

if (-not $pythonExe) {
    Write-ColorOutput "⚠️  Python not found in PATH" $WarningColor
    Write-ColorOutput "   Please install Python 3.8+ and add it to PATH" $WarningColor
    Write-ColorOutput "   Virtual environment will be created later" $WarningColor
} else {
    $venvPath = "$HomeDir\venv"
    if (Test-Path "$venvPath\Scripts\python.exe") {
        Write-ColorOutput "⚠️  Virtual environment already exists" $WarningColor
    } else {
        try {
            # Create venv as the service user (requires runas or scheduled task)
            # For now, create it and change ownership
            & $pythonExe.Source -m venv $venvPath
            Write-ColorOutput "✅ Created Python virtual environment" $SuccessColor
            
            # Upgrade pip
            & "$venvPath\Scripts\python.exe" -m pip install --upgrade pip | Out-Null
            Write-ColorOutput "✅ Upgraded pip" $SuccessColor
        } catch {
            Write-ColorOutput "⚠️  Failed to create virtual environment: $($_.Exception.Message)" $WarningColor
            Write-ColorOutput "   You can create it manually later" $WarningColor
        }
    }
}

# Set up credential storage
Write-Host ""
Write-ColorOutput "🔐 Setting up credential storage..." "White"
try {
    # Store password in Credential Manager
    $credential = New-Object System.Management.Automation.PSCredential($FUBAR_USER, $securePassword)
    cmdkey /add:fubar-server /user:$FUBAR_USER /pass:$Password | Out-Null
    Write-ColorOutput "✅ Configured Credential Manager" $SuccessColor
} catch {
    Write-ColorOutput "⚠️  Failed to configure Credential Manager: $($_.Exception.Message)" $WarningColor
}

# Create Windows Service using NSSM (if available) or provide instructions
Write-Host ""
Write-ColorOutput "📋 Windows Service Configuration..." "White"

$nssmPath = Get-Command nssm -ErrorAction SilentlyContinue
if ($nssmPath) {
    Write-ColorOutput "✅ NSSM found, you can install the service with:" $SuccessColor
    Write-ColorOutput "   nssm install fubar-agent" "White"
    Write-ColorOutput "   nssm set fubar-agent Application $HomeDir\venv\Scripts\python.exe" "White"
    Write-ColorOutput "   nssm set fubar-agent AppParameters `"-m fubar_agent.cli start --config-file $HomeDir\config\agent_config.yaml`"" "White"
    Write-ColorOutput "   nssm set fubar-agent AppDirectory $HomeDir" "White"
    Write-ColorOutput "   nssm set fubar-agent ObjectName $FUBAR_USER $Password" "White"
    Write-ColorOutput "   nssm start fubar-agent" "White"
} else {
    Write-ColorOutput "⚠️  NSSM not found" $WarningColor
    Write-ColorOutput "   Download from: https://nssm.cc/download" $WarningColor
    Write-ColorOutput "   Or use Windows Task Scheduler to run the agent" $WarningColor
}

# Instructions
Write-Host ""
Write-ColorOutput "==================================================" "White"
Write-ColorOutput "✅ FUBAR Agent Service Account Setup Complete!" $SuccessColor
Write-ColorOutput "==================================================" "White"
Write-Host ""
Write-ColorOutput "📋 Next Steps:" "White"
Write-Host ""
Write-ColorOutput "1. Install the FUBAR agent:" "White"
Write-ColorOutput "   $HomeDir\venv\Scripts\pip.exe install -e C:\path\to\fubar-agent" "Yellow"
Write-Host ""
Write-ColorOutput "2. Configure the agent:" "White"
Write-ColorOutput "   $HomeDir\venv\Scripts\python.exe -m fubar_agent.cli configure" "Yellow"
Write-ColorOutput "   # Use --config-file $HomeDir\config\agent_config.yaml" "Yellow"
Write-Host ""
Write-ColorOutput "3. Install as Windows Service (using NSSM):" "White"
Write-ColorOutput "   Download NSSM from: https://nssm.cc/download" "Yellow"
Write-ColorOutput "   Then run the commands shown above" "Yellow"
Write-Host ""
Write-ColorOutput "4. Or use Task Scheduler:" "White"
Write-ColorOutput "   - Create a new task" "Yellow"
Write-ColorOutput "   - Run as: $FUBAR_USER" "Yellow"
Write-ColorOutput "   - Program: $HomeDir\venv\Scripts\python.exe" "Yellow"
Write-ColorOutput "   - Arguments: -m fubar_agent.cli start --config-file $HomeDir\config\agent_config.yaml" "Yellow"
Write-Host ""
Write-ColorOutput "📝 User Information:" "White"
Write-ColorOutput "   User: $FUBAR_USER" "Yellow"
Write-ColorOutput "   Home: $HomeDir" "Yellow"
Write-ColorOutput "   Password: $Password" "Yellow"
Write-ColorOutput "   Group: $FUBAR_GROUP" "Yellow"
Write-Host ""
Write-ColorOutput "⚠️  IMPORTANT: Save the password securely!" $WarningColor
Write-ColorOutput "   You'll need it to configure the service account" $WarningColor
Write-Host ""

