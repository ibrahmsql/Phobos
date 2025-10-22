# Phobos Port Scanner - Windows Installation Script
# Usage: iwr -useb https://raw.githubusercontent.com/ibrahmsql/phobos/main/install_windows.ps1 | iex

# Requires PowerShell 5.1 or later

param(
    [string]$InstallDir = "$env:ProgramFiles\Phobos",
    [switch]$NoPath,
    [switch]$NoConfig
)

$ErrorActionPreference = "Stop"

# Configuration
$Repo = "ibrahmsql/phobos"
$BinaryName = "phobos.exe"
$ConfigDir = "$env:USERPROFILE\.phobos"

# Colors
function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Blue
}

function Write-Success {
    param([string]$Message)
    Write-Host "[✓] $Message" -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[⚠] $Message" -ForegroundColor Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "[✗] $Message" -ForegroundColor Red
    exit 1
}

# Banner
function Show-Banner {
    Write-Host @"
____  _   _   ___   ____   ___   ____   _____ 
|  _ \| | | | / _ \ | __ ) / _ \ |  _ \ | ____| 
| |_) | |_| || | | ||  _ \| | | || | | ||  _|  
|  __/|  _  || |_| || |_) | |_| || |_| || |___ 
|_|   |_| |_| \___/ |____/ \___/ |____/ |_____| 

"@ -ForegroundColor Red
    Write-Host "Phobos Installer for Windows" -ForegroundColor Cyan
    Write-Host "The Blazingly Fast Port Scanner" -ForegroundColor Yellow
    Write-Host ""
}

# Check if running as administrator
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Detect system architecture
function Get-SystemArchitecture {
    $arch = [System.Environment]::GetEnvironmentVariable("PROCESSOR_ARCHITECTURE")
    switch ($arch) {
        "AMD64" { return "x86_64" }
        "ARM64" { return "aarch64" }
        default { Write-Error "Unsupported architecture: $arch" }
    }
}

# Download Phobos binary
function Install-Phobos {
    param([string]$Arch)
    
    Write-Info "Downloading Phobos for $Arch..."
    
    # Create temporary directory
    $tempDir = New-Item -ItemType Directory -Path "$env:TEMP\phobos_install" -Force
    
    # Get latest release URL
    $latestUrl = "https://github.com/$Repo/releases/latest/download/phobos-windows-$Arch.exe"
    $downloadPath = Join-Path $tempDir.FullName $BinaryName
    
    try {
        # Download binary
        Invoke-WebRequest -Uri $latestUrl -OutFile $downloadPath -UseBasicParsing
        Write-Success "Download complete"
    }
    catch {
        Write-Error "Failed to download Phobos: $_"
    }
    
    # Create installation directory
    Write-Info "Installing Phobos to $InstallDir..."
    
    if (Test-Administrator) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
        Copy-Item -Path $downloadPath -Destination (Join-Path $InstallDir $BinaryName) -Force
    }
    else {
        Write-Warning "Not running as administrator. Installing to user directory..."
        $InstallDir = "$env:LOCALAPPDATA\Programs\Phobos"
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
        Copy-Item -Path $downloadPath -Destination (Join-Path $InstallDir $BinaryName) -Force
    }
    
    # Cleanup
    Remove-Item -Path $tempDir -Recurse -Force
    
    Write-Success "Phobos installed successfully!"
    
    return $InstallDir
}

# Add to PATH
function Add-ToPath {
    param([string]$Directory)
    
    if ($NoPath) {
        Write-Info "Skipping PATH modification (--NoPath specified)"
        return
    }
    
    Write-Info "Adding Phobos to PATH..."
    
    $currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
    
    if ($currentPath -notlike "*$Directory*") {
        $newPath = "$currentPath;$Directory"
        [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
        $env:Path = "$env:Path;$Directory"
        Write-Success "Added to PATH. Restart your terminal to use 'phobos' command"
    }
    else {
        Write-Info "Directory already in PATH"
    }
}

# Setup configuration
function Setup-Config {
    if ($NoConfig) {
        Write-Info "Skipping configuration setup (--NoConfig specified)"
        return
    }
    
    Write-Info "Setting up configuration directory..."
    New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null
    
    # Download example config
    $configUrl = "https://raw.githubusercontent.com/$Repo/main/phobos.toml.example"
    $configPath = Join-Path $ConfigDir "config.toml"
    
    if (-not (Test-Path $configPath)) {
        try {
            Invoke-WebRequest -Uri $configUrl -OutFile $configPath -UseBasicParsing
            Write-Success "Configuration file created at $ConfigDir"
        }
        catch {
            Write-Warning "Failed to download config file: $_"
        }
    }
}

# Install PowerShell completion
function Install-Completion {
    Write-Info "Installing PowerShell completion..."
    
    $completionDir = "$env:USERPROFILE\Documents\PowerShell\Modules\PhobosCompletion"
    New-Item -ItemType Directory -Path $completionDir -Force | Out-Null
    
    # Create completion script
    $completionScript = @'
using namespace System.Management.Automation
using namespace System.Management.Automation.Language

Register-ArgumentCompleter -Native -CommandName phobos -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)
    
    $customComp = @{
        '-p' = @('22', '80', '443', '1-1000', '1-65535')
        '-s' = @('syn', 'connect', 'udp', 'fin', 'null', 'xmas')
        '-T' = @('0', '1', '2', '3', '4', '5')
        '-o' = @('text', 'json', 'xml', 'csv', 'nmap', 'greppable')
        '--profile' = @('stealth', 'aggressive', 'comprehensive', 'quick')
        '--stealth' = @('0', '1', '2', '3', '4', '5')
    }
    
    $customComp.Keys | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
        [CompletionResult]::new($_, $_, 'ParameterValue', $_)
    }
}
'@
    
    Set-Content -Path (Join-Path $completionDir "PhobosCompletion.psm1") -Value $completionScript
    
    # Add to profile
    $profileContent = @"
# Phobos completion
Import-Module PhobosCompletion
"@
    
    if (Test-Path $PROFILE) {
        $currentProfile = Get-Content $PROFILE -Raw
        if ($currentProfile -notlike "*PhobosCompletion*") {
            Add-Content -Path $PROFILE -Value "`n$profileContent"
        }
    }
    else {
        New-Item -Path $PROFILE -Force | Out-Null
        Set-Content -Path $PROFILE -Value $profileContent
    }
    
    Write-Success "PowerShell completion installed"
}

# Create desktop shortcut
function New-DesktopShortcut {
    param([string]$InstallPath)
    
    $WScriptShell = New-Object -ComObject WScript.Shell
    $shortcutPath = Join-Path ([Environment]::GetFolderPath("Desktop")) "Phobos.lnk"
    $shortcut = $WScriptShell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = "powershell.exe"
    $shortcut.Arguments = "-NoExit -Command `"cd ~; phobos --help`""
    $shortcut.WorkingDirectory = $env:USERPROFILE
    $shortcut.IconLocation = Join-Path $InstallPath $BinaryName
    $shortcut.Description = "Phobos Port Scanner"
    $shortcut.Save()
    
    Write-Success "Desktop shortcut created"
}

# Post-installation information
function Show-PostInstall {
    param([string]$InstallPath)
    
    Write-Host ""
    Write-Host "═══════════════════════════════════════════" -ForegroundColor Green
    Write-Host "  Phobos Installation Complete! 🚀" -ForegroundColor Green
    Write-Host "═══════════════════════════════════════════" -ForegroundColor Green
    Write-Host ""
    
    Write-Host "Installation Details:" -ForegroundColor Cyan
    Write-Host "  Binary: " -NoNewline
    Write-Host (Join-Path $InstallPath $BinaryName) -ForegroundColor Yellow
    Write-Host "  Config: " -NoNewline
    Write-Host $ConfigDir -ForegroundColor Yellow
    Write-Host ""
    
    Write-Host "Quick Start:" -ForegroundColor Cyan
    Write-Host "  phobos --help" -ForegroundColor Yellow -NoNewline
    Write-Host "                    # Show help"
    Write-Host "  phobos scanme.nmap.org" -ForegroundColor Yellow -NoNewline
    Write-Host "          # Basic scan"
    Write-Host "  phobos target.com -p 1-1000" -ForegroundColor Yellow -NoNewline
    Write-Host "     # Port range"
    Write-Host "  phobos target.com --wrath" -ForegroundColor Yellow -NoNewline
    Write-Host "       # Aggressive scan"
    Write-Host ""
    
    Write-Host "Documentation:" -ForegroundColor Cyan
    Write-Host "  https://github.com/$Repo" -ForegroundColor Blue
    Write-Host ""
    
    Write-Host "Note:" -ForegroundColor Yellow -NoNewline
    Write-Host " Restart your terminal to use the 'phobos' command"
    Write-Host ""
    
    # Verify installation
    $phobosPath = Join-Path $InstallPath $BinaryName
    if (Test-Path $phobosPath) {
        Write-Host "Installation verified!" -ForegroundColor Green
    }
    
    Write-Host ""
    Write-Host "`"Let your ports tremble.`"" -ForegroundColor Red -NoNewline
    Write-Host " ⚡"
    Write-Host ""
}

# Main installation
function Main {
    Show-Banner
    
    # Check administrator
    if (-not (Test-Administrator)) {
        Write-Warning "Not running as administrator. Installing to user directory..."
    }
    
    # Detect architecture
    $arch = Get-SystemArchitecture
    Write-Info "Detected: Windows ($arch)"
    
    # Install Phobos
    $installPath = Install-Phobos -Arch $arch
    
    # Add to PATH
    Add-ToPath -Directory $installPath
    
    # Setup configuration
    Setup-Config
    
    # Install completion
    Install-Completion
    
    # Create desktop shortcut
    try {
        New-DesktopShortcut -InstallPath $installPath
    }
    catch {
        Write-Warning "Failed to create desktop shortcut: $_"
    }
    
    # Show post-installation info
    Show-PostInstall -InstallPath $installPath
}

# Run main installation
try {
    Main
}
catch {
    Write-Error "Installation failed: $_"
}
