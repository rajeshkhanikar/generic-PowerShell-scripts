<#
    This PowerShell script does the following:
    - Detects if the Site24x7 Windows Monitoring Agent is already installed.
    - If the agent is installed, it uninstalls the agent using the correct uninstallation command.
    - Downloads the Site24x7 Windows Monitoring Agent MSI installer if internet is available, or installs from the local path if not.
    - Installs the MSI agent installer with the provided Device Key in silent mode.
    - Logs the outcome of each operation and verbose error details if any.
    - Verifies installation success by checking the Windows Event Log.
#>

# ---------------------------------------------------------------
# Initialize variables
$Site24x7InstallerPath = "C:\Site24x7_Installer"
$logFilePath = "$Site24x7InstallerPath\install_log.txt"
$Site24x7AgentDLurl = "https://staticdownloads.site24x7.eu/server/Site24x7WindowsAgent.msi"
$Site24x7AgentMSIfile = "$Site24x7InstallerPath\Site24x7WindowsAgent.msi"
$DeviceKey = "DeviceKey"  # Replace with your actual device key
$ServiceName = "Site24x7 Windows Agent"
$UninstallGUID = "{0C16B7BE-0473-4345-B182-E61A209699D4}" #MSI GUID of site24x7 agent

<# 
    The below path is set to point to a folder under C:\ (root)
    The folder is automatically copied by the Windows installer from the media "\sources\$OEM$\$1\Site24x7_Installer"
    You must have the Site24x7WindowsAgent.msi placed in the folder in the Windows ISO image.
#>
$localInstallerPath = "C:\Site24x7_Installer\Site24x7WindowsAgent.msi" 
# --------------------------------------------------------------- 

# Ensure the directory exists
if (-not (Test-Path -Path $Site24x7InstallerPath)) {
    New-Item -ItemType Directory -Path $Site24x7InstallerPath
}

# Create the log file if it doesn't exist
if (-not (Test-Path -Path $logFilePath)) {
    New-Item -ItemType File -Path $logFilePath
}

# Function to write log with timestamp and log level
function Write-Log {
    Param (
        [string]$logLevel,
        [string]$logString
    )
    $timeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "${timeStamp}: ${logLevel}: ${logString}" | Out-File -FilePath $logFilePath -Append
}

# Function to log system information
function Write-SystemInfo {
    Write-Log "INFORMATION" "Logging system information."
    $cpu = Get-WmiObject Win32_Processor | Measure-Object -Property LoadPercentage -Average | Select-Object -ExpandProperty Average
    $memory = Get-WmiObject Win32_OperatingSystem | Select-Object -ExpandProperty FreePhysicalMemory
    $disk = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='C:'" | Select-Object -ExpandProperty FreeSpace
    Write-Log "INFORMATION" "CPU Load: $cpu%"
    Write-Log "INFORMATION" "Free Memory: $([math]::Round($memory/1KB, 2)) MB"
    Write-Log "INFORMATION" "Free Disk Space (C:): $([math]::Round($disk/1GB, 2)) GB"
}

# ---------------------------------------------------------------
# Ensure the script runs with administrator privileges
# ---------------------------------------------------------------
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Log "INFORMATION" "Script not running as administrator. Restarting with elevated privileges."
    $newProcess = Start-Process -FilePath "powershell.exe" -ArgumentList ("-File `"" + $MyInvocation.MyCommand.Path + "`"") -Verb RunAs -PassThru
    $newProcess.WaitForExit()
    exit
} else {
    Write-Log "INFORMATION" "Script is running with administrator privileges."
    Write-SystemInfo
}

# ---------------------------------------------------------------
# Detect existing Site24x7 Windows Agent installation by checking the service
# ---------------------------------------------------------------
try {
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

    if ($service) {
        Write-Log "INFORMATION" "Existing Site24x7 Agent service detected. Initiating uninstallation process."

        # Uninstall the Site24x7 Agent using the correct Product Code (GUID)
        Write-Log "INFORMATION" "Uninstalling Site24x7 Agent using GUID $UninstallGUID"
        Start-Process -FilePath "msiexec.exe" -ArgumentList "/X$UninstallGUID /quiet" -NoNewWindow -Wait
        Write-Log "INFORMATION" "Site24x7 Agent uninstallation command executed."

        # Kill the tray icon process if it's still running
        Write-Log "INFORMATION" "Attempting to kill Site24x7 Tray Icon process if running."
        Stop-Process -Name "LiteAgentTrayIcon" -Force -ErrorAction SilentlyContinue

        # Stop and delete services
        Write-Log "INFORMATION" "Stopping and deleting Site24x7 services."
        & Set-Content stop "Site24x7 Windows Agent"
        & Set-Content stop "Site24x7 Agent Helper"
        & Set-Content delete "Site24x7 Windows Agent"
        & Set-Content delete "Site24x7 Agent Helper"

        # Delete registry entries with existence check
        Write-Log "INFORMATION" "Deleting registry entries."

        $regPaths = @(
            "HKLM\SOFTWARE\ManageEngine\Site24x7WindowsAgent",
            "HKLM\SOFTWARE\Wow6432Node\ManageEngine\Site24x7WindowsAgent",
            "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Management\ARPCache\$UninstallGUID",
            "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\App Management\ARPCache\$UninstallGUID",
            "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\EB7B61C0374054341B286EA10269994D",
            "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\EB7B61C0374054341B286EA10269994D",
            "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$UninstallGUID",
            "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$UninstallGUID"
        )

        foreach ($regPath in $regPaths) {
            if (Test-Path -Path "Registry::$regPath") {
                reg delete "$regPath" /f
                Write-Log "INFORMATION" "Deleted registry key: $regPath"
            } else {
                Write-Log "INFORMATION" "Registry key not found: $regPath"
            }
        }

        # Delete directories using Remove-Item in PowerShell
        Write-Log "INFORMATION" "Deleting Site24x7 directories."
        Remove-Item -Path "C:\Program Files (x86)\Site24x7" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "C:\Program Files\Site24x7" -Recurse -Force -ErrorAction SilentlyContinue

        # Delete installation/uninstallation logs
        Write-Log "INFORMATION" "Deleting Site24x7 installation/uninstallation logs."
        Remove-Item -Path "C:\InstallSite24x7WindowsAgent.log" -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "C:\UnInstallSite24x7WindowsAgent" -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "C:\Site24x7Debug.log" -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "C:\DebugTrayIcon.txt" -Force -ErrorAction SilentlyContinue

        Write-Log "INFORMATION" "Site24x7 Agent uninstallation completed."
    } else {
        Write-Log "INFORMATION" "No existing Site24x7 installation detected."
    }
} catch {
    Write-Log "ERROR" "Error during service detection or uninstallation: $_"
    throw $_
}

# ---------------------------------------------------------------
# Download the Site24x7 Agent MSI
# ---------------------------------------------------------------
try {
    # Check if Internet connection is available
    if (Test-Connection -ComputerName google.com -Count 1 -Quiet) {
        Write-Log "INFORMATION" "Internet connection available. Downloading installer from: $Site24x7AgentDLurl"
        Invoke-WebRequest -Uri $Site24x7AgentDLurl -OutFile "$Site24x7InstallerPath\Site24x7WindowsAgent.msi"
        Write-Log "INFORMATION" "Downloaded installer."
    } else {
        Write-Log "INFORMATION" "No Internet connection available. Using local installer at: $localInstallerPath"
        $Site24x7AgentMSIfile = $localInstallerPath
    }
} catch {
    Write-Log "ERROR" "Error during download or using local installer: $_"
    throw $_
}

# ---------------------------------------------------------------
# Install the MSI installer with the provided Device Key in silent mode
# ---------------------------------------------------------------
try {
    $arguments = "/i `"$Site24x7AgentMSIfile`" EDITA1=$DeviceKey ENABLESILENT=YES REBOOT=ReallySuppress /qn"
    Write-Log "INFORMATION" "Installing MSI: $Site24x7AgentMSIfile with arguments: $arguments"
    Start-Process -FilePath "msiexec.exe" -ArgumentList $arguments -NoNewWindow -Wait
    Write-Log "INFORMATION" "MSI installed successfully."

    # Check if the MSI has been installed by checking the MSI's Product Code.
    $productCode = (Get-WmiObject -Query "SELECT * FROM Win32_Product WHERE IdentifyingNumber='$UninstallGUID'" -ErrorAction SilentlyContinue).IdentifyingNumber
    if ($productCode -eq $UninstallGUID) {
        Write-Log "INFORMATION" "MSI Product Code detected: $productCode"
    } else {
        Write-Log "ERROR" "MSI Product Code not detected. Installation might have failed."
        throw "MSI Product Code not detected. Installation might have failed."
    }
} catch {
    Write-Log "ERROR" "Error installing MSI: $_"
    throw $_
}

# ---------------------------------------------------------------
# Verify Installation via Event Log
# ---------------------------------------------------------------
try {
    Write-Log "INFORMATION" "Verifying installation by checking the Windows Event Log."

    # Set the time window to the last 10 minutes
    $startTime = (Get-Date).AddMinutes(-10)

    # Retrieve all events with Event ID 11707 from the last 10 minutes
    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Application'; 
        ID = 11707;
        StartTime = $startTime
    }

    if ($events) {
        # Check for the specific message related to Site24x7 Windows Agent
        $site24x7Event = $events | Where-Object { $_.Message -like '*Site24x7 Windows Agent*' }

        if ($site24x7Event) {
            Write-Log "INFORMATION" "Installation verified successfully via Event Log. Event ID 11707 found for Site24x7 Windows Agent."
        } else {
            Write-Log "ERROR" "Event ID 11707 found, but no matching message for Site24x7 Windows Agent."
            throw "Installation verification via Event Log failed."
        }
    } else {
        Write-Log "ERROR" "No Event ID 11707 found in the last 10 minutes."
        throw "Installation verification via Event Log failed."
    }
} catch {
    Write-Log "ERROR" "Error during installation verification: $_"
    throw $_
}
