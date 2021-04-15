[CmdletBinding(SupportsShouldProcess=$true)]
param
(
    [Parameter(Position = 0, Mandatory)]
    [String]$Path,
    [Parameter(Position = 1)]
    [Switch]$JustRemove,
    [Parameter(Position = 2, Mandatory)]
    [Switch]$HKLMSwitch,
    [Parameter(Position = 3, Mandatory)]
    [Switch]$HKDUSwitch,
    [Parameter(Position = 4, Mandatory)]
    [Switch]$HKCUSwitch,
    [Parameter(Position = 5)]
    [Switch]$Restart
)

########################################################
###############ranWare All-Mighty Tools#################
########################################################
# Big part: Craft YT@craftcomputing
# But i think i kind of did perfect it :P

# And some sub parts and inspiration from: https://github.com/Sycnex

# Also if it happens that u find yourself somewhere here without mention, feel free to let me know, as i could forget, not intentionally though...

Write-Host "Environment setup..."
Set-Location $Path

## For Import
Set-ExecutionPolicy Unrestricted -Scope Process -Force -Confirm:$false

## Import Functions
. $Path\ranWareWindexInclude.ps1

## Revert Execution Policy Changes
Set-ExecutionPolicy Default -Scope Process -Force -Confirm:$false

## Add registry key for easier access of Classes Root
New-PSDrive -PSProvider Registry -Name HKCR -Root HKEY_CLASSES_ROOT

## Add registry key for Users
New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS

## Import Hive of Default User
New-PSDrive-RegistryLoadHive -Name HKDU -Root HKEY_USERS\Default -Path "C:\Users\Default\NTUSER.DAT"

########################################################
########################################################
########################################################

## Maximize, DUNNO hh
Set-WindowStyle MAXIMIZE

##########
# Packages
##########

Remove-AppxPackage-CustomSet

##########
# Features
##########

Write-Host "Uninstalling WCF Port Sharing application & WCF services..."
Disable-WindowsOptionalFeature -FeatureName WCF-TCP-PortSharing45 -Online -NoRestart -EA SilentlyContinue
Disable-WindowsOptionalFeature -FeatureName WCF-Services45 -Online -NoRestart -EA SilentlyContinue

Write-Host "Uninstalling IE11 application..."
Disable-WindowsOptionalFeature -FeatureName Internet-Explorer-Optional-amd64 -Online -NoRestart -EA SilentlyContinue
Get-WindowsCapability -Online | ? { $_.Name -like "Browser.InternetExplorer*" } | Remove-WindowsCapability –Online -EA SilentlyContinue

Write-Host "Uninstalling WMP application..."
Disable-WindowsOptionalFeature -FeatureName WindowsMediaPlayer -Online -NoRestart -EA SilentlyContinue
Get-WindowsCapability -Online | ? { $_.Name -like "Media.WindowsMediaPlayer*" } | Remove-WindowsCapability –Online -EA SilentlyContinue

Write-Host "Uninstalling Work Folders Client..."
Disable-WindowsOptionalFeature -FeatureName WorkFolders-Client -Online -NoRestart -EA SilentlyContinue

Write-Host "Uninstalling WordPad application..."
Get-WindowsCapability -Online | ? { $_.Name -like "Microsoft.Windows.WordPad*" } | Remove-WindowsCapability –Online -EA SilentlyContinue

Write-Host "Uninstalling Support..."
Get-WindowsCapability -Online | ? { $_.Name -like "*ContactSupport*" } | Remove-WindowsCapability –Online -EA SilentlyContinue

##########
# Registry
##########

Clear-Registry

##########
# Manifest
##########

Appx-Fix

## Removing-Apps-Only Mode
If ($JustRemove -eq $true) { Exit }

$layoutName = "LayoutModification.xml"
$layoutFile = "$Path\Data\$layoutName"
$layoutSaved = $false

## Classic-Prep-Mode-Stage-1
If ((Test-Path $Path\Data\unattend_sysprep.xml) -eq $true)
{
    ## Move unattended file to sysprep.exe (Contains CopyProfile, clean Admininistator account(script included and moven in next step), ...)
    #Write-Host "Moving unattended.xml into sysprep folder..."
    #Move-Item -Path $Path\Data\unattend_sysprep.xml -Destination C:\Windows\System32\sysprep\unattend.xml -Force
    Write-Host "Moving SysprepScript into startup folder..."
    Move-Item -Path "$Path\ranWareWindexSysprep.bat" -Destination "$ENV:USERPROFILE\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\" -Force
}

## Classic-Prep-Mode-Stage-2
if ((Test-Path $layoutFile) -eq $true)
{
    Write-Host "Moving Start & Taskbar layout..."

    $layoutWin = "$ENV:WINDIR\$layoutName"
    #$shellFolder = "Appdata\Local\Microsoft\Windows\Shell\"
    #$userFolder = "$ENV:USERPROFILE\$shellP"
    #$defaultFolder = "C:\Users\Default\$shellP"
    #$defLay = "DefaultLayouts.xml"

    #If (Test-Path ($bP + $def)) { Remove-Item ($bP + $def) -Force }
    #Copy-Item -Path $layoutFile -Destination ($bP + $def) -Force
    #If (Test-Path ($bDP + $def)) { Remove-Item ($bDP + $def) -Force }
    #Copy-Item -Path $layoutFile -Destination ($bDP + $def) -Force
    #Copy-Item -Path $layoutFile -Destination ($bP + $tdef) -Force
    #Copy-Item -Path $layoutFile -Destination ($bDP + $tdef) -Force
    #Copy-Item -Path $layoutFile -Destination ($bP + $layoutName) -Force
    #Copy-Item -Path $layoutFile -Destination ($bDP + $layoutName) -Force

    Move-Item -Path $layoutFile -Destination $layoutWin -Force
         
    $layoutFile = $layoutWin
    $layoutSaved = $true
}

## At stage is script used
$setupState = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\State" -Name "ImageState" -EA SilentlyContinue
## Personalization of Default User only in Audit Mode
if ($setupState.ImageState -eq "IMAGE_STATE_COMPLETE") { $HKDUSwitch = $FALSE }

##########
#  Privacy
##########s
# -- Craft  

Write-Host "Disabling Telemetry..."
Conditional-Set-ItemProperty $HKLMSwitch -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0

Write-Host "Disabling Wi-Fi Sense..."
Conditional-New-FolderForced $HKLMSwitch -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting"
Conditional-Set-ItemProperty $HKLMSwitch -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Value 0
Conditional-Set-ItemProperty $HKLMSwitch -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Value 0

Write-Host "Disabling SmartScreen Filter..."
Conditional-Set-ItemProperty $HKLMSwitch -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "Off"

Write-Host "Disabling Bing Search in Start Menu..."
Conditional-New-FolderForced $HKDUSwitch -Path "HKDU:\Software\Microsoft\Windows\CurrentVersion\Search"
Conditional-Set-ItemProperty $HKDUSwitch -Path "HKDU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Value 0
Conditional-New-FolderForced $HKCUSwitch -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search"
Conditional-Set-ItemProperty $HKCUSwitch -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Value 0

Write-Host "Disabling Location Tracking..."
Conditional-New-FolderForced $HKLMSwitch -Path "HKLM:\System\CurrentControlSet\Services\lfsvc\Service\Configuration"
Conditional-Set-ItemProperty $HKLMSwitch -Path "HKLM:\System\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Value 0
Conditional-Set-ItemProperty $HKLMSwitch -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Value 0

Write-Host "Disabling Feedback..."
Conditional-New-FolderForced $HKDUSwitch -Path "HKDU:\Software\Microsoft\Siuf\Rules"
Conditional-Set-ItemProperty $HKDUSwitch -Path "HKDU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Value 0
Conditional-New-FolderForced $HKCUSwitch -Path "HKCU:\Software\Microsoft\Siuf\Rules"
Conditional-Set-ItemProperty $HKCUSwitch -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Value 0

Write-Host "Disabling Advertising ID..."
Conditional-New-FolderForced $HKDUSwitch -Path "HKDU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" 
Conditional-Set-ItemProperty $HKDUSwitch -Path "HKDU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0
Conditional-New-FolderForced $HKCUSwitch -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" 
Conditional-Set-ItemProperty $HKCUSwitch -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0

Write-Host "Cripling Cortana..."
Conditional-New-FolderForced $HKDUSwitch -Path "HKDU:\Software\Microsoft\InputPersonalization\TrainedDataStore"
Conditional-Set-ItemProperty $HKDUSwitch -Path "HKDU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Value 1
Conditional-Set-ItemProperty $HKDUSwitch -Path "HKDU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Value 1
Conditional-Set-ItemProperty $HKDUSwitch -Path "HKDU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Value 0
Conditional-New-FolderForced $HKCUSwitch -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore"
Conditional-Set-ItemProperty $HKCUSwitch -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Value 1
Conditional-Set-ItemProperty $HKCUSwitch -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Value 1
Conditional-Set-ItemProperty $HKCUSwitch -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Value 0

Write-Host "Restricting Windows Update P2P only to local network..."
Conditional-New-FolderForced $HKLMSwitch -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config"
Conditional-Set-ItemProperty $HKLMSwitch -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Value 1
Conditional-New-FolderForced $HKDUSwitch -Path "HKDU:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization"
Conditional-Set-ItemProperty $HKDUSwitch -Path "HKDU:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -Name "SystemSettingsDownloadMode" -Value 3
Conditional-New-FolderForced $HKCUSwitch -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization"
Conditional-Set-ItemProperty $HKCUSwitch -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -Name "SystemSettingsDownloadMode" -Value 3

##########
# Services
##########
# -- Craft

Write-Host "Removing AutoLogger file and restricting directory..."
$autoLoggerDir = "$ENV:PROGRAMDATA\Microsoft\Diagnosis\ETLLogs\AutoLogger"
Remove-Item "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl" -EA SilentlyContinue -Force
ICACLS $autoLoggerDir /Deny SYSTEM:`(OI`)`(CI`)F | Out-Null

Write-Host "Stopping and disabling Diagnostics Tracking Service..."
Stop-Service "DiagTrack"
Set-Service "DiagTrack" -StartupType Disabled

Write-Host "Disabling Windows Update automatic restart..."
Conditional-Set-ItemProperty $HKLMSwitch -Path "HKLM:\Software\Microsoft\WindowsUpdate\UX\Settings" -Name "UxOption" -Value 1

$services = @(
    "diagnosticshub.standardcollector.service"# Microsoft (R) Diagnostics Hub Standard Collector Service
    "DiagTrack"                               # Diagnostics Tracking Service
    #"dmwappushservice"                       # WAP Push Message Routing Service (see known issues)
    "lfsvc"                                   # Geolocation Service
    "MapsBroker"                              # Downloaded Maps Manager
    "NetTcpPortSharing"                       # Net.Tcp Port Sharing Service
    #"RemoteAccess"                           # Routing and Remote Access
    #"RemoteRegistry"                         # Remote Registry
    #"SharedAccess"                           # Internet Connection Sharing (ICS)
    "TrkWks"                                  # Distributed Link Tracking Client
    #"WbioSrvc"                               # Windows Biometric Service (required for Fingerprint reader / facial detection)
    #"WlanSvc"                                # WLAN AutoConfig
    "WMPNetworkSvc"                           # Windows Media Player Network Sharing Service
    #"wscsvc"                                 # Windows Security Center Service
    #"WSearch"                                # Windows Search
    #"XblAuthManager"                         # Xbox Live Auth Manager
    #"XblGameSave"                            # Xbox Live Game Save Service
    #"XboxNetApiSvc"                          # Xbox Live Networking Service
    #"ndu"                                    # Windows Network Data Usage Monitor
    ###########################################
    #"WdNisSvc"                               # Service which cannot be disabled
)

foreach ($service in $services)
{
    Write-Host "Trying to disable $service"
    Get-Service -Name $service -EA SilentlyContinue | Set-Service -StartupType Disabled -EA SilentlyContinue
}

##########
# UITweaks
##########

if ($layoutSaved -eq $true)
{
    Write-Host "Changing default Taskbar Layout path to xml..."
    Conditional-New-FolderForced $HKLMSwitch -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
    Conditional-Set-ItemProperty $HKLMSwitch -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "LayoutXMLPath" -Value $layoutFile

    Write-Host "Changing default Start Layout path to xml..."
    Conditional-New-FolderForced $HKLMSwitch -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
    Conditional-Set-ItemProperty $HKLMSwitch -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "LockedStartLayout" -Value 0
    Conditional-Set-ItemProperty $HKLMSwitch -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "StartLayoutFile" -Value $layoutFile

    Write-Host "Importing Start-Taskbar ModificationLayout..."
    if ($HKLMSwitch -eq $true) { Import-startlayout -LayoutPath $layoutFile -MountPath "$ENV:SystemDrive\" }

    ## Test of Modification...
    if ($HKLMSwitch -eq $true) { Export-StartLayout -UseDesktopApplicationID –path $ENV:LOCALAPPDATA\LayoutModification.xml }
}

Write-Host "Removing Edge lnk..."
Conditional-Set-ItemProperty $HKLMSwitch -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "DisableEdgeDesktopShortcutCreation" -Value 1 -Force
Conditional-Remove-Item $HKLMSwitch -Path "$ENV:USERPROFILE\Desktop\Microsoft Edge.lnk" -Force -EA SilentlyContinue

Write-Host "Disabling Sticky keys prompt..."
Conditional-Set-ItemProperty $HKDUSwitch -Path "HKDU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Value "506"
Conditional-Set-ItemProperty $HKCUSwitch -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Value "506"

Write-Host "Hiding Search Box/Button..."
Conditional-New-FolderForced $HKDUSwitch -Path "HKDU:\Software\Microsoft\Windows\CurrentVersion\Search"
Conditional-Set-ItemProperty $HKDUSwitch -Path "HKDU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 0
Conditional-New-FolderForced $HKCUSwitch -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search"
Conditional-Set-ItemProperty $HKCUSwitch -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 0

Write-Host "I like it small in taskbar..."
Conditional-New-FolderForced $HKDUSwitch -Path "HKDU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" 
Conditional-Set-ItemProperty $HKDUSwitch -Path "HKDU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -Value 1
Conditional-New-FolderForced $HKCUSwitch -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
Conditional-Set-ItemProperty $HKCUSwitch -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -Value 1

Write-Host "Have to hide The Ring..."
Conditional-Set-ItemProperty $HKDUSwitch -Path "HKDU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCortanaButton" -Value 0
Conditional-Set-ItemProperty $HKCUSwitch -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCortanaButton" -Value 0

Write-Host "I can't read anyway..."
Conditional-Remove-ItemProperty $HKDUSwitch -Path "HKDU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -EA SilentlyContinue
Conditional-Remove-ItemProperty $HKCUSwitch -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -EA SilentlyContinue

Write-Host "Yeey pictures, i mean icons! See?..."
Conditional-Set-ItemProperty $HKDUSwitch -Path "HKDU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Value 0
Conditional-Set-ItemProperty $HKCUSwitch -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Value 0

Write-Host "Disable People icon...hmmm, Disable People..."
Conditional-New-FolderForced $HKDUSwitch -Path "HKDU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People"
Conditional-Set-ItemProperty $HKDUSwitch -Path "HKDU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Value 0 -Force
Conditional-New-FolderForced $HKCUSwitch -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People"
Conditional-Set-ItemProperty $HKCUSwitch -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Value 0 -Force

Write-Host "Yes, show me what that mouth do..."
Conditional-Set-ItemProperty $HKDUSwitch -Path "HKDU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0
Conditional-Set-ItemProperty $HKCUSwitch -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0

Write-Host "U can run, but u can't hide..."
Conditional-Set-ItemProperty $HKDUSwitch -Path "HKDU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Value 1
Conditional-Set-ItemProperty $HKCUSwitch -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Value 1

Write-Host "What if..."
Conditional-Set-ItemProperty $HKDUSwitch -Path "HKDU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "EncryptionContextMenu" -Value 1
Conditional-Set-ItemProperty $HKCUSwitch -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "EncryptionContextMenu" -Value 1

Write-Host "Hallowed are the Ori,..."
Conditional-Remove-ItemProperty $HKDUSwitch -Path "HKDU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -EA SilentlyContinue
Conditional-Set-ItemProperty $HKDUSwitch -Path "HKDU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Value 1
Conditional-Remove-ItemProperty $HKCUSwitch -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -EA SilentlyContinue
Conditional-Set-ItemProperty $HKCUSwitch -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Value 1

Conditional-New-FolderForced $HKDUSwitch -Path "HKDU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons"
Conditional-New-FolderForced $HKDUSwitch -Path "HKDU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu"
Conditional-New-FolderForced $HKDUSwitch -Path "HKDU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"
Conditional-New-FolderForced $HKCUSwitch -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons"
Conditional-New-FolderForced $HKCUSwitch -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu"
Conditional-New-FolderForced $HKCUSwitch -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"

Write-Host "Get that trash out of my sight..."
Conditional-Set-ItemProperty $HKDUSwitch -Path "HKDU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{645FF040-5081-101B-9F08-00AA002F954E}" -Value 1
Conditional-Set-ItemProperty $HKDUSwitch -Path "HKDU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{645FF040-5081-101B-9F08-00AA002F954E}" -Value 1
Conditional-Set-ItemProperty $HKCUSwitch -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{645FF040-5081-101B-9F08-00AA002F954E}" -Value 1
Conditional-Set-ItemProperty $HKCUSwitch -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{645FF040-5081-101B-9F08-00AA002F954E}" -Value 1

Write-Host "...Put it between User Files..."
Conditional-New-FolderForced $HKLMSwitch -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\UsersFiles\NameSpace\{645FF040-5081-101B-9F08-00AA002F954E}"

Write-Host "Disable icons on Desktop... Alles in Ordnung! Vo vsetkom!"
Conditional-Set-ItemProperty $HKDUSwitch -Path "HKDU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideIcons" -Value 1
Conditional-Set-ItemProperty $HKCUSwitch -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideIcons" -Value 1

Write-Host "Single TaskBar, 4ever alone..."
Conditional-Set-ItemProperty $HKDUSwitch -Path "HKDU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "MMTaskbarEnabled" -Value 0 -Force
Conditional-Set-ItemProperty $HKCUSwitch -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "MMTaskbarEnabled" -Value 0 -Force

Write-Host "Always in hurry, soooo..."
Conditional-Set-ItemProperty $HKLMSwitch -Path "HKCR:\.txt\ShellNew" -Name "NullFile" -Value 1

Write-Host "Drag&Drop >> Shortcut as default (U know why)..."
Conditional-Set-ItemProperty $HKLMSwitch -LiteralPath "HKCR:\*" -Name "DefaultDropEffect" -Value 4
Conditional-Set-ItemProperty $HKLMSwitch -Path "HKCR:\AllFilesystemObjects" -Name "DefaultDropEffect" -Value 4

Write-Host "Stranger Things back&forth to..."
Conditional-New-FolderForced $HKLMSwitch -Path "HKCR:\AllFilesystemObjects\shellex\ContextMenuHandlers\Copy to"
Conditional-Set-ItemProperty $HKLMSwitch -Path "HKCR:\AllFilesystemObjects\shellex\ContextMenuHandlers\Copy to" -Name "(default)" -Value "{C2FBB631-2971-11D1-A18C-00C04FD75D13}"
Conditional-New-FolderForced $HKLMSwitch -Path "HKCR:\AllFilesystemObjects\shellex\ContextMenuHandlers\Move to"
Conditional-Set-ItemProperty $HKLMSwitch -Path "HKCR:\AllFilesystemObjects\shellex\ContextMenuHandlers\Move to" -Name "(default)" -Value "{C2FBB631-2971-11D1-A18C-00C04FD75D13}"

##########
# Settings
##########
# -- Craft

Write-Host "Disable automatic download and installation of Windows Updates"
Conditional-New-FolderForced $HKLMSwitch -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU"
Conditional-Set-ItemProperty $HKLMSwitch -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 0
Conditional-Set-ItemProperty $HKLMSwitch -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Value 2
Conditional-Set-ItemProperty $HKLMSwitch -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallDay" -Value 0
Conditional-Set-ItemProperty $HKLMSwitch -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallTime" -Value 3

Write-Host "Disable seeding of updates to other computers via Group Policies"
Conditional-New-FolderForced $HKLMSwitch -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
Conditional-Set-ItemProperty $HKLMSwitch -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -Value 0

$objSID = New-Object System.Security.Principal.SecurityIdentifier "S-1-1-0"
$everyone = $objSID.Translate([System.Security.Principal.NTAccount]).Value

Write-Host "Disable 'Updates are available' message"
Takeown /F "$ENV:WinDIR\System32\MusNotification.exe"
ICACLS "$ENV:WinDIR\System32\MusNotification.exe" /Deny "$($everyone):(X)"
Takeown /F "$ENV:WinDIR\System32\MusNotificationUx.exe"
ICACLS "$ENV:WinDIR\System32\MusNotificationUx.exe" /Deny "$($everyone):(X)"

$cdm = @(
    "ContentDeliveryAllowed"
    "FeatureManagementEnabled"
    "OemPreInstalledAppsEnabled"
    "PreInstalledAppsEnabled"
    "PreInstalledAppsEverEnabled"
    "SilentInstalledAppsEnabled"
    "SubscribedContent-314559Enabled"
    "SubscribedContent-338387Enabled"
    "SubscribedContent-338388Enabled"
    "SubscribedContent-338389Enabled"
    "SubscribedContent-338393Enabled"
    "SubscribedContentEnabled"
    "SystemPaneSuggestionsEnabled"
)

Write-Host "Disabling Content Delivery..."
Conditional-New-FolderForced $HKDUSwitch -Path "HKDU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
Conditional-New-FolderForced $HKCUSwitch -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
foreach ($key in $cdm)
{
    Conditional-Set-ItemProperty $HKDUSwitch -Path "HKDU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name $key -Value 0 -Force
    Conditional-Set-ItemProperty $HKCUSwitch -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name $key -Value 0 -Force
}

Conditional-Remove-Item $HKDUSwitch -Path "HKDU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Recurse -Force -EA SilentlyContinue
Conditional-Remove-Item $HKCUSwitch -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Recurse -Force -EA SilentlyContinue

Write-Host "Disabling Windows Store auto download..."
Conditional-New-FolderForced $HKLMSwitch -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
Conditional-Set-ItemProperty $HKLMSwitch -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "AutoDownload" -Value 2 -Force

Write-Host "Disabling Windows Consumer Features..."
Conditional-New-FolderForced $HKLMSwitch -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
Conditional-Set-ItemProperty $HKLMSwitch -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1 -Force

Write-Host "Removing Password date of expire..."
if ($HKLMSwitch) { NET Accounts /MAXPWAGE:0 }

If ($HKLMSwitch -AND (Get-Service -Name InstallService | Where-Object {$_.StartType -eq "Disabled"}))
{
    Write-Host "Enabling install service"
    Set-Service -Name InstallService -StartupType Automatic
}

if ($HKLMSwitch -AND (Get-Service -Name InstallService | Where-Object { $_.Status -eq "Stopped" }))
{
    Write-Host "Run install service..."
    Start-Service -Name InstallService
}

Write-Host "Eth tweaks (NoDelay...) - B.Walden - see more info on equk.co.uk"
foreach ($eths in (reg query "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards" /F "ServiceName" /S | FINDSTR /I /L "ServiceName"))
{
    $p = $eths.IndexOf("{")
    $v = $eths.Substring($p, $eths.Length - $p)

    Conditional-Set-ItemProperty $HKLMSwitch -Path "HKLM:\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\$v" -Name "TcpAckFrequency" -Value 1 -Force
    Conditional-Set-ItemProperty $HKLMSwitch -Path "HKLM:\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\$v" -Name "TCPNoDelay" -Value 1 -Force
}

Write-Host "Disabling All System Sounds..."
Disable-System-Sounds

Write-Host "Disabling MAC Randomizer (I just need a wey how to work with v6 riiiiiight?)..."
Set-NetIPv6Protocol -RandomizeIdentifiers Disabled

Write-Host "Add Czeq-QWERTY..."
Add-CZEQWERTY-Keyboard

##########
# WUpdates
##########
# B.Walden

Write-Host "Removing Dubious Windows Updates - B.Walden - see more info on equk.co.uk"
WUSA /Uninstall /KB:3021917 /Quiet /NoRestart
WUSA /Uninstall /KB:3050265 /Quiet /NoRestart
WUSA /Uninstall /KB:3035583 /Quiet /NoRestart
WUSA /Uninstall /KB:2952664 /Quiet /NoRestart
WUSA /Uninstall /KB:2976978 /Quiet /NoRestart
WUSA /Uninstall /KB:2990214 /Quiet /NoRestart
WUSA /Uninstall /KB:3068708 /Quiet /NoRestart
WUSA /Uninstall /KB:3022345 /Quiet /NoRestart
WUSA /Uninstall /KB:2952664 /Quiet /NoRestart
WUSA /Uninstall /KB:3075851 /Quiet /NoRestart
WUSA /Uninstall /KB:3045999 /Quiet /NoRestart
WUSA /Uninstall /KB:2919355 /Quiet /NoRestart
WUSA /Uninstall /KB:3065987 /Quiet /NoRestart
WUSA /Uninstall /KB:3075851 /Quiet /NoRestart
WUSA /Uninstall /KB:2977759 /Quiet /NoRestart
WUSA /Uninstall /KB:3075249 /Quiet /NoRestart
WUSA /Uninstall /KB:3080149 /Quiet /NoRestart

##########
# --- OOBE
##########
# -- Craft

Write-Host "OOBE ala disable all..."
Conditional-Remove-ItemProperty $HKLMSwitch -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OOBE" -Name "DisablePrivacyExperience" -EA SilentlyContinue -Force
Conditional-New-FolderForced    $HKLMSwitch -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OOBE"
Conditional-Set-ItemProperty    $HKLMSwitch -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OOBE" -Name "DisablePrivacyExperience" -Value 1 -Force
Conditional-Remove-ItemProperty $HKDUSwitch -Path "HKDU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Name "HasAccepted" -EA SilentlyContinue -Force
Conditional-New-FolderForced    $HKDUSwitch -Path "HKDU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy"
Conditional-Set-ItemProperty    $HKDUSwitch -Path "HKDU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Name "HasAccepted" -Value 0 -Force
Conditional-Remove-ItemProperty $HKCUSwitch -Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings" -Name "HasAccepted" -EA SilentlyContinue -Force
Conditional-New-FolderForced    $HKCUSwitch -Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings"
Conditional-Set-ItemProperty    $HKCUSwitch -Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\" -Name "HasAccepted" -Value 0 -Force
Conditional-Remove-ItemProperty $HKDUSwitch -Path "HKDU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -EA SilentlyContinue -Force
Conditional-New-FolderForced    $HKDUSwitch -Path "HKDU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"
Conditional-Set-ItemProperty    $HKDUSwitch -Path "HKDU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Value "Deny" -Force
Conditional-Remove-ItemProperty $HKCUSwitch -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -EA SilentlyContinue -Force
Conditional-New-FolderForced    $HKCUSwitch -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore"
Conditional-Set-ItemProperty    $HKCUSwitch -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Value "Deny" -Force
Conditional-Remove-ItemProperty $HKLMSwitch -Path "HKLM:\SOFTWARE\Microsoft\Settings\FindMyDevice" -Name "LocationSyncEnabled" -EA SilentlyContinue -Force
Conditional-New-FolderForced    $HKLMSwitch -Path "HKLM:\SOFTWARE\Microsoft\Settings\FindMyDevice"
Conditional-Set-ItemProperty    $HKLMSwitch -Path "HKLM:\SOFTWARE\Microsoft\Settings\FindMyDevice" -Name "LocationSyncEnabled" -Value 0 -Force
Conditional-Remove-ItemProperty $HKDUSwitch -Path "HKDU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" -Name "ShowedToastAtLevel" -EA SilentlyContinue -Force
Conditional-New-FolderForced    $HKDUSwitch -Path "HKDU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack"
Conditional-Set-ItemProperty    $HKDUSwitch -Path "HKDU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" -Name "ShowedToastAtLevel" -Value 1 -Force
Conditional-Remove-ItemProperty $HKCUSwitch -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" -Name "ShowedToastAtLevel" -EA SilentlyContinue -Force
Conditional-New-FolderForced    $HKCUSwitch -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack"
Conditional-Set-ItemProperty    $HKCUSwitch -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" -Name "ShowedToastAtLevel" -Value 1 -Force
Conditional-Remove-ItemProperty $HKLMSwitch -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -EA SilentlyContinue -Force
Conditional-New-FolderForced    $HKLMSwitch -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
Conditional-Set-ItemProperty    $HKLMSwitch -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 1 -Force
Conditional-Remove-ItemProperty $HKLMSwitch -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "MaxTelemetryAllowed" -EA SilentlyContinue -Force
Conditional-Set-ItemProperty    $HKLMSwitch -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "MaxTelemetryAllowed" -Value 1 -Force
Conditional-Remove-ItemProperty $HKDUSwitch -Path "HKDU:\Software\Microsoft\Input\TIPC" -Name "Enabled" -EA SilentlyContinue -Force
Conditional-New-FolderForced    $HKDUSwitch -Path "HKDU:\Software\Microsoft\Input\TIPC"
Conditional-Set-ItemProperty    $HKDUSwitch -Path "HKDU:\Software\Microsoft\Input\TIPC" -Name "Enabled" -Value 0 -Force
Conditional-Remove-ItemProperty $HKCUSwitch -Path "HKCU:\Software\Microsoft\Input\TIPC" -Name "Enabled" -EA SilentlyContinue -Force
Conditional-New-FolderForced    $HKCUSwitch -Path "HKCU:\Software\Microsoft\Input\TIPC"
Conditional-Set-ItemProperty    $HKCUSwitch -Path "HKCU:\Software\Microsoft\Input\TIPC" -Name "Enabled" -Value 0 -Force
Conditional-Remove-ItemProperty $HKDUSwitch -Path "HKDU:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -EA SilentlyContinue -Force
Conditional-New-FolderForced    $HKDUSwitch -Path "HKDU:\Software\Microsoft\Windows\CurrentVersion\Privacy"
Conditional-Set-ItemProperty    $HKDUSwitch -Path "HKDU:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Value 0 -Force
Conditional-Remove-ItemProperty $HKCUSwitch -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -EA SilentlyContinue -Force
Conditional-New-FolderForced    $HKCUSwitch -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy"
Conditional-Set-ItemProperty    $HKCUSwitch -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Value 0 -Force
Conditional-Remove-ItemProperty $HKDUSwitch -Path "HKDU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -EA SilentlyContinue -Force
Conditional-New-FolderForced    $HKDUSwitch -Path "HKDU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
Conditional-Set-ItemProperty    $HKDUSwitch -Path "HKDU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0 -Force
Conditional-Remove-ItemProperty $HKCUSwitch -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -EA SilentlyContinue -Force
Conditional-New-FolderForced    $HKCUSwitch -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
Conditional-Set-ItemProperty    $HKCUSwitch -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0 -Force

if ((PowerCfg /L | ? { $_ -like "*Ultimate*" } -eq $null) -AND ($HKCUSwitch -eq $true))
{
    Write-Host "Enabling NotAPowerSaFing..."
    Conditional-Remove-Item $HKCUSwitch -Path C:\OutdoorScheme.pow -EA SilentlyContinue -Force
    PowerCfg -DuplicateScheme e9a42b02-d5df-448d-aa00-03f14749eb61
    PowerCfg -EXPORT C:\OutdoorScheme.pow { guidScheme-New }
    PowerCfg -IMPORT C:\OutdoorScheme.pow
    PowerCfg -SETACTIVE { guidScheme-New }
    Conditional-Remove-Item $HKCUSwitch -Path C:\OutdoorScheme.pow -EA SilentlyContinue -Force
}

Write-Host "Restarting explorer... clearing CloudStore..."
Get-Process -Name "explorer" -EA SilentlyContinue | Stop-Process -EA SilentlyContinue -Force
Conditional-Remove-Item $HKCUSwitch "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\*" -Recurse -Force -EA SilentlyContinue
Conditional-Remove-Item $HKCUSwitch "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store\DefaultAccount\Cloud\*" -Recurse -Force -EA SilentlyContinue
Conditional-Remove-Item $HKCUSwitch "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount" -Recurse -Force -EA SilentlyContinue
Conditional-Remove-Item $HKCUSwitch "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store\DefaultAccount\Cloud" -Recurse -Force -EA SilentlyContinue
Conditional-Remove-Item $HKCUSwitch "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache" -Recurse -Force -EA SilentlyContinue
Conditional-Remove-Item $HKCUSwitch "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store\DefaultAccount" -Recurse -Force -EA SilentlyContinue
Get-Process -Name "explorer" -EA SilentlyContinue | Stop-Process -EA SilentlyContinue -Force
Conditional-Remove-Item $HKCUSwitch "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store" -Recurse -Force -EA SilentlyContinue
$wshell = New-Object -ComObject wscript.shell; $wshell.SendKeys('^{ESCAPE}')

New-PSDrive-RegistryUnloadHive HKDU -EA SilentlyContinue
Remove-PSDrive HKU -EA SilentlyContinue
Remove-PSDrive HKCR -EA SilentlyContinue

Wait 5

if ((Get-Process -Name "explorer" -EA Stop | Out-Null) -eq $null)
{
    if ($Restart -eq $true) { Restart }
}

Wait 5

Start-Process -FilePath "explorer.exe" -EA SilentlyContinue
