[CmdletBinding(SupportsShouldProcess=$true)]
param
(
    [Parameter(Position = 0, Mandatory)]
    [String]$Path
)

########################################################
###############ranWare All-Mighty Tools#################
########################################################

Write-Host "Environment setup..."
Set-Location $Path

## For Import
Set-ExecutionPolicy Unrestricted -Scope Process -Force -Confirm:$false

. $Path\include.ps1
. $Path\Data\secret.ps1 #pssssst!

## Revert Executio Policy Changes
Set-ExecutionPolicy Default -Scope Process -Force -Confirm:$false

## Add registry key for easier access of default profile
New-PSDrive -PSProvider Registry -Name HKCR -Root HKEY_CLASSES_ROOT

########################################################
########################################################
########################################################

## Maximize, DUNNO hh
Set-WindowStyle MAXIMIZE

##########
# UITweaks
##########

#Write-Host "Changing Theme to Dark mode..."
#Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0 -Force

$layoutFile = "$Path\Data\LayoutModification.xml"

Write-Host "Changing default Taskbar Layout path to xml..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "LayoutXMLPath" -Value $layoutFile

Write-Host "Changing default Start Layout path to xml..."
New-FolderForced -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "LockedStartLayout" -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "StartLayoutFile" -Value $layoutFile

Write-Output "Importing Start-Taskbar ModificationLayout..."
Import-startlayout -LayoutPath $layoutFile -MountPath "$ENV:SystemDrive\"

Write-Host "Removing Edge lnk..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "DisableEdgeDesktopShortcutCreation" -Value 1 -Force
Remove-Item -Path ($ENV:USERPROFILE + "\Desktop\Microsoft Edge.lnk") -EA SilentlyContinue -Force

Write-Host "Disabling Sticky keys prompt..."
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Value "506"

Write-Host "Hiding Search Box/Button..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 0

Write-Host "Use small icons in taskbar..."
New-FolderForced -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -Value 1

Write-Host "Hiding titles in taskbar..."
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -EA SilentlyContinue

Write-Host "Showing all tray icons..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Value 0

Write-Host "Showing known file extensions..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0

Write-Host "Showing hidden files..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Value 1

Write-Host "Changing default Explorer view to This Computer..."
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -EA SilentlyContinue
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Value 1

New-FolderForced -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons"
New-FolderForced -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu"
New-FolderForced -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"

Write-Host "Hide Recycle Bin from Desktop..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{645FF040-5081-101B-9F08-00AA002F954E}" -Value 1
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{645FF040-5081-101B-9F08-00AA002F954E}" -Value 1

Write-Host "...Put it between User Files..."
New-FolderForced -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\UsersFiles\NameSpace\{645FF040-5081-101B-9F08-00AA002F954E}"

Write-Host "Disable icons on Desktop... Alles in Ordnung! Vo vsetkom!"
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideIcons" -Value 1

Write-Host "New Text Document direct name editing..."
Set-ItemProperty -Path "HKCR:\.txt\ShellNew" -Name "NullFile" -Value 1

#Write-Host "Drag&Drop >> Shortcut as default (U know why)..."
#Set-ItemProperty -Path "HKCR:\*" -Name "DefaultDropEffect" -Value 4
#Set-ItemProperty -Path "HKCR:\AllFilesystemObjects" -Name "DefaultDropEffect" -Value 4

Disable-System-Sounds

##########
# Settings
##########

Write-Host "Prep RD..."
if (-not (Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Terminal Server Client\Default")) { New-Item "HKCU:\SOFTWARE\Microsoft\Terminal Server Client\Default" -Force -EA SilentlyContinue }
New-ItemProperty    -Path "HKCU:\SOFTWARE\Microsoft\Terminal Server Client\Default" -Name "MRU0" -Value "$ip"
if (-not (Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Terminal Server Client\Servers")) { New-Item "HKCU:\SOFTWARE\Microsoft\Terminal Server Client\Servers" -Force -EA SilentlyContinue }
if (-not (Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Terminal Server Client\Servers\$ip")) { New-Item "HKCU:\SOFTWARE\Microsoft\Terminal Server Client\Servers\$ip" -Force -EA SilentlyContinue }
New-ItemProperty    -Path "HKCU:\SOFTWARE\Microsoft\Terminal Server Client\Servers\$ip" -Name "UsernameHint" -Value $login -Force -EA SilentlyContinue
New-ItemProperty    -Path "HKCU:\SOFTWARE\Microsoft\Terminal Server Client\Servers\$ip" -Name "CertHash" -PropertyType Binary -Value $cert -Force -EA SilentlyContinue 
New-ItemProperty    -Path "HKCU:\SOFTWARE\Microsoft\Terminal Server Client\Servers\$ip" -Name "Settings" -PropertyType Binary -Value $sett -Force -EA SilentlyContinue 

Write-Host "OVPN..."
Install-Msi (Get-Path "Setup\ovpn.msi")

Write-Host "Edge..."
Install-Msi (Get-Path "Setup\edge.msi")

$profileFile = Get-Path "Data\profile.ovpn" 
$profile = $profileFile -replace ".ovpn"
$openConfig =  (Get-Path "..\OpenVPN\config\" -Create | Select -Last 1)

Write-Host "Distribution of client OVPN profile..."
if (Test-Path $profileFile)
{
    Copy-Item -Path $profileFile -Destination $openConfig
    Copy-Item -Path $profile -Destination $openConfig
}

Write-Host "Removing CloudStore registry key..."
Remove-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore" -EA SilentlyContinue -Recurse -Force

Write-Output "Restarting Explorer..."
Stop-Process -ProcessName explorer

Wait 1

$wShell = New-Object -ComObject wscript.shell; $wshell.SendKeys("^{ESCAPE}")

Wait 2