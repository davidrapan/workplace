########################################################
################ranWare All-Mighty Tools################
########################################################

$keepool = @(
    "1527c705-839a-4832-9118-54d4Bd6a0c89"
    "c5e2524a-ea46-4f67-841f-6a9465d9d515"
    "E2A4F912-2574-4A75-9BB0-0D023378592B"
    "F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE"
    "windows.immersivecontrolpanel"
    "CanonicalGroupLimited.UbuntuonWindows"
    "Microsoft.Microsoft3DViewer"
    "Microsoft.People"
    "Microsoft.Xbox.TCUI"
    "Microsoft.XboxGameOverlay"
    "Microsoft.XboxIdentityProvider"
    "Microsoft.XboxSpeechToTextOverlay"
    "Microsoft.MixedReality.Portal"
    "Microsoft.XboxApp"
    "Microsoft.XboxGameCallableUI"
    "Microsoft.WindowsCalculator"
    "Microsoft.XboxGamingOverlay"
    "Microsoft.YourPhone"
    "Microsoft.Paint3D"
    "Microsoft.MicrosoftEdge*"
    "Microsoft.WindowsStore"
    "Microsoft.Windows.Photos"
    "Microsoft.MicrosoftStickyNotes"
    "Microsoft.MSPaint"
    "Microsoft.VCLibs*"
    "Microsoft.WindowsCamera"
    "Microsoft.HEIFImageExtension"
    "Microsoft.ScreenSketch"
    "Microsoft.StorePurchaseApp"
    "Microsoft.VP9VideoExtensions"
    "Microsoft.WebMediaExtensions"
    "Microsoft.WebpImageExtension"
    "Microsoft.DesktopAppInstaller"
)

$regexPool = @(
    "*\.NET\.*"
    "*\.UI\.*"
    "*Framework*"
)

########################################################
########################################################
########################################################

## Helper
function KeePool-NotLike($value)
{
    foreach ($item in ($keepool + $regexPool))
    {
        $condition = ($value -ilike $item)

        if ($condition) { return !($condition) }
    }

    return !($condition)
}

## Remove heavy weight packages
function Remove-AppxPackage-CustomSet
{
    $r = 2

    Write-Host "Elevating privileges for this process..."
    do {} until (Elevate-Privileges SeTakeOwnershipPrivilege)

    Write-Host "Removing packages..."
    while($r -ge 0)
    {
        Get-AppxPackage -AllUsers | Where-Object { KeePool-NotLike($_.Name) -eq $true } | Remove-AppxPackage -EA SilentlyContinue

        $r -= 1
    }

    $r = 2

    Write-Host "Removing Provisioned packages..."
    while($r -ge 0)
    {
        foreach ($app in (Get-AppxProvisionedPackage -Online | Where-Object { KeePool-NotLike($_.DisplayName) -eq $true }))
        {
            $package = Get-AppxPackage -Name $app.DisplayName -AllUsers

            if ($package.NonRemovable)
            {
                Write-Host "$app ...is marked as NonRemovable"

                try
                {
                    Set-NonRemovableAppsPolicy -Online -PackageFamilyName $app.PackageFamilyName -NonRemovable 0 -EA SilentlyContinue

                    $package | Remove-AppxPackage -AllUsers -EA SilentlyContinue -Force
                }
                catch
                {
                    "Could not prepare $($app.DisplayName)"
                }
            }

            try
            {
                Remove-AppxProvisionedPackage -Online -PackageName $app.PackageName -AllUsers -EA SilentlyContinue
            }
            catch
            {
                "Could not remove $($app.DisplayName)"
            }
        }

        $r -= 1
    }

    Remove-Item -Path "$ENV:USERPROFILE\Appdata\Local\IconCache.db" -EA SilentlyContinue -Force
}

## Clear Rrgistry from BackgroundTasks and Packages, from: https://github.com/Sycnex/Windows10Debloater/blob/master/Windows10SysPrepDebloater.ps1
function Clear-Registry
{
    $keys = @(
        #Remove Background Tasks
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
        #"HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
        #"HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
        
        #Windows File
        "HKCR:\Extensions\ContractId\Windows.File\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        
        #Registry keys to delete if they aren't uninstalled by RemoveAppXPackage/RemoveAppXProvisionedPackage
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
        #"HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
        #"HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
        
        #Scheduled Tasks to delete
        "HKCR:\Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
        
        #Windows Protocol Keys
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
        #"HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
        #"HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
           
        #Windows Share Target
        "HKCR:\Extensions\ContractId\Windows.ShareTarget\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
    )
    
    foreach ($key in $keys)
    {
        Write-Host "Removing $key from registry"
        Remove-Item $key -Recurse -EA SilentlyContinue -Force
    }
}

## Fix actually sometime used packages, stolen from: This includes fixes by xsisbest, https://github.com/Sycnex/Windows10Debloater/blob/master/Windows10SysPrepDebloater.ps1 #Credit to abulgatz for the 4 lines of code
function Appx-Fix
{
    foreach ($item in $keepool) { Get-AppxPackage -AllUsers $item -EA SilentlyContinue | foreach { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" -EA SilentlyContinue } }
}

## Helpers 1
function Get-Path
{
    param
    (
        [Parameter(Position = 0, Mandatory)]
        [String]$Path,
        [Switch]$Create
    )

    if (-not (Test-Path $Path)) { if ($Create -eq $true) { New-FolderForced $Path } }

    (Get-Item $Path | Resolve-Path).ProviderPath
}

## Helpers 2
function Get-Dir([Parameter(Position = 0, Mandatory)]$Path)
{
    Split-Path (Get-Path $Path)
}

## Helpers 3
function Get-Leaf([Parameter(Position = 0, Mandatory)]$Path)
{
    Split-Path (Get-Path $Path) -Leaf
}

## Conditionals 1
function Conditional-Set-ItemProperty
{
    [CmdletBinding(SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Position = 0, Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [bool]$Condition,
        [Parameter(Position = 1, Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$Path,
        [string]$Name,$Value,
        [Switch]$Recurse,
        [Switch]$Force
    )

    $result = $Condition

    $PSBoundParameters.Remove("Condition")

    if ($PSBoundParameters["Verbose"] -eq $true) { $PSBoundParameters }

    if ($Condition -eq $true) { $result = Set-ItemProperty @PSBoundParameters }

    if ($PSBoundParameters["Verbose"] -eq $true) { $result }
}

## Conditionals 2
function Conditional-New-FolderForced
{
    [CmdletBinding(SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Position = 0, Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [bool]$Condition,
        [Parameter(Position = 1, Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$Path,
        [string]$Name,
        [Switch]$Recurse,
        [Switch]$Force
    )

    $result = $Condition

    $PSBoundParameters.Remove("Condition")

    if ($PSBoundParameters["Verbose"] -eq $true) { $PSBoundParameters }

    if ($Condition -eq $true) { $result = New-FolderForced @PSBoundParameters }

    if ($PSBoundParameters["Verbose"] -eq $true) { $result }
}

## Conditionals 3
function Conditional-Remove-ItemProperty
{
    [CmdletBinding(SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Position = 0, Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [bool]$Condition,
        [Parameter(Position = 1, Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$Path,
        [string]$Name,
        [Switch]$Recurse,
        [Switch]$Force
    )

    $result = $Condition

    $PSBoundParameters.Remove("Condition")

    if ($PSBoundParameters["Verbose"] -eq $true) { $PSBoundParameters }

    if ($Condition -eq $true) { $result = Remove-ItemProperty @PSBoundParameters }

    if ($PSBoundParameters["Verbose"] -eq $true) { $result }
}

## Conditionals 4
function Conditional-Remove-Item
{
    [CmdletBinding(SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Position = 0, Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [bool]$Condition,
        [Parameter(Position = 1, Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$Path,
        [string]$Name,
        [Switch]$Recurse,
        [Switch]$Force
    )

    $result = $Condition

    $PSBoundParameters.Remove("Condition")

    if ($PSBoundParameters["Verbose"] -eq $true) { $PSBoundParameters }

    if ($Condition -eq $true) { $result = Remove-Item @PSBoundParameters }

    if ($PSBoundParameters["Verbose"] -eq $true) { $result }
}

## Wrapping of REG & New-PSDrive for Hive loading
function New-PSDrive-RegistryLoadHive
{
    [CmdletBinding(SupportsShouldProcess=$true)]
    Param
    (
        [Parameter(Position = 0, Mandatory)][ValidatePattern("^[^;~/\\\.\:]+$")]
        [String]$Name,
        [Parameter(Position = 1, Mandatory)][ValidatePattern("^(([A-Z_]*)\\)[a-zA-Z0-9- _\\]+$")]
        [String]$Root,
        [Parameter(Position = 2, Mandatory)]
        [String]$Path
    )

    # check whether the drive name is available
    $r1 = Get-PSDrive -Name $Name -EA SilentlyContinue

    if ($r1 -ne $null) { throw [Management.Automation.SessionStateException] "Drive '$Name' already exists." }

    $r2 = REG Load $Root $Path

    if ($r2 -eq $null) { throw [Management.Automation.PSInvalidOperationException] "Could not load $Root as $Path." }

    if ($PSBoundParameters["Verbose"] -eq $true) { $r2 }

    try
    {
        $r3 = New-PSDrive -PSProvider Registry -Name HKDU -Root HKEY_USERS\Default -Scope Script -EA Stop | Out-Null

        if ($r3 -ne $null) { throw [Management.Automation.PSInvalidOperationException] "Register of new drive caused unexpected error: $r3" }
    }
    catch
    {
        throw [Management.Automation.PSInvalidOperationException] "Loading of new drive $Name from $Root as $Path failed. Hive is still loaded, attended intervention required."
    }
}

## Wrapping of REG & New-PSDrive for Hive unloading
function New-PSDrive-RegistryUnloadHive
{
    [CmdletBinding(SupportsShouldProcess=$true)]
    Param
    (
        [Parameter(Position = 0, Mandatory)][ValidatePattern('^[^;~/\\\.\:]+$')]
        [String]$Name
    )

    $Root = (Get-PSDrive -Name $Name -EA Stop).Root

    if ($PSBoundParameters["Verbose"] -eq $true) { $Root }

    $r1 = Remove-PSDrive $Name -EA Stop

    if ($r1 -ne $null) { throw [Management.Automation.PSInvalidOperationException] "Could not remove $Name, drive is busy." }

    $r2 = REG Unload $Root

    if ($r2 -eq $null)
    {
        New-PSDrive -PSProvider Registry -Name HKDU -Root HKEY_USERS\Default -Scope Script -EA Stop | Out-Null

        throw [Management.Automation.PSInvalidOperationException] "Could not unload $Root as $Path. Reverted changes made by this function."
    }

    if ($PSBoundParameters["Verbose"] -eq $true) { $r2 }
}

## Just small proof of concept of one thought
function EditContextMenu
{
    $keys = @(
        "HKEY_CLASSES_ROOT\SystemFileAssociations\.fbx\Shell\3D Edit"
        "HKEY_CLASSES_ROOT\SystemFileAssociations\.gif\Shell\3D Edit"
        "HKEY_CLASSES_ROOT\SystemFileAssociations\.jfif\Shell\3D Edit"
        "HKEY_CLASSES_ROOT\SystemFileAssociations\.jpe\Shell\3D Edit"
        "HKEY_CLASSES_ROOT\SystemFileAssociations\.jpeg\Shell\3D Edit"
        "HKEY_CLASSES_ROOT\SystemFileAssociations\.jpg\Shell\3D Edit"
        "HKEY_CLASSES_ROOT\SystemFileAssociations\.png\Shell\3D Edit"
        "HKEY_CLASSES_ROOT\SystemFileAssociations\.tif\Shell\3D Edit"
        "HKEY_CLASSES_ROOT\SystemFileAssociations\.tiff\Shell\3D Edit"
    )

    foreach($key in $keys)
    {
        #TODO
    }
}

## Wait given amount of seconds
function Wait([Parameter(Position = 0, Mandatory)]$Delay = 1)
{
    if ($Delay -le 1)
    {
        start-sleep 1
        $Delay -= 1
        return
    }

    while ($Delay -ge 0)
    {
        Write-Progress -Activity "Closing in..." -SecondsRemaining $Delay;
        start-sleep 1
        $Delay -= 1
    }
}

## Restart
function Restart
{
    #Write-Host
    #Write-Host "Press any key to restart your system..." -ForegroundColor Black -BackgroundColor White
    #$key = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    Write-Host "Restarting..."
    Restart-Computer
}

########## ID:1
## Count: 6
## _
## Functions Debloat-Windows-10/lib/New-FolderForced.psm1 & Debloat-Windows-10/lib/take-own.psm1 from @Zoran-Jankov Zoran-Jankov - https://github.com/Zoran-Jankov
<#
  .SYNOPSIS
  If the target registry key is already present, all values within that key are purged.
  .DESCRIPTION
  While `mkdir -force` works fine when dealing with regular folders, it behaves strange when using it at registry level.
  If the target registry key is already present, all values within that key are purged.
  .PARAMETER Path
  Full path of the storage or registry folder
  .EXAMPLE
  New-FolderForced -Path "HKCU:\Printers\Defaults"
  .EXAMPLE
  New-FolderForced "HKCU:\Printers\Defaults"
  .EXAMPLE
  "HKCU:\Printers\Defaults" | New-FolderForced
  .NOTES
  Replacement for `force-mkdir` to uphold PowerShell conventions.
  Thanks to raydric, this function should be used instead of `mkdir -force`.
#>
function New-FolderForced
{
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
		[Parameter(Position = 0, Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
		[string]$Path
    )

    process {
        if (-not (Test-Path $Path))
        {
            Write-Verbose "-- Creating full path to: $Path"
            New-Item -Path $Path -ItemType Directory -Force
        }
    }
}

function Takeown-Registry($Key)
{
    # TODO does not work for all root keys yet
    switch ($Key.split('\')[0])
    {
        "HKEY_CLASSES_ROOT"
        {
            $reg = [Microsoft.Win32.Registry]::ClassesRoot
            $Key = $Key.substring(18)
        }
        "HKEY_CURRENT_USER"
        {
            $reg = [Microsoft.Win32.Registry]::CurrentUser
            $Key = $Key.substring(18)
        }
        "HKEY_LOCAL_MACHINE"
        {
            $reg = [Microsoft.Win32.Registry]::LocalMachine
            $Key = $Key.substring(19)
        }
    }

    # get administrator group
    $admins = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
    $admins = $admins.Translate([System.Security.Principal.NTAccount])

    # set owner
    $Key = $reg.OpenSubKey($Key, "ReadWriteSubTree", "TakeOwnership")
    $acl = $key.GetAccessControl()
    $acl.SetOwner($admins)
    $Key.SetAccessControl($acl)

    # set FullControl
    $acl = $key.GetAccessControl()
    $rule = New-Object System.Security.AccessControl.RegistryAccessRule($admins, "FullControl", "Allow")
    $acl.SetAccessRule($rule)
    $Key.SetAccessControl($acl)
}

function Takeown-File($Path)
{
    takeown.exe /A /F $Path
    $acl = Get-Acl $Path

    # get administraor group
    $admins = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
    $admins = $admins.Translate([System.Security.Principal.NTAccount])

    # add NT Authority\SYSTEM
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($admins, "FullControl", "None", "None", "Allow")
    $acl.AddAccessRule($rule)

    Set-Acl -Path $Path -AclObject $acl
}

function Takeown-Folder($path)
{
    Takeown-File $path

    foreach ($item in Get-ChildItem $path)
    {
        if (Test-Path $item -PathType Container) { Takeown-Folder $item.FullName }
        else { Takeown-File $item.FullName }
    }
}

function Elevate-Privileges($Privilege)
{
    $Definition = @"
    using System;
    using System.Runtime.InteropServices;
    public class AdjPriv {
        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
            internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr rele);
        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
            internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);
        [DllImport("advapi32.dll", SetLastError = true)]
            internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
            internal struct TokPriv1Luid {
                public int Count;
                public long Luid;
                public int Attr;
            }
        internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
        internal const int TOKEN_QUERY = 0x00000008;
        internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
        public static bool EnablePrivilege(long processHandle, string privilege) {
            bool retVal;
            TokPriv1Luid tp;
            IntPtr hproc = new IntPtr(processHandle);
            IntPtr htok = IntPtr.Zero;
            retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
            tp.Count = 1;
            tp.Luid = 0;
            tp.Attr = SE_PRIVILEGE_ENABLED;
            retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
            retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
            return retVal;
        }
    }
"@
    $ProcessHandle = (Get-Process -id $pid).Handle
    $type = Add-Type $definition -PassThru
    $type[0]::EnablePrivilege($processHandle, $Privilege)
}
## ^
## Count: 6
########## ID:1

## Trying to have No Sound as default hope it gets transfered, [Registry::\HKEY_USERS\Default] must be loaded
function Disable-System-Sounds
{
    Write-Host "Disabling system sounds for good..."
    if((Test-Path "Registry::\HKEY_USERS\Default\AppEvents\Schemes") -ne $true) { New-Item "Registry::\HKEY_USERS\Default\AppEvents\Schemes" -Force -EA SilentlyContinue };
    if((Test-Path "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Names\.None") -ne $true) { New-Item "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Names\.None" -Force -EA SilentlyContinue };
    if((Test-Path "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\.Default\.Current") -ne $true) { New-Item "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\.Default\.Current" -Force -EA SilentlyContinue };
    if((Test-Path "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\CriticalBatteryAlarm\.Current") -ne $true) { New-Item "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\CriticalBatteryAlarm\.Current" -Force -EA SilentlyContinue };
    if((Test-Path "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\DeviceConnect\.Current") -ne $true) { New-Item "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\DeviceConnect\.Current" -Force -EA SilentlyContinue };
    if((Test-Path "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\DeviceDisconnect\.Current") -ne $true) { New-Item "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\DeviceDisconnect\.Current" -Force -EA SilentlyContinue };
    if((Test-Path "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\DeviceFail\.Current") -ne $true) { New-Item "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\DeviceFail\.Current" -Force -EA SilentlyContinue };
    if((Test-Path "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\FaxBeep\.Current") -ne $true) { New-Item "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\FaxBeep\.Current" -Force -EA SilentlyContinue };
    if((Test-Path "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\LowBatteryAlarm\.Current") -ne $true) { New-Item "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\LowBatteryAlarm\.Current" -Force -EA SilentlyContinue };
    if((Test-Path "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\MailBeep\.Current") -ne $true) { New-Item "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\MailBeep\.Current" -Force -EA SilentlyContinue };
    if((Test-Path "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\MessageNudge\.Current") -ne $true) { New-Item "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\MessageNudge\.Current" -Force -EA SilentlyContinue };
    if((Test-Path "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\Notification.Default\.Current") -ne $true) { New-Item "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\Notification.Default\.Current" -Force -EA SilentlyContinue };
    if((Test-Path "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\Notification.IM\.Current") -ne $true) { New-Item "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\Notification.IM\.Current" -Force -EA SilentlyContinue };
    if((Test-Path "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\Notification.Mail\.Current") -ne $true) { New-Item "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\Notification.Mail\.Current" -Force -EA SilentlyContinue };
    if((Test-Path "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\Notification.Proximity\.Current") -ne $true) { New-Item "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\Notification.Proximity\.Current" -Force -EA SilentlyContinue };
    if((Test-Path "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\Notification.Reminder\.Current") -ne $true) { New-Item "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\Notification.Reminder\.Current" -Force -EA SilentlyContinue };
    if((Test-Path "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\Notification.SMS\.Current") -ne $true) { New-Item "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\Notification.SMS\.Current" -Force -EA SilentlyContinue };
    if((Test-Path "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\ProximityConnection\.Current") -ne $true) { New-Item "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\ProximityConnection\.Current" -Force -EA SilentlyContinue };
    if((Test-Path "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\SystemAsterisk\.Current") -ne $true) { New-Item "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\SystemAsterisk\.Current" -Force -EA SilentlyContinue };
    if((Test-Path "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\SystemExclamation\.Current") -ne $true) { New-Item "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\SystemExclamation\.Current" -Force -EA SilentlyContinue };
    if((Test-Path "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\SystemHand\.Current") -ne $true) { New-Item "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\SystemHand\.Current" -Force -EA SilentlyContinue };
    if((Test-Path "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\SystemNotification\.Current") -ne $true) { New-Item "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\SystemNotification\.Current" -Force -EA SilentlyContinue };
    if((Test-Path "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\WindowsUAC\.Current") -ne $true) { New-Item "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\WindowsUAC\.Current" -Force -EA SilentlyContinue };
    if((Test-Path "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\sapisvr\DisNumbersSound\.current") -ne $true) { New-Item "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\sapisvr\DisNumbersSound\.current" -Force -EA SilentlyContinue };
    if((Test-Path "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\sapisvr\HubOffSound\.current") -ne $true) { New-Item "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\sapisvr\HubOffSound\.current" -Force -EA SilentlyContinue };
    if((Test-Path "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\sapisvr\HubOnSound\.current") -ne $true) { New-Item "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\sapisvr\HubOnSound\.current" -Force -EA SilentlyContinue };
    if((Test-Path "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\sapisvr\HubSleepSound\.current") -ne $true) { New-Item "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\sapisvr\HubSleepSound\.current" -Force -EA SilentlyContinue };
    if((Test-Path "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\sapisvr\MisrecoSound\.current") -ne $true) { New-Item "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\sapisvr\MisrecoSound\.current" -Force -EA SilentlyContinue };
    if((Test-Path "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\sapisvr\PanelSound\.current") -ne $true) { New-Item "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\sapisvr\PanelSound\.current" -Force -EA SilentlyContinue };
    New-ItemProperty "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\.Default\.Current" -Name "(default)" -Value "" -PropertyType String -Force -EA SilentlyContinue;
    New-ItemProperty "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\CriticalBatteryAlarm\.Current" -Name "(default)" -Value "" -PropertyType String -Force -EA SilentlyContinue;
    New-ItemProperty "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\DeviceConnect\.Current" -Name "(default)" -Value "" -PropertyType String -Force -EA SilentlyContinue;
    New-ItemProperty "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\DeviceDisconnect\.Current" -Name "(default)" -Value "" -PropertyType String -Force -EA SilentlyContinue;
    New-ItemProperty "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\DeviceFail\.Current" -Name "(default)" -Value "" -PropertyType String -Force -EA SilentlyContinue;
    New-ItemProperty "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\FaxBeep\.Current" -Name "(default)" -Value "" -PropertyType String -Force -EA SilentlyContinue;
    New-ItemProperty "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\LowBatteryAlarm\.Current" -Name "(default)" -Value "" -PropertyType String -Force -EA SilentlyContinue;
    New-ItemProperty "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\MailBeep\.Current" -Name "(default)" -Value "" -PropertyType String -Force -EA SilentlyContinue;
    New-ItemProperty "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\MessageNudge\.Current" -Name "(default)" -Value "" -PropertyType String -Force -EA SilentlyContinue;
    New-ItemProperty "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\Notification.Default\.Current" -Name "(default)" -Value "" -PropertyType String -Force -EA SilentlyContinue;
    New-ItemProperty "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\Notification.IM\.Current" -Name "(default)" -Value "" -PropertyType String -Force -EA SilentlyContinue;
    New-ItemProperty "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\Notification.Mail\.Current" -Name "(default)" -Value "" -PropertyType String -Force -EA SilentlyContinue;
    New-ItemProperty "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\Notification.Proximity\.Current" -Name "(default)" -Value "" -PropertyType String -Force -EA SilentlyContinue;
    New-ItemProperty "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\Notification.Reminder\.Current" -Name "(default)" -Value "" -PropertyType String -Force -EA SilentlyContinue;
    New-ItemProperty "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\Notification.SMS\.Current" -Name "(default)" -Value "" -PropertyType String -Force -EA SilentlyContinue;
    New-ItemProperty "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\ProximityConnection\.Current" -Name "(default)" -Value "" -PropertyType String -Force -EA SilentlyContinue;
    New-ItemProperty "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\SystemAsterisk\.Current" -Name "(default)" -Value "" -PropertyType String -Force -EA SilentlyContinue;
    New-ItemProperty "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\SystemExclamation\.Current" -Name "(default)" -Value "" -PropertyType String -Force -EA SilentlyContinue;
    New-ItemProperty "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\SystemHand\.Current" -Name "(default)" -Value "" -PropertyType String -Force -EA SilentlyContinue;
    New-ItemProperty "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\SystemNotification\.Current" -Name "(default)" -Value "" -PropertyType String -Force -EA SilentlyContinue;
    New-ItemProperty "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\.Default\WindowsUAC\.Current" -Name "(default)" -Value "" -PropertyType String -Force -EA SilentlyContinue;
    New-ItemProperty "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\sapisvr\DisNumbersSound\.current" -Name "(default)" -Value "" -PropertyType String -Force -EA SilentlyContinue;
    New-ItemProperty "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\sapisvr\HubOffSound\.current" -Name "(default)" -Value "" -PropertyType String -Force -EA SilentlyContinue;
    New-ItemProperty "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\sapisvr\HubOnSound\.current" -Name "(default)" -Value "" -PropertyType String -Force -EA SilentlyContinue;
    New-ItemProperty "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\sapisvr\HubSleepSound\.current" -Name "(default)" -Value "" -PropertyType String -Force -EA SilentlyContinue;
    New-ItemProperty "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\sapisvr\MisrecoSound\.current" -Name "(default)" -Value "" -PropertyType String -Force -EA SilentlyContinue;
    New-ItemProperty "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Apps\sapisvr\PanelSound\.current" -Name "(default)" -Value "" -PropertyType String -Force -EA SilentlyContinue;
    New-ItemProperty "Registry::\HKEY_USERS\Default\AppEvents\Schemes\Names\.None" -Name "(default)" -Value "No Sounds" -PropertyType String -Force -EA SilentlyContinue;
    New-ItemProperty "Registry::\HKEY_USERS\Default\AppEvents\Schemes" -Name "(default)" -Value ".None" -PropertyType String -Force -EA SilentlyContinue;

    if (( Test-Path  -Path "HKCU:\AppEvents\Schemes") -ne $true) { New-Item "HKCU:\AppEvents\Schemes" -Force -EA SilentlyContinue };
    if (( Test-Path  -Path "HKCU:\AppEvents\Schemes\Names\.None") -ne $true) { New-Item "HKCU:\AppEvents\Schemes\Names\.None" -Force -EA SilentlyContinue };
    if (( Test-Path  -Path "HKCU:\AppEvents\Schemes\Apps\.Default\.Default\.Current") -ne $true) { New-Item "HKCU:\AppEvents\Schemes\Apps\.Default\.Default\.Current" -Force -EA SilentlyContinue };
    if (( Test-Path  -Path "HKCU:\AppEvents\Schemes\Apps\.Default\CriticalBatteryAlarm\.Current") -ne $true) { New-Item "HKCU:\AppEvents\Schemes\Apps\.Default\CriticalBatteryAlarm\.Current" -Force -EA SilentlyContinue };
    if (( Test-Path  -Path "HKCU:\AppEvents\Schemes\Apps\.Default\DeviceConnect\.Current") -ne $true) { New-Item "HKCU:\AppEvents\Schemes\Apps\.Default\DeviceConnect\.Current" -Force -EA SilentlyContinue };
    if (( Test-Path  -Path "HKCU:\AppEvents\Schemes\Apps\.Default\DeviceDisconnect\.Current") -ne $true) { New-Item "HKCU:\AppEvents\Schemes\Apps\.Default\DeviceDisconnect\.Current" -Force -EA SilentlyContinue };
    if (( Test-Path  -Path "HKCU:\AppEvents\Schemes\Apps\.Default\DeviceFail\.Current") -ne $true) { New-Item "HKCU:\AppEvents\Schemes\Apps\.Default\DeviceFail\.Current" -Force -EA SilentlyContinue };
    if (( Test-Path  -Path "HKCU:\AppEvents\Schemes\Apps\.Default\FaxBeep\.Current") -ne $true) { New-Item "HKCU:\AppEvents\Schemes\Apps\.Default\FaxBeep\.Current" -Force -EA SilentlyContinue };
    if (( Test-Path  -Path "HKCU:\AppEvents\Schemes\Apps\.Default\LowBatteryAlarm\.Current") -ne $true) { New-Item "HKCU:\AppEvents\Schemes\Apps\.Default\LowBatteryAlarm\.Current" -Force -EA SilentlyContinue };
    if (( Test-Path  -Path "HKCU:\AppEvents\Schemes\Apps\.Default\MailBeep\.Current") -ne $true) { New-Item "HKCU:\AppEvents\Schemes\Apps\.Default\MailBeep\.Current" -Force -EA SilentlyContinue };
    if (( Test-Path  -Path "HKCU:\AppEvents\Schemes\Apps\.Default\MessageNudge\.Current") -ne $true) { New-Item "HKCU:\AppEvents\Schemes\Apps\.Default\MessageNudge\.Current" -Force -EA SilentlyContinue };
    if (( Test-Path  -Path "HKCU:\AppEvents\Schemes\Apps\.Default\Notification.Default\.Current") -ne $true) { New-Item "HKCU:\AppEvents\Schemes\Apps\.Default\Notification.Default\.Current" -Force -EA SilentlyContinue };
    if (( Test-Path  -Path "HKCU:\AppEvents\Schemes\Apps\.Default\Notification.IM\.Current") -ne $true) { New-Item "HKCU:\AppEvents\Schemes\Apps\.Default\Notification.IM\.Current" -Force -EA SilentlyContinue };
    if (( Test-Path  -Path "HKCU:\AppEvents\Schemes\Apps\.Default\Notification.Mail\.Current") -ne $true) { New-Item "HKCU:\AppEvents\Schemes\Apps\.Default\Notification.Mail\.Current" -Force -EA SilentlyContinue };
    if (( Test-Path  -Path "HKCU:\AppEvents\Schemes\Apps\.Default\Notification.Proximity\.Current") -ne $true) { New-Item "HKCU:\AppEvents\Schemes\Apps\.Default\Notification.Proximity\.Current" -Force -EA SilentlyContinue };
    if (( Test-Path  -Path "HKCU:\AppEvents\Schemes\Apps\.Default\Notification.Reminder\.Current") -ne $true) { New-Item "HKCU:\AppEvents\Schemes\Apps\.Default\Notification.Reminder\.Current" -Force -EA SilentlyContinue };
    if (( Test-Path  -Path "HKCU:\AppEvents\Schemes\Apps\.Default\Notification.SMS\.Current") -ne $true) { New-Item "HKCU:\AppEvents\Schemes\Apps\.Default\Notification.SMS\.Current" -Force -EA SilentlyContinue };
    if (( Test-Path  -Path "HKCU:\AppEvents\Schemes\Apps\.Default\ProximityConnection\.Current") -ne $true) { New-Item "HKCU:\AppEvents\Schemes\Apps\.Default\ProximityConnection\.Current" -Force -EA SilentlyContinue };
    if (( Test-Path  -Path "HKCU:\AppEvents\Schemes\Apps\.Default\SystemAsterisk\.Current") -ne $true) { New-Item "HKCU:\AppEvents\Schemes\Apps\.Default\SystemAsterisk\.Current" -Force -EA SilentlyContinue };
    if (( Test-Path  -Path "HKCU:\AppEvents\Schemes\Apps\.Default\SystemExclamation\.Current") -ne $true) { New-Item "HKCU:\AppEvents\Schemes\Apps\.Default\SystemExclamation\.Current" -Force -EA SilentlyContinue };
    if (( Test-Path  -Path "HKCU:\AppEvents\Schemes\Apps\.Default\SystemHand\.Current") -ne $true) { New-Item "HKCU:\AppEvents\Schemes\Apps\.Default\SystemHand\.Current" -Force -EA SilentlyContinue };
    if (( Test-Path  -Path "HKCU:\AppEvents\Schemes\Apps\.Default\SystemNotification\.Current") -ne $true) { New-Item "HKCU:\AppEvents\Schemes\Apps\.Default\SystemNotification\.Current" -Force -EA SilentlyContinue };
    if (( Test-Path  -Path "HKCU:\AppEvents\Schemes\Apps\.Default\WindowsUAC\.Current") -ne $true) { New-Item "HKCU:\AppEvents\Schemes\Apps\.Default\WindowsUAC\.Current" -Force -EA SilentlyContinue };
    if (( Test-Path  -Path "HKCU:\AppEvents\Schemes\Apps\sapisvr\DisNumbersSound\.current") -ne $true) { New-Item "HKCU:\AppEvents\Schemes\Apps\sapisvr\DisNumbersSound\.current" -Force -EA SilentlyContinue };
    if (( Test-Path  -Path "HKCU:\AppEvents\Schemes\Apps\sapisvr\HubOffSound\.current") -ne $true) { New-Item "HKCU:\AppEvents\Schemes\Apps\sapisvr\HubOffSound\.current" -Force -EA SilentlyContinue };
    if (( Test-Path  -Path "HKCU:\AppEvents\Schemes\Apps\sapisvr\HubOnSound\.current") -ne $true) { New-Item "HKCU:\AppEvents\Schemes\Apps\sapisvr\HubOnSound\.current" -Force -EA SilentlyContinue };
    if (( Test-Path  -Path "HKCU:\AppEvents\Schemes\Apps\sapisvr\HubSleepSound\.current") -ne $true) { New-Item "HKCU:\AppEvents\Schemes\Apps\sapisvr\HubSleepSound\.current" -Force -EA SilentlyContinue };
    if (( Test-Path  -Path "HKCU:\AppEvents\Schemes\Apps\sapisvr\MisrecoSound\.current") -ne $true) { New-Item "HKCU:\AppEvents\Schemes\Apps\sapisvr\MisrecoSound\.current" -Force -EA SilentlyContinue };
    if (( Test-Path  -Path "HKCU:\AppEvents\Schemes\Apps\sapisvr\PanelSound\.current") -ne $true) { New-Item "HKCU:\AppEvents\Schemes\Apps\sapisvr\PanelSound\.current" -Force -EA SilentlyContinue };

    New-ItemProperty -Path "HKCU:\AppEvents\Schemes\Names\.None"                                   -Name "(default)" -Value "No Sounds" -Force -EA SilentlyContinue;
    New-ItemProperty -Path "HKCU:\AppEvents\Schemes"                                               -Name "(default)" -Value ".None" -Force -EA SilentlyContinue;
    New-ItemProperty -Path "HKCU:\AppEvents\Schemes\Apps\.Default\.Default\.Current"               -Name "(default)" -Value "" -Force -EA SilentlyContinue;
    New-ItemProperty -Path "HKCU:\AppEvents\Schemes\Apps\.Default\CriticalBatteryAlarm\.Current"   -Name "(default)" -Value "" -Force -EA SilentlyContinue;
    New-ItemProperty -Path "HKCU:\AppEvents\Schemes\Apps\.Default\DeviceConnect\.Current"          -Name "(default)" -Value "" -Force -EA SilentlyContinue;
    New-ItemProperty -Path "HKCU:\AppEvents\Schemes\Apps\.Default\DeviceDisconnect\.Current"       -Name "(default)" -Value "" -Force -EA SilentlyContinue;
    New-ItemProperty -Path "HKCU:\AppEvents\Schemes\Apps\.Default\DeviceFail\.Current"             -Name "(default)" -Value "" -Force -EA SilentlyContinue;
    New-ItemProperty -Path "HKCU:\AppEvents\Schemes\Apps\.Default\FaxBeep\.Current"                -Name "(default)" -Value "" -Force -EA SilentlyContinue;
    New-ItemProperty -Path "HKCU:\AppEvents\Schemes\Apps\.Default\LowBatteryAlarm\.Current"        -Name "(default)" -Value "" -Force -EA SilentlyContinue;
    New-ItemProperty -Path "HKCU:\AppEvents\Schemes\Apps\.Default\MailBeep\.Current"               -Name "(default)" -Value "" -Force -EA SilentlyContinue;
    New-ItemProperty -Path "HKCU:\AppEvents\Schemes\Apps\.Default\MessageNudge\.Current"           -Name "(default)" -Value "" -Force -EA SilentlyContinue;
    New-ItemProperty -Path "HKCU:\AppEvents\Schemes\Apps\.Default\Notification.Default\.Current"   -Name "(default)" -Value "" -Force -EA SilentlyContinue;
    New-ItemProperty -Path "HKCU:\AppEvents\Schemes\Apps\.Default\Notification.IM\.Current"        -Name "(default)" -Value "" -Force -EA SilentlyContinue;
    New-ItemProperty -Path "HKCU:\AppEvents\Schemes\Apps\.Default\Notification.Mail\.Current"      -Name "(default)" -Value "" -Force -EA SilentlyContinue;
    New-ItemProperty -Path "HKCU:\AppEvents\Schemes\Apps\.Default\Notification.Proximity\.Current" -Name "(default)" -Value "" -Force -EA SilentlyContinue;
    New-ItemProperty -Path "HKCU:\AppEvents\Schemes\Apps\.Default\Notification.Reminder\.Current"  -Name "(default)" -Value "" -Force -EA SilentlyContinue;
    New-ItemProperty -Path "HKCU:\AppEvents\Schemes\Apps\.Default\Notification.SMS\.Current"       -Name "(default)" -Value "" -Force -EA SilentlyContinue;
    New-ItemProperty -Path "HKCU:\AppEvents\Schemes\Apps\.Default\ProximityConnection\.Current"    -Name "(default)" -Value "" -Force -EA SilentlyContinue;
    New-ItemProperty -Path "HKCU:\AppEvents\Schemes\Apps\.Default\SystemAsterisk\.Current"         -Name "(default)" -Value "" -Force -EA SilentlyContinue;
    New-ItemProperty -Path "HKCU:\AppEvents\Schemes\Apps\.Default\SystemExclamation\.Current"      -Name "(default)" -Value "" -Force -EA SilentlyContinue;
    New-ItemProperty -Path "HKCU:\AppEvents\Schemes\Apps\.Default\SystemHand\.Current"             -Name "(default)" -Value "" -Force -EA SilentlyContinue;
    New-ItemProperty -Path "HKCU:\AppEvents\Schemes\Apps\.Default\SystemNotification\.Current"     -Name "(default)" -Value "" -Force -EA SilentlyContinue;
    New-ItemProperty -Path "HKCU:\AppEvents\Schemes\Apps\.Default\WindowsUAC\.Current"             -Name "(default)" -Value "" -Force -EA SilentlyContinue;
    New-ItemProperty -Path "HKCU:\AppEvents\Schemes\Apps\sapisvr\DisNumbersSound\.current"         -Name "(default)" -Value "" -Force -EA SilentlyContinue;
    New-ItemProperty -Path "HKCU:\AppEvents\Schemes\Apps\sapisvr\HubOffSound\.current"             -Name "(default)" -Value "" -Force -EA SilentlyContinue;
    New-ItemProperty -Path "HKCU:\AppEvents\Schemes\Apps\sapisvr\HubOnSound\.current"              -Name "(default)" -Value "" -Force -EA SilentlyContinue;
    New-ItemProperty -Path "HKCU:\AppEvents\Schemes\Apps\sapisvr\HubSleepSound\.current"           -Name "(default)" -Value "" -Force -EA SilentlyContinue;
    New-ItemProperty -Path "HKCU:\AppEvents\Schemes\Apps\sapisvr\MisrecoSound\.current"            -Name "(default)" -Value "" -Force -EA SilentlyContinue;
    New-ItemProperty -Path "HKCU:\AppEvents\Schemes\Apps\sapisvr\PanelSound\.current"              -Name "(default)" -Value "" -Force -EA SilentlyContinue;
}

## Add CZE-QWERTY keyboard
function Add-CZEQWERTY-Keyboard
{
    Write-Host "Trying to add new CZE-QWERTY Language&Keyboard..."
    $langs = Get-WinUserLanguageList
    $langs.Add("cs")
    ## Change Input method to qwerty
    $lang = $langs.Item($langs.Count - 1)
    $lang.InputMethodTips.Clear()
    $lang.InputMethodTips.Add("0405:00010405")

    Set-WinUserLanguageList $langs -Force

    # And use as default input
    Write-Host "...and set as def..."
    Set-WinDefaultInputMethodOverride -InputTip "0405:00010405"
}

## Window Style-State (Get-Process -Name notepad).MainWindowHandle | foreach { Set-WindowStyle MAXIMIZE $_ }
function Set-WindowStyle
{
    param
    (
        [Parameter()]
        [ValidateSet("FORCEMINIMIZE", "HIDE", "MAXIMIZE", "MINIMIZE", "RESTORE", 
                    "SHOW", "SHOWDEFAULT", "SHOWMAXIMIZED", "SHOWMINIMIZED", 
                    "SHOWMINNOACTIVE", "SHOWNA", "SHOWNOACTIVATE", "SHOWNORMAL")]
        $Style = "SHOW",
        [Parameter()]
        $MainWindowHandle = (Get-Process -Id $pid).MainWindowHandle
    )
    
    $WindowStates =
    @{
        FORCEMINIMIZE   = 11; HIDE            = 0
        MAXIMIZE        = 3;  MINIMIZE        = 6
        RESTORE         = 9;  SHOW            = 5
        SHOWDEFAULT     = 10; SHOWMAXIMIZED   = 3
        SHOWMINIMIZED   = 2;  SHOWMINNOACTIVE = 7
        SHOWNA          = 8;  SHOWNOACTIVATE  = 4
        SHOWNORMAL      = 1
    }

    Write-Verbose ("Set Window Style {1} on handle {0}" -f $MainWindowHandle, $($WindowStates[$style]))

    $Win32ShowWindowAsync = Add-Type –MemberDefinition @"
    [DllImport("user32.dll")] 
    public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);
"@  -Name "Win32ShowWindowAsync" -Namespace Win32Functions –PassThru

    $Win32ShowWindowAsync::ShowWindowAsync($MainWindowHandle, $WindowStates[$Style]) | Out-Null
}

#https://msedge.sf.dl.delivery.mp.microsoft.com/filestreamingservice/files/20439f3d-3756-4ffd-a45a-6d9890576e81/MicrosoftEdgeDevEnterpriseX64.msi
#Invoke-WebRequest https://c2rsetup.officeapps.live.com/c2r/downloadEdge.aspx?platform=Default'&'source=EdgeInsiderPage'&'Channel=Canary'&'language=en -OutFile C:\edge.exe
#Invoke-WebRequest https://openvpn.net/downloads/openvpn-connect-v3-windows.msi -OutFile C:\openvpn.msi

#$taskTrigger = New-ScheduledTaskTrigger -AtLogOn
#$taskAction = New-ScheduledTaskAction -Execute ("$alpha\runContinue.bat")
    
#Register-ScheduledTask -TaskName "SysprepContinuation" -Trigger $taskTrigger -Action $taskAction -EA SilentlyContinue

## Move sysprepclean to C:\
#if (Test-Path $alpha\ranWareWorkerSysprepCleanAdministratorFolder.ps1) { Move-Item -Path $alpha\ranwareWorkerSysprepCleanAdministratorFolder.ps1 -Destination C:\sysprepCleanAdministratorFolder.ps1 -Force }
