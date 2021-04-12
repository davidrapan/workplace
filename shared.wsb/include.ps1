########################################################
###############ranWare All-Mighty Tools#################
########################################################

########################################################
########################################################
########################################################

#Mix of helper functions, mine and borrowed too, refers to authors are sadly in second script which will join soon as possible :)))

## Try to acquire higher priviledges
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

## MKDir when not exists
function New-FolderForced
{
    [CmdletBinding(SupportsShouldProcess = $true)]
    param
    (
		[Parameter(Position = 0, Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
		[string]
        $Path
    )

    process
    {
        if (-not (Test-Path $Path))
        {
            Write-Verbose "-- Creating full path to: $Path"
            New-Item -Path $Path -ItemType Directory -Force
        }
    }
}

## Helpers 1
function Get-Path
{
    param
    (
        [Parameter(Position = 0, Mandatory)]
        [String]$Path,
        [Parameter(Position = 1)]
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

## Test-Path Destination then Copy
function Test-Copy-Item
{
    param
    (
        [Parameter(Position = 0)]
        [String]$Path,
        [Parameter(Position = 1, Mandatory)]
        [String]$Destination
    )

    if (-not (Test-Path $Destination -EA SilentlyContinue)) { Copy-Item -Path $Path -Destination $Destination -EA SilentlyContinue -Force }
}

function Test-Path-Wait([Parameter()]$Path)
{
    while (-not (Test-Path $Path)) { start-sleep 1 }

    return $true
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

## Install SW using msi installer
function Install-Msi
{
    param
    (
        [Parameter(Position = 0, Mandatory)]
        [string]$Path,
        [Parameter(Position = 1)]
        [string]$Destination="C:\",
        [Parameter(Position = 2)]
        [Switch]$Passive,
        [Parameter(Position = 3)]
        [string]$Arguments = "/qn"
    )

    $dest = ($Destination + (Get-Leaf($Path)))
    $args = "/quiet "

    if ($Passive) { $args = "/passive " }

    Test-Copy-Item -Path $Path -Destination $dest

    $installer = Start-Process -FilePath $dest -EA SilentlyContinue -Wait -PassThru -ArgumentList ($args + $Arguments)

    Write-Host "Installation exited /w code $($installer.ExitCode)..."

    Remove-Item -Path $dest -EA SilentlyContinue -Force

    Wait 1
}

## Disable System Sounds
function Disable-System-Sounds
{
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

    $Win32ShowWindowAsync = Add-Type MemberDefinition @"
    [DllImport("user32.dll")] 
    public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);
"@  -Name "Win32ShowWindowAsync" -Namespace Win32Functions PassThru

    $Win32ShowWindowAsync::ShowWindowAsync($MainWindowHandle, $WindowStates[$Style]) | Out-Null
}
