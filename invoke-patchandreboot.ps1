Function Get-PendingReboot {

    Try {
        ## Setting pending values to false to cut down on the number of else statements
        $CompPendRen, $PendFileRename, $Pending, $SCCM = $false, $false, $false, $false

        ## Setting CBSRebootPend to null since not all versions of Windows has this value
        $CBSRebootPend = $null

        ## Making registry connection to the local/remote computer
        $HKLM = [UInt32] "0x80000002"
        $WMI_Reg = [WMIClass] "\\$($env:Computername)\root\default:StdRegProv"

        $RegSubKeysCBS = $WMI_Reg.EnumKey($HKLM, "SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\")
        $CBSRebootPend = $RegSubKeysCBS.sNames -contains "RebootPending"

        ## Query WUAU from the registry
        $RegWUAURebootReq = $WMI_Reg.EnumKey($HKLM, "SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\")
        $WUAURebootReq = $RegWUAURebootReq.sNames -contains "RebootRequired"

        ## Query PendingFileRenameOperations from the registry
        $RegSubKeySM = $WMI_Reg.GetMultiStringValue($HKLM, "SYSTEM\CurrentControlSet\Control\Session Manager\", "PendingFileRenameOperations")
        $RegValuePFRO = $RegSubKeySM.sValue

        ## Query JoinDomain key from the registry - These keys are present if pending a reboot from a domain join operation
        $Netlogon = $WMI_Reg.EnumKey($HKLM, "SYSTEM\CurrentControlSet\Services\Netlogon").sNames
        $PendDomJoin = ($Netlogon -contains 'JoinDomain') -or ($Netlogon -contains 'AvoidSpnSet')

        ## Query ComputerName and ActiveComputerName from the registry
        $ActCompNm = $WMI_Reg.GetStringValue($HKLM, "SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName\", "ComputerName")
        $CompNm = $WMI_Reg.GetStringValue($HKLM, "SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName\", "ComputerName")

        If (($ActCompNm -ne $CompNm) -or $PendDomJoin) {
            $CompPendRen = $true
        }

        ## If PendingFileRenameOperations has a value set $RegValuePFRO variable to $true
        If ($RegValuePFRO) {
            $PendFileRename = $true
        }

        ## Creating Custom PSObject and Select-Object Splat
        $SelectSplat = @{
            Property = (
                'Computer',
                'CBServicing',
                'WindowsUpdate',
                'PendComputerRename',
                'PendFileRename',
                'PendFileRenVal',
                'RebootPending'
            )
        }
        New-Object -TypeName PSObject -Property @{
            Computer           = $env:COMPUTERNAME
            CBServicing        = $CBSRebootPend
            WindowsUpdate      = $WUAURebootReq
            PendComputerRename = $CompPendRen
            PendFileRename     = $PendFileRename
            PendFileRenVal     = $RegValuePFRO
            RebootPending      = ($CompPendRen -or $CBSRebootPend -or $WUAURebootReq -or $PendFileRename)
        } | Select-Object @SelectSplat

    }
    Catch {
        Write-Warning "$Computer`: $_"
        ## If $ErrorLog, log the file to a user specified location/path
        If ($ErrorLog) {
            Out-File -InputObject "$Computer`,$_" -FilePath $ErrorLog -Append
        }
    }
}## End Function Get-PendingReboot

# Start the actual configuration
# These 2 items and a new log source need to be installed first.


[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

if (-not ([System.Diagnostics.EventLog]::SourceExists('NodePatch')) ) {
    New-EventLog -LogName Application -Source NodePatch
}

if (-not (Get-PackageProvider -ListAvailable -Name 'Nuget' -ErrorAction SilentlyContinue)) {
    Get-PackageProvider -Name "Nuget" -ForceBootstrap
}

Set-PSRepository -Name PSGallery -InstallationPolicy Trusted

if (-not(Get-Module -ListAvailable -Name PSWindowsUpdate)) {
    Install-Module -Name PSWindowsUpdate -Force
    Import-Module -Name PSWindowsUpdate
}

# Remove items set in the foreach loop below. Nice and Tidy
if (Get-ScheduledTask -TaskName PatchWindows -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName PatchWindows -Confirm:$false
}

if (Get-ScheduledTask -TaskName PatchWindowsReboot -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName PatchWindowsReboot -Confirm:$false
}

if (Test-Path -path c:\staging -ErrorAction SilentlyContinue) {
    Remove-Item -Path c:\Staging -Recurse -Force -Confirm:$false
}

$config = Get-NetConnectionProfile
if ($config.NetworkCategory -eq 'Public') {
    Set-NetConnectionProfile -InterfaceIndex $config.InterfaceIndex -NetworkCategory Private
}

Enable-PSRemoting -Confirm:$false

#Install Chocolatey
if (-not(Get-Module -FullyQualifiedName chocolateyprofile)) {
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
}

# Start My Updates
$updates = Get-WUList

if ($updates) {
    foreach ($update in $updates) {

        Install-WindowsUpdate -KBArticleID $update.KB -confirm:$false -IgnoreReboot
        Write-EventLog -LogName Application -Source NodePatch -EventId 20 -EntryType Information -Message "Just installed $($update.Title)"

        $pending = Get-PendingReboot

        # The pending blob can hold a number of lines in array format that indicate if the KB is installed. We're checking
        # for the presence of True which is thrown when a reboot is required
        if ($pending -match 'True') {
            if (-not(Test-Path -path c:\staging)) {
                New-Item -Path c:\Staging -ItemType Directory
            }

            Write-EventLog -LogName Application -Source NodePatch -EventId 30 -EntryType Warning -Message "Pending Reboot detected, writing scheduled task and restarting for patch : \n$($update.Title)"

            # Write this script to disk so we can load it and contiue updating the OS after a reboot
            $content = $MyInvocation.MyCommand.ScriptBlock
            New-Item -Path c:\staging\nodepatch.ps1 -ItemType File
            Set-Content -Path c:\staging\nodepatch.ps1 -Encoding utf8 -Value $content

            $A = New-ScheduledTaskAction -Execute "C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument "-ExecutionPolicy Bypass -File c:\Staging\nodepatch.ps1”
            # $T = New-ScheduledTaskTrigger -AtLogOn
            $T = New-ScheduledTaskTrigger -AtStartup
            $S = New-ScheduledTaskSettingsSet -Compatibility Win8 -Priority 0
            # $P = New-ScheduledTaskPrincipal -GroupId "Users" -RunLevel Highest
            $P = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
            $D = New-ScheduledTask -Action $A -Trigger $T -Settings $S -Principal $P
            Register-ScheduledTask -TaskName 'PatchWindows' -Force -InputObject $D

            # Restart-computer

            $A = New-ScheduledTaskAction -Execute "C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument "Restart-Computer -Force”
            # $T = New-ScheduledTaskTrigger -AtLogOn
            # $T = New-ScheduledTaskTrigger -AtStartup
            $T = New-ScheduledTaskTrigger -Once -At (get-date).AddMinutes(2)
            $S = New-ScheduledTaskSettingsSet -Compatibility Win8 -Priority 0
            # $P = New-ScheduledTaskPrincipal -GroupId "Users" -RunLevel Highest
            $P = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
            $D = New-ScheduledTask -Action $A -Trigger $T -Settings $S -Principal $P
            Register-ScheduledTask -TaskName 'PatchWindowsReboot' -Force -InputObject $D

        }

    }
}

$ErrorActionPreference = "Stop"

Write-Output "Installing a Chef17 client"

. { Invoke-WebRequest -useb https://omnitruck.chef.io/install.ps1 } | Invoke-Expression; install
