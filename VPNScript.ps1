#Original script for rasphone and UDP encapsulation: https://pastebin.com/9nLjeJ5B

#Variables
$ConnectionName = 'VPN Friendly Name spaces allowed'
$ServerAddress = 'meraki-dynamic-ip-address-dynamic-m.com' #Note, if you have issues, I recommend trying WAN Ip address instead of the providied Meraki dynamic address found in the portal.
$PresharedKey = 'PreSharedKeySecret'
$DNSSuffix = 'company.local'
$Subnet = '10.10.10.0/24'
$DNSServer = '10.10.10.100'

# If there's a VPN connection profile with the same name, delete it
Remove-VpnConnection -AllUserConnection -Name $ConnectionName -Force -EA SilentlyContinue
#Add Connection, all user
Add-VpnConnection -AllUserConnection -Name $ConnectionName -ServerAddress $ServerAddress -TunnelType L2tp -DnsSuffix $DNSSuffix -EncryptionLevel Optional -AuthenticationMethod PAP -L2tpPsk $PresharedKey -Force -PassThru –RememberCredential
#Enable split tunneling
Set-VpnConnection -Name $ConnectionName -SplitTunneling $True -AllUserConnection -WA SilentlyContinue
#Add subnet route
Add-VpnConnectionRoute -ConnectionName $ConnectionName -AllUserConnection -DestinationPrefix $Subnet
#Connection trigger - Optional - Automatically connects to VPN if a mapped drive, RDP server, or other resource is attempted to be reached.
Set-VpnConnectionTriggerDnsConfiguration -ConnectionName $ConnectionName -DnsSuffix $DNSSuffix -DnsIPAddress $DNSServer -PassThru -Force
#Assume UDP encapsulation
if ((Test-Path -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\PolicyAgent') -ne $true) { New-Item 'HKLM:\SYSTEM\CurrentControlSet\Services\PolicyAgent' -Force -ea SilentlyContinue }
New-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\PolicyAgent' -Name 'AssumeUDPEncapsulationContextOnSendRule' -Value 2 -PropertyType DWord -Force -ea SilentlyContinue

#------------Create desktop shortcut----------------
$PbkPath = Join-Path $env:PROGRAMDATA 'Microsoft\Network\Connections\Pbk\rasphone.Pbk'

If ((Test-Path $PbkPath) -eq $false) {
    $PbkFolder = Join-Path $env:PROGRAMDATA 'Microsoft\Network\Connections\pbk\'
    # Check if pbk folder actually exists. If it does, create place-holder phonebook.
    if ((Test-Path $PbkFolder) -eq $true) {
        New-Item -Path $PbkFolder -Name 'rasphone.pbk' -ItemType 'file' | Out-Null
    }
    # If pbk folder doesn't exist, make folder then make place-holder phonebook.
    else {
        $ConnectionFolder = Join-Path $env:PROGRAMDATA 'Microsoft\Network\Connections\'
        New-Item -Path $ConnectionFolder -Name 'pbk' -ItemType 'directory' | Out-Null
        New-Item -Path $PbkFolder -Name 'rasphone.pbk' -ItemType 'file' | Out-Null
    }
}

$IconLocation = '%SystemRoot%\System32\SHELL32.dll'
$IconArrayIndex = 18
$ShortcutFile = "$env:Public\Desktop\VPN.lnk"
$WScriptShell = New-Object -ComObject WScript.Shell
$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
$Shortcut.TargetPath = 'rasphone.exe'
#$Shortcut.Arguments = "-d `"$ConnectionName[i]`""
$ShortCut.WorkingDirectory = "$env:SystemRoot\System32\"
$Shortcut.IconLocation = "$IconLocation, $IconArrayIndex"
$Shortcut.Save()
#------------/Create desktop shortcut----------------


#Use domain credentials instead of VPN credentials
(Get-Content -Path 'C:\ProgramData\Microsoft\Network\Connections\Pbk\rasphone.pbk' -Raw) -Replace 'UseRasCredentials=1', 'UseRasCredentials=0' | Set-Content -Path C:\ProgramData\Microsoft\Network\Connections\Pbk\rasphone.pbk

#Disable Xbox live services
Stop-Service -Name 'XblAuthManager'
Stop-Service -Name 'XboxNetApiSvc'
Set-Service -Name 'XblAuthManager' -Status stopped -StartupType disabled
Set-Service -Name 'XboxNetApiSvc' -Status stopped -StartupType disabled
