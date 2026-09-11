param(
    [Parameter(Mandatory=$true)][System.Net.IPAddress]$WslAddress,
    [Parameter(Mandatory=$true)][System.Net.IPAddress]$LanAddress,
    [int]$Port = 8765
)
$ErrorActionPreference = 'Stop'
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw 'Run this script in an Administrator PowerShell window.' }
# Replace the Vandal listener only; leave other forwarded ports intact.
netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport=$Port | Out-Null
netsh interface portproxy delete v4tov4 listenaddress=$LanAddress listenport=$Port | Out-Null
netsh interface portproxy add v4tov4 listenaddress=$LanAddress listenport=$Port connectaddress=$WslAddress connectport=$Port
if ($LASTEXITCODE -ne 0) { throw 'Could not configure port forwarding' }
$name = "Vandal-LAN-$Port"
Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -Name $name -DisplayName "Vandal LAN TCP $Port" -Direction Inbound -Action Allow -Protocol TCP -LocalPort $Port -LocalAddress $LanAddress -RemoteAddress LocalSubnet -Profile Any | Out-Null
Write-Output "Vandal LAN access: http://${LanAddress}:$Port"
