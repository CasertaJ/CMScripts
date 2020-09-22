#Discovery
$regkey = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration\"

$changeNeeded = $false

if($regkey.CDNBaseUrl-ne $regkey.UpdateChannel){
    if($regkey.UpdateChannel -ne $null){
        $changeNeeded = $true}
}
    
if($regkey.CDNBaseUrl-ne $regkey.UnmanagedUpdateUrl){
    if($regkey.UnmanagedUpdateUrl -ne $null){
        $changeNeeded = $true}
}

$changeNeeded

#Remediation
$regkey = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration\"

if($regkey.CDNBaseUrl -ne $regkey.UpdateChannel){Set-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration\" -Name UpdateChannel -Value $regkey.CDNBaseUrl}
    
if($regkey.CDNBaseUrl-ne $regkey.UnmanagedUpdateUrl){Set-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration\" -Name UnmanagedUpdateUrl -Value $regkey.CDNBaseUrl}
