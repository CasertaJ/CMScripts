<#
.SYNOPSIS
	This script performs an uninstall of the application using the uninstall key found in the registry. You can further tweak the script with your own custom parameters.

.PARAMETER AppName
	This is the application name that would appear in the "DisplayName" field in the registry
.PARAMETER CustomMSIParams
	This will add any custom MSI parameters to the uninstall script. 
.PARAMETER CustomEXEParams
	This will add any custom EXE parameters to the uninstall script.
.PARAMETER RunUninstaller
	If this parameter exists, it will run the uninstall.
.EXAMPLE
    & '.\MECM - Application - Universal Uninstaller.ps1' -AppName Notepad -CustomEXEparams '/S'
	This is run the script is "Finding Mode". It will display the uninstall string found and add the CustomEXEparams to it.
.EXAMPLE
	Computer Uninstalls
	x86 Programs
	x64 Programs
	###Notepad++ (64-bit x64)###
	Custom: "c:\program files\notepad++\uninstall.exe" /S
	User Uninstalls
	user1
	user2
	user3

.EXAMPLE
    & '.\MECM - Application - Universal Uninstaller.ps1' -AppName chrome -CustomMSIParams '\qn'
	This is run the script is "Finding Mode". It will display the uninstall string found and add the CustomMSIparams to it.
.EXAMPLE
    Computer Uninstalls
	x86 Programs
	x64 Programs
	###Google Chrome###
	Custom: msiexec.exe /x {3acbc599-f9fa-344f-a90c-4bc47885d629} \qn
	User Uninstalls
	user1
	user2
	user3
.EXAMPLE
     & '.\MECM - Application - Universal Uninstaller.ps1' -AppName Notepad -CustomEXEparams '/S' -RunUninstaller
	 This will run the script in "Uninstall Mode". It will uninstall the application using the uninstall string found and add the CustomEXEparams to it.
#>
[cmdletbinding()]
Param (
	[Parameter(Mandatory=$true)][string]$AppName,
	[Parameter(Mandatory=$false)][string]$CustomEXEParams = $null,
	[Parameter(Mandatory=$false)][string]$CustomMSIParams = $null,
    [Parameter(Mandatory=$false)][switch]$RunUninstaller
)
#>

Function Uninstall {
			Param ($Uninstaller)
    
			ForEach ($ver in $Uninstaller) {
				$name = $ver.DisplayName
				#MSI
				if ($ver.UninstallString -match "msiexec.exe") {
					$AppUninstallString = ($ver.UninstallString).ToString().tolower()
					$ProductIDbase = $AppUninstallString.split('{,}') 
					$ProductID = "{" + $ProductIDbase[1] + "}"
                    
					if ($CustomMSIParams) {
						if ($RunUninstaller) {
							Start-Process msiexec.exe -Argumentlist "/x $ProductID $CustomMSIParams"
						}
						else {
							write-host "###" -ForegroundColor Green -NoNewline 
							write-host "$name" -ForegroundColor Cyan -NoNewline 
							write-host "###" -ForegroundColor Green
							write-host "Custom: " -NoNewline -ForegroundColor Cyan
							write-host "msiexec.exe /x $ProductID $CustomMSIParams"
						}
					}
					else {
						$NonCustomMSIParams = $ProductIDbase[2]
						if ($RunUninstaller) {
							if ($null -eq $NonCustomMSIParams) {
								Start-Process msiexec.exe -Argumentlist "/x $ProductID"
							}
							else {
								Start-Process msiexec.exe -Argumentlist "/x $ProductID$NonCustomMSIParams"
							}
						}
						else {
							write-host "###" -ForegroundColor Green -NoNewline 
							write-host "$name" -ForegroundColor Cyan -NoNewline 
							write-host "###" -ForegroundColor Green
							write-host "Non-Custom: " -NoNewline -ForegroundColor Cyan
							write-host "msiexec.exe /x $ProductID$NonCustomMSIParams"
						}
					}
                
				}
				#EXE
				else {
					$AppUninstallString = (($ver.UninstallString).ToString().tolower()).replace("`"", "")
					$seperator = [string[]]@(".exe")
					$ProductIDbase = $AppUninstallString.split($seperator, [System.StringSplitOptions]::RemoveEmptyEntries) 
                
					$AppUninstall = "`"" + $ProductIDbase[0] + ".exe`""

					if ($CustomEXEParams) {
						if ($RunUninstaller) {
							Start-Process -FilePath $AppUninstall -ArgumentList $CustomEXEParams
							Start-Sleep -Seconds 15
						}
						else {
							write-host "###" -ForegroundColor Green -NoNewline 
							write-host "$name" -ForegroundColor Cyan -NoNewline 
							write-host "###" -ForegroundColor Green
							write-host "Custom: " -NoNewline -ForegroundColor Cyan
							write-host "$AppUninstall $CustomEXEParams"
						}
					}
					else {
						$NonCustomEXEParams = $ProductIDbase[1]
						if ($RunUninstaller) {
							if ($null -eq $NonCustomEXEParams) {
								Start-Process -FilePath $AppUninstall
							}
							else {
								Start-Process -FilePath $AppUninstall -Argumentlist $NonCustomEXEParams
							}
							Start-Sleep -Seconds 15
						}
						else {
							write-host "###" -ForegroundColor Green -NoNewline 
							write-host "$name" -ForegroundColor Cyan -NoNewline 
							write-host "###" -ForegroundColor Green
							write-host "Non-Custom: " -NoNewline -ForegroundColor Cyan
							write-host "$AppUninstall$NonCustomEXEParams"
						}
					}
				}
			}
  }
  
$HKLMWoW64Key = Get-ChildItem -path HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\ -Recurse | Get-ItemProperty | Where-Object { $_.DisplayName -match $AppName } | Select-Object -Property DisplayName, UninstallString
$HKLMKey = Get-ChildItem -path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ -Recurse | Get-ItemProperty | Where-Object { $_.DisplayName -match $AppName } | Select-Object -Property DisplayName, UninstallString

if(!$RunUninstaller)
{
    Write-Host "Computer Uninstalls" -BackgroundColor White -ForegroundColor Red
    Write-Host "x86 Programs" -BackgroundColor Black -ForegroundColor Yellow
}
Uninstall($HKLMWoW64Key)

if(!$RunUninstaller)
{
    Write-Host "x64 Programs" -BackgroundColor Black -ForegroundColor Yellow
}
Uninstall($HKLMKey)

if(!$RunUninstaller)
{
    Write-Host "User Uninstalls" -BackgroundColor White -ForegroundColor Red
}

# Regex pattern for SIDs
$PatternSID = 'S-1-5-21-\d+-\d+\-\d+\-\d+$'
 
# Get Username, SID, and location of ntuser.dat for all users
$ProfileList = gp 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' | Where-Object {$_.PSChildName -match $PatternSID} | 
    Select-Object  @{name="SID";expression={$_.PSChildName}}, 
            @{name="UserHive";expression={"$($_.ProfileImagePath)\ntuser.dat"}}, 
            @{name="Username";expression={$_.ProfileImagePath -replace '^(.*[\\\/])', ''}}
 
# Get all user SIDs found in HKEY_USERS (ntuder.dat files that are loaded)
$LoadedHives = Get-ChildItem Registry::HKEY_USERS | ? {$_.PSChildname -match $PatternSID} | Select @{name="SID";expression={$_.PSChildName}}
 
# Get all users that are not currently logged
$UnloadedHives = Compare-Object $ProfileList.SID $LoadedHives.SID | Select-Object @{name="SID";expression={$_.InputObject}}, UserHive, Username
 
# Loop through each profile on the machine

Foreach ($item in $ProfileList) {
    # Load User ntuser.dat if it's not already loaded
    IF ($item.SID -in $UnloadedHives.SID) {
        reg load HKU\$($Item.SID) $($Item.UserHive) | Out-Null
    }
 
    #####################################################################
    # Start Change
    #####################################################################

    $name=$item.Username
    
    if(!$RunUninstaller)
    {
        Write-Host "$name" -BackgroundColor Black -ForegroundColor Yellow
    }
    
    $UserKey = Get-ChildItem -path registry::HKEY_USERS\$($Item.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ -Recurse -ErrorAction SilentlyContinue | Get-ItemProperty | Where-Object { $_.DisplayName -match $AppName } | Select-Object -Property DisplayName, UninstallString
    if($null -ne $UserKey)
    {
        Uninstall($UserKey)
    }

    #####################################################################
    # End Change
    #####################################################################
 
    # Unload ntuser.dat        
    IF ($item.SID -in $UnloadedHives.SID) {
        ### Garbage collection and closing of ntuser.dat ###
        [gc]::Collect()
        reg unload HKU\$($Item.SID) | Out-Null
    }
}
   #>  
