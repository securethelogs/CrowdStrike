
<#

This aims to help with the Log4J hunt using CrowdStrikes RTR and Cast.exe: https://www.crowdstrike.com/blog/free-targeted-log4j-search-tool/
For More: https://securethelogs.com/2021/12/29/log4j-crowdstrike-rtr-script/
@Securethelogs

This uses PSFalcon: https://github.com/CrowdStrike/psfalcon/

#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)][string] $InFile
      )

if (-not($InFile.EndsWith(".txt"))){Throw "[!] InFile is not a txt file...!!"}
$Ids = @(Get-Content $InFile)

# This Needs To Match The Script Within RTR Scripts (Falcon Portal): Find-VulnerableLog4J
$CastLoc = "C:\Temp"
if ($CastLoc.EndsWith("\")){ $CastLoc = $CastLoc.TrimEnd("\")}


$Clientid = ""
$Csecret = ""

if ($Clientid -eq ""){Throw "[!] Please fill in the clientID ..."}
if ($Csecret -eq ""){Throw "[!] Please fill in the csecret ..."}

Request-FalconToken -client_id $clientid -ClientSecret $csecret

$Logo = @('

                          .------._ 
                    .-"""`-.<")    `-._ 
                   (.--. _   `._       `"---.__.-"
  RTR Cast.exe  -     `   `;"-.-"         "-    ._
                      .--"``   ""._      - "   .
                       `"""-.    `---"    ,
                             `\
                               `\      ."
                                 `". "
                                    `".   jgs

@Securethelogs / Using  https://github.com/CrowdStrike/psfalcon/ (I Do not Own)
')
$logo



foreach ($d in $Ids){

    $failedrtr = 0

    Write-Host "[*] Running on Host: $d"


    try{(Invoke-FalconRtr -Command put -Arguments cast.exe -HostIds $d).stdout} catch {
        Write-Host "[!] Failed To Connect To $d " -ForegroundColor Red
        $failedrtr = 1
    }
    Start-Sleep -Seconds 2

    if ($failedrtr -eq 0){
    
    # Using Move As Direct Drop Became Hit and Miss 
    Invoke-FalconRtr -Command mv -Arguments "C:\cast.exe $($CastLoc)\cast.exe" -HostIds $d | Out-Null
    (Invoke-FalconRtr -Command runscript -Arguments "-CloudFile='Find-VulnerableLog4J' -Timeout=9999" -HostIds $d -QueueOffline $true).stdout

    Write-Output ""
    Write-Host "RTR Commands Sent For:  $d" -ForegroundColor Green
    Start-Sleep -Seconds 2
    

    }
    
    Write-Output ""
}


