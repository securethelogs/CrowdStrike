<#

This aims to help with the Log4J hunt using CrowdStrikes RTR and Cast.exe: https://www.crowdstrike.com/blog/free-targeted-log4j-search-tool/
For More: https://securethelogs.com/2021/12/29/log4j-crowdstrike-rtr-script/
@Securethelogs

This uses PSFalcon: https://github.com/CrowdStrike/psfalcon/

#>

#Global Variables

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)][string] $OutFolder,
    [Parameter(Mandatory=$true)][string] $InFile
      )

if (-not($InFile.EndsWith(".txt"))){Throw "[!] InFile is not a txt file...!!"}


$Clientid = ""
$Csecret = ""

$Dids = @()

$CastLoc = "C:\Temp"
if ($CastLoc.EndsWith("\")){ $CastLoc = $CastLoc.TrimEnd("\")}


if ($Clientid -eq ""){Throw "[!] Please fill in the clientID ..."}
if ($Csecret -eq ""){Throw "[!] Please fill in the csecret ..."}



Write-Output ""

Request-FalconToken -client_id $Clientid -ClientSecret $Csecret


$Logo = @('

                          .------._ 
                    .-"""`-.<")    `-._ 
                   (.--. _   `._       `"---.__.-"
  Get Cast Json -         `   `;"-.-"         "-    ._
                      .--"``   ""._      - "   .
                       `"""-.    `---"    ,
                             `\
                               `\      ."
                                 `". "
                                    `".   jgs

@Securethelogs / Using  https://github.com/CrowdStrike/psfalcon/ (I Do not Own)
')
$logo

# Format Check

if ($OutFolder.EndsWith("\")){ $OutFolder = $OutFolder.TrimEnd("\")}
if (Test-path $OutFolder){ Write-Host "[*] Folder Already Exists... Moving On"} else { New-Item -ItemType Directory $OutFolder | Out-Null}

Write-Output ""
Write-Host "[*] Running RTR Checks..." -ForegroundColor Yellow
Write-Output ""


$Ids = @(Get-Content $InFile)


foreach ($d in $Ids){

try {$searchjson =  Invoke-FalconRtr -Command filehash -Arguments "$($CastLoc)\cast_results.json" -HostIds $d -ErrorAction SilentlyContinue}catch{}

if ([String]($searchjson).stderr -like "*Check your filename*" -or $searchjson -eq $null){ Write-Host "No File Found: $d" -ForegroundColor Red
} else {
    Write-Host "File Found: $d" -ForegroundColor Green
    $Dids += $d 
    
}

}

# End of Search, Output for Backup
$Dids | Out-File "$OutFolder\AIDs_Backup.txt"

Write-Output ""
Write-Host "[*] Translating AIDs to Host..." -ForegroundColor Yellow
Write-Output ""


$Convd = @(Get-FalconHost -Ids $Dids)
$Convd | Export-Csv "$OutFolder\CS_RTR_Log4J_Hosts.csv"

$Convd | Format-Table hostname, machine_domain, last_seen, os_version, ou

Write-Output ""
Write-Host "[*] The Results Have Been Exported To: "
Write-Host "    - AID Backup: $OutFolder\AIDs_Backup.txt"
Write-Host "    - Hosts To Investigate: $OutFolder\CS_RTR_Log4J_Hosts.csv"

Write-Output ""


foreach ($c in $Convd){

$Failedrtr = 0

Write-Host "Running on $($c.hostname)" -ForegroundColor Blue

try{Invoke-FalconRtr -Command mv -Arguments "$($CastLoc)\cast_results.json $($CastLoc)\cast_results_$($c.hostname).json" -HostIds $c.device_id}catch{Write-Host "[*] Failed To Rename. May already have been moved" -ForegroundColor Yellow}
Start-Sleep -Seconds 3

try{$Init = Start-FalconSession -HostId $c.device_id -ErrorAction SilentlyContinue}catch{ Write-Host "Failed to connect to $c.hostname"; $Failedrtr = 1}
if ($Init -eq $null){$Failedrtr = 1}

if ($Failedrtr -eq 0){

Start-Sleep -Seconds 2

$Get = Invoke-FalconAdminCommand -SessionId $Init.session_id -Command get -Arguments "$($CastLoc)\cast_results_$($c.hostname).json"


Start-Sleep -Seconds 5

$Confirm = Confirm-FalconGetFile -SessionId $Init.session_id ; $Confirm

foreach ($con in $Confirm){

try{Receive-FalconGetFile -Sha256 $con.sha256 -SessionId $Init.session_id -Path "$OutFolder\cast_results_$($c.hostname).7z"} catch { Write-Host "[*] File Already Exists; Skipping...." -ForegroundColor Yellow}

}

}

Write-Output ""

}


$7z = "$env:ProgramFiles\7-Zip\7z.exe"

if(Test-Path $7z){

$uzq = Read-Host "Would you like to unzip all using 7Zip?"

if ($uzq -eq "y" -or $uzq -eq "yes"){

Write-Output ""
Write-Host "[*] Unzipping Downloaded Files ..." -ForegroundColor Yellow

Set-Alias 7z $7z

New-Item -ItemType Directory "$OutFolder\Extracted_Json" -ErrorAction SilentlyContinue | Out-Null

$fls = @((Get-ChildItem -Path $OutFolder -Exclude *.csv, *.txt -ErrorAction SilentlyContinue).FullName)

foreach ($i in $fls){

   7z x -o"$OutFolder\Extracted_Json\" $i -pinfected | Out-Null


}

Write-Output ""

if ((Get-ChildItem "$OutFolder\Extracted_Json\").count){ Write-Host "Files Extracted Here: $OutFolder\Extracted_Json\ " -ForegroundColor Green}


} else { Write-Host "[*] No 7Zip was found to auto unzip" -ForegroundColor Red}

}

Write-Output ""












