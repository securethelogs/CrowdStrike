<# 
   API Guide: https://falcon.crowdstrike.com/documentation/46/crowdstrike-oauth2-based-apis
   Access Rights: Sandbox, Reports, IOCs. 
   Author: @securethelogs

Data - Sandbox variables: https://assets.falcon.crowdstrike.com/support/api/swagger.html#/falconx-sandbox/Submit
environment_id: Specifies the sandbox environment used for analysis. Values:

300: Linux Ubuntu 16.04, 64-bit
200: Android (static analysis)
160: Windows 10, 64-bit
110: Windows 7, 64-bit
100: Windows 7, 32-bit
sha256 ID of the sample, which is a SHA256 hash value. Find a sample ID from the response when uploading a malware sample or search with /falconx/queries/submissions/v1.The url parameter must be unset if sha256 is used.

url A web page or file URL. It can be HTTP(S) or FTP. The sha256 parameter must be unset if url is used.

action_script (optional): Runtime script for sandbox analysis. Values:

default
default_maxantievasion
default_randomfiles
default_randomtheme
default_openie
command_line (optional): Command line script passed to the submitted file at runtime. Max length: 2048 characters

document_password (optional): Auto-filled for Adobe or Office files that prompt for a password. Max length: 32 characters

enable_tor (optional): Deprecated, please use network_settings instead. If true, sandbox analysis routes network traffic via TOR. Default: false.

network_settings (optional): Specifies the sandbox network_settings used for analysis. Values:

default: Fully operating network
tor: Route network traffic via TOR
simulated: Simulate network traffic
offline: No network traffic
submit_name (optional): Name of the malware sample that's used for file type detection and analysis

system_date (optional): Set a custom date in the format yyyy-MM-dd for the sandbox environment

system_time (optional): Set a custom time in the format HH:mm for the sandbox environment.


#>


# -- Global --
$noauth = 0
$hashsuploaded = @()
$logfile = "C:\Temp\Sandbox_API_IDs.txt"
$sandboxids = @()
$fresh = 1
$file2chk = @()


# -- Falcon x --
$clientid = ""
$csecret = ""


# ---- logo -----

$Logo = @('

                          .------._ 
                    .-"""`-.<")    `-._ 
                   (.--. _   `._       `"---.__.-"
  On-Demand Scan -    `   `;"-.-"         "-    ._
                      .--"``   ""._      - "   .
                       `"""-.    `---"    ,
                             `\
                               `\      ."
                                 `". "
                                    `".   jgs

@Securethelogs / Crowdstrike API Script
')
$logo


# -- Get Client Details --

 $param = @{
    URI = 'https://api.crowdstrike.com/oauth2/token'
    Method = 'post'
    Headers = @{

        accept = 'application/json'
        'content-type' = 'application/x-www-form-urlencoded'
    
    }
    Body = "client_id=$clientid&client_secret=$csecret"


}

# -- Request Token --

$token = try { (Invoke-RestMethod @param).Access_Token; } catch { Write-Host "[!] Status: Failed to issue access token" -ForegroundColor Red ; $noauth = 1 }
if ($noauth -eq 0){

Write-Host "Status: " -NoNewline; Write-Host "Access Granted" -ForegroundColor Green

Write-Output "" 

Write-Host "Please select an option: 1. Hash Scan (Quick)  2. Sandbox Scan (Detailed)"
$options = Read-Host -Prompt "Option"
Write-Output ""


if ($options -eq 1){
  # Quick Hash Scan

  $hfile = Read-Host -Prompt "File Location"
  Write-Output ""


  if (Test-Path $hfile){

  $file2chk = @((Get-ChildItem $hfile | Where-Object {$_.Length -gt 1}).fullname) 

  foreach ($hb in $file2chk){

  Write-Host "Checking: $hb ..."

  $errc = 0

    $paramhash = @{
        URI = "https://api.crowdstrike.com/malquery/entities/metadata/v1?ids=$hb"
        Method = 'GET'
        Headers = @{
    
                Accept = 'application/json'
                Authorization = "Bearer $token"
    
                }


    } # Params 

$res = try { Invoke-RestMethod @paramhash } catch { $errc = 1; Write-Host "Not match found!" -ForegroundColor Yellow }

if ($errc -ne 1){
  
  Write-Host "[*] File was matched!" -ForegroundColor Red
  $res.resources

} 

  } 



} else { Write-Host "File path was incorrect!" -ForegroundColor Red } 


} # End Of Hash Scan


if ($options -eq 2){

if ((Test-Path $logfile) -and (Get-Content $logfile) -ne $null){

  Write-Host "[*] Previous File Detected !" -ForegroundColor Yellow
  Write-Output ""

  $rescan = Read-Host -Prompt "Would you like to check on previous sandbox reports? (Y/N)"

} 

if ($rescan -eq "Y"){

  $sandboxids = @(Get-Content $logfile)
  $fresh = 0
  
} else { 

 # Get Quota 

 $param = @{
  URI = "https://api.crowdstrike.com/falconx/entities/submissions/v1?ids="
  Method = 'GET'
  Headers = @{
          Authorization = "Bearer $token"  
          "Content-Type" = "application/json" 
          }

  }

$quota = (Invoke-RestMethod @param).meta.quota

$left = $quota.total - $quota.used
Write-Host "Sandbox API Quota: " -NoNewline

if ($left -ne 0){ Write-Host $left "/"$quota.total -ForegroundColor Green } else { Write-Host $left "/"$quota.total -ForegroundColor Red }

Write-Output ""

# Now run ....


$fileloc = Read-Host -Prompt "File Location"
if (Test-Path $fileloc){


$file2chk = @((Get-ChildItem $fileloc | Where-Object {$_.Length -gt 1}).fullname) 


foreach ($fle in $file2chk){

$filename = (Get-ItemProperty -path $fle).Name
$filecom = ($filename + "_api_upload")

$uri = "https://api.crowdstrike.com/samples/entities/samples/v2?file_name=" + $filename + "&comment=" + $filecom

# Upload File

Write-Host "Uploading File: $fle" -ForegroundColor Yellow #
Write-Output ""

$param = @{
    URI = $uri
    Method = 'POST'
    Headers = @{
            Authorization = "Bearer $token"
            'Content-Type' =  'application/octet-stream'
            }

    }

    $upld = Invoke-RestMethod @param -InFile $fle #

    if (($upld.resources.file_name) -eq $filename){

      $hash = $upld.resources.sha256
      $hashsuploaded += $hash
      $suc = 1
      Write-Host "Upload Successful ..." -ForegroundColor Green
      Write-Output ""

    } else { Write-Host "Failed to upload $fle..." -ForegroundColor Red; Write-Output ""; $suc = 0}
    

if ($suc -eq 1){

# uploaded file, time to submit -------

$data = ('
  {
    "sandbox": [{
        "sha256": "' + $hash + '",
        "environment_id": 100,
        "submit_name": "' + $filename + '"
    }]

}'
)

Write-Host "Submitting File: $filename..." -ForegroundColor Yellow

$param = @{
    URI = "https://api.crowdstrike.com/falconx/entities/submissions/v1"
    Method = 'POST'
    Headers = @{
            Authorization = "Bearer $token"  
            "Content-Type" = "application/json" 
            }
            Body = $data

    }

  $sf = Invoke-RestMethod @param

  $sf.resources | Format-List id, state, created_timestamp

  if (($sf.resources.state) -eq "created"){

    $sandboxids += $sf.resources.id

    Write-Host "Sandbox Started for $filename..." -ForegroundColor Yellow
    Write-Output ""
    
  }
 


} 
# End of successful upload


}
# End of Foreach file2chk

} else { Write-Host "[!] File/Folder not found..." -ForegroundColor Red}

} 
# End of FreshScan

Write-Host "[*] On average, fresh scans can take between 0 - 15 mins ..." 

# Get Results 

foreach ($sid in $sandboxids){

$param = @{
  URI = "https://api.crowdstrike.com/falconx/entities/submissions/v1?ids=$sid"
  Method = 'GET'
  Headers = @{
          Authorization = "Bearer $token"  
          "Content-Type" = "application/json" 
          }

  }

$gsb = Invoke-RestMethod @param
$state = $gsb.resources.state
$gsb.resources | Format-List id, state, created_timestamp


if ($fresh -eq 1){

Write-Host "[*] Creating temp file to store Sandbox IDs. They can be viewed here if the console closes: C:\Temp\Sandbox_API_IDs.txt"

if (Test-Path -Path $logfile){ 

} else { 

  New-Item -Path $logfile -Force | Out-Null

}

Add-Content -Path $logfile -Value $sid

}

Write-Output ""
Write-Host "Progress: " -NoNewline 

 while ($state -ne "Success"){ 

  $state = (Invoke-RestMethod @param).resources.state
  
  Start-Sleep -Seconds 60
  Write-Host "." -NoNewline -ForegroundColor ("Red", "Yellow", "Blue", "Green", "White" | Get-Random)
  
  }

# End of while loop = Finished

  $param = @{
    URI = "https://api.crowdstrike.com/falconx/entities/report-summaries/v1?ids=$sid"
    Method = 'Get'
    Headers = @{
            Authorization = "Bearer $token"  
            "Content-Type" = "application/json" 
            }

    }

  $mp = Invoke-RestMethod @param
  $report = $mp.resources.sandbox
  
  Write-Host "Results for: " -NoNewline; Write-Host $report.submit_name -ForegroundColor green

  $report 
  

  } 
  # foreach sid


} 
# Sandbox

} 
#auth'd

Write-Output ""
if (Test-Path -Path $logfile){ Remove-Item -Path $logfile -Force }