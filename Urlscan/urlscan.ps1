﻿#
# Author: JTekt
# November 2018
# Version 0.8
#
# URLScan.io SmartResponse  
#   
#
# .\URLScan.ps1 -key $urlscanAPI -link $splitLink
#
# Originally sourced from LogRhythm Community by: nielsvb
#  https://community.logrhythm.com/t5/SmartResponse/SRP-URLScan-io/ta-p/121220
#

[CmdLetBinding()]
param( 
    [string]$key,
    [string]$link
)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Mask errors
$ErrorActionPreference= 'continue'
$tmpFolder = Split-Path $MyInvocation.MyCommand.Path

#Request and load scan request results
$urlscanRequest = Invoke-WebRequest -Headers @{"API-Key" = "$key"} -Method Post ` -Body "{`"url`":`"$link`",`"public`":`"off`"}" -Uri https://urlscan.io/api/v1/scan/ ` -ContentType application/json
$urlscanRequest.RawContent | Out-File $tmpFolder\urlscanRequest.txt

#Find line skip
$lines = Get-Content $tmpFolder\urlscanRequest.txt
for ($i = 0; $i -le $lines.Length; $i++) {
    if ($lines[$i].Length -eq 0) {
        break
    }
}
$skip = $i + 1
$urlscanStatus = Get-Content $tmpFolder\urlscanRequest.txt | select -Skip $skip | ConvertFrom-Json

#Determine when scan has completed
DO
{
    Write-Verbose "Waiting for scan to complete"
    sleep 5
    try {
        $urlscanResultQuery = Invoke-WebRequest -Headers @{"API-Key" = "$apikey"} -Method Get ` -Uri $($urlscanStatus.api) ` -ContentType application/json
        $status = "200"
    } catch {
    $status =$_.Exception.Response.StatusCode.Value__
    }
} While ($status -eq "404" )

#Load scan results and populate variables
#This could be built out to retrieve additional information from the scan results.
$urlscanResultQuery.RawContent | Out-File $tmpFolder\urlscanAnalysis.txt
$urlscanResults = Get-Content $tmpFolder\urlscanAnalysis.txt | select -Skip $skip | ConvertFrom-Json

#Cleanup temporary files
Remove-Item -Path $tmpFolder\urlscanAnalysis.txt
Remove-Item -Path $tmpFolder\urlscanRequest.txt

#Set meaningful info
$scanTime = $urlscanResults.task.time
$scannedURL = $urlscanResults.task.url
$ssURL = $urlscanResults.task.screenshotURL
$repURL = $urlscanResults.task.reportURL
$malware = $urlscanResults.stats.malicious
$certIssuers = $urlscanResults.lists.certificates.issuer
$domains = $urlscanResults.lists.domains
$serverStats = $urlscanResults.stats.serverStats.Count

#Build display info
$status = "====INFO - URLSCAN====\r\nScanned Link`: $link"
if ( $serverStats -eq 0 ) {
    $status += "\r\nALERT: Website could not be scanned by urlscan.io\r\nScans from urlscan.io are based from Germany.  \r\nPossible geographical-ip or explicit urlscan.io blocked."
} else {
    $status += "\r\n\r\nScan Report`: $repURL\r\nURL Screenshot`: $ssURL"
}
if ($malware -gt 0 ) {
    $status += "\r\nALERT: Malware reported!"
}
if ( $certIssuers -imatch "Let's Encrypt" ) {
    $status += "\r\nALERT: Let's Encrypt Certificate Authority Detected!"      
}
if ( $certIssuers -imatch $domains ) {
    $status += "\r\nALERT: Self-Signed Certificate Detected!"      
}

#Present
$status += "\r\n\r\nScan Time: $scanTime\r\n====END - URLSCAN===="
Write-Host $status.Replace("\r\n","`r`n")
exit 0