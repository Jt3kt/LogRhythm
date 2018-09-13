#====================================#
#     Wildfire SmartResponse         #
#         Version 0.8                #
#        Author: Jtekt               #
#====================================#
#
# Licensed under the MIT License. See LICENSE file in the project root for full license information.
#
#   
# Case update borrowed from Greg Foss / PIE Project 
#     https://github.com/LogRhythm-Labs/PIE
#

<#
    .SYNOPSIS
        Submits SHA256 hashes to Palo Alto wildfire and returns results to session.

    .DESCRIPTION


    .INPUTS
        1) Wildfire API key
        
        2) SHA256 hash or full file path.  Executing user must have permissions to read file.

        Optional - Update LogRhythm Case
        a) LogRhythm Case API key
        
        b) LogRhythm Web Console URL

        c) Case # for result submission

    .OUTPUTS
        Wildfire verdict for supplied hash.

    .EXAMPLE
        Compares $fileHash to $fullPath file's hash and submits to Wildfire upon match.  Results returned to session.
        .\SR_Wildfire.ps1 -key "axkjd93jkdlkjsdf93jklsdf" -fileHash "66AF58FCACE2613657510B44D6100D6B017EA9EBF969C243B1511FED00F3DC49" -fullPath "\\yourhost.example.com\c$\temp\OpenMe.pdf"

        Generates SHA256 hash for OpenMe.xlsx and submits to Wildfire.  Results returned to session.
        .\SR_Wildfire.ps1 -key "axkjd93jkdlkjsdf93jklsdf" -fullPath "S:\myshares\myfolders\temp\OpenMe.xlsx"

        Submits supplied hash to Wildfire.  Results returned to session and to LogRhythm case #322.
        .\SR_Wildfire.ps1 -key "axkjd93jkdlkjsdf93jklsdf" -fileHash "66AF58FCACE2613657510B44D6100D6B017EA9EBF969C243B1511FED00F3DC49" -caseNumber "322" -LogRhythmHost "lrwebconsole.com:8501" -caseAPIToken "jyEhbcGiOjISzUI1NiIsin5Rc5I6IkpXVCJ9"


    .LINK
        https://www.paloaltonetworks.com/documentation/80/wildfire/wf_api

    .NOTES
        Accepts raw SHA256 hash or generates SHA256 hash for specified file.  Submitted hash formats are validated.  
        If both hash and file are specified a comparison is made to ensure they match.

        Results are printed out to session.  

        If supplied with LogRhythm caseNumber, LogRhythmHost, and API token this information is added as a note to the supplied case.

        A translation from Case Number to Case ID occurs to support the evidence/note call.

    #>

[CmdLetBinding()]
param( 
    [Parameter(Mandatory=$true,Position=1)][string]$key,
    [Parameter(Mandatory=$false,Position=2)][string]$fileHash,
    [Parameter(Mandatory=$false,Position=3)][string]$fullPath,
    [Parameter(Mandatory=$false,Position=4)][string]$caseNumber,
    [Parameter(Mandatory=$false,Position=5)][string]$LogRhythmHost,
    [Parameter(Mandatory=$false,Position=6)][string]$caseAPIToken
)
# Mask errors
$ErrorActionPreference= 'continue'

# Global Parameters
# Validator regex expressions
$MD5regex='(?<Hash>([a-f0-9]{32}))'
$SHA256regex='(?<Hash>([A-Fa-f0-9]{64}))'

# ================================================================================
# If a hash has been provided, check against regex
# ================================================================================
if ( $fileHash ) {
    $hashValidate = $fileHash -match $SHA256regex
    if ( $hashValidate -eq $true ) { 
        Write-Verbose "Hash format valid." 
    } else { 
        Write-Host "Invalid hash format supplied.  Please check hash and re-submit."
        exit 1 
    }
}

# ================================================================================
# If a file path has been provided, determine hash and populate variables.  
# Compares hashes if both $fileHash and $fullPath supplied.
# ================================================================================

if ( $fullPath ) {
    $tempHash = Get-FileHash $fullPath -Algorithm SHA256
    if ( $fileHash ) {
        if ($fileHash -eq $tempHash.hash){
            Write-Verbose "Provided hash and file hashes match."
        }
        else{
            Write-Host "Provided file hash and Path file hash mismatch.  Please verify and resubmit."
            exit 1
        }
    }
    $fileName = Split-Path $tempHash.Path -leaf
    $fileHash = $tempHash.hash
    Write-Verbose "File Name:$fileName File Hash:$fileHash "
}

# ================================================================================
# Lookup info and print info
# ================================================================================
if ( $fileHash ) {
    #Get verdict - single lookup
    [xml]$wfQuery = Invoke-WebRequest -uri "https://wildfire.paloaltonetworks.com/publicapi/get/verdict" -Method Post -Body "apikey=$key;hash=$fileHash;format=xml"
    $wfVerdict = $wfQuery.wildfire.'get-verdict-info'.verdict
    switch ( $wfVerdict )
    {
        -103{
            #-103 Invalid hash code submitted
            Write-Verbose "Invalid hash value submitted to Palo Alto Wildfire."
            
            $wfStatus = "====ERROR - WILDFIRE====\r\nInvalid Hash format supplied.\r\n\r\nWildfire Information:\r\n"
            if ( $fileName ) { $wfStatus += " File Name: $fileName\r\n" }
            $wfStatus += " File SHA256: $fileHash\r\n\r\nPlease check the hash format and manually submit at: https://wildfire.paloaltonetworks.com/."

            Write-Output "Palo Alto Wildfire Results`r`n"
            if ( $fileName ) { Write-Output "Submitted file: $fileName`r`n" }
            Write-Output "Submitted hash: $fileHash`r`n"
            Write-Output "Wildfire Verdict: Invalid Hash Format Reported"
        }
        -102{
            #-102 Record not in database
            Write-Verbose "Hash value not found within Palo Alto Wildfire database." 
            
            $wfStatus = "====INFO - WILDFIRE====\r\nWildfire has no data on submitted hash.\r\n\r\nWildfire Information:\r\n"
            if ( $fileName ) { $wfStatus += " File Name: $fileName\r\n" }
            $wfStatus += " File SHA256: $fileHash\r\n\r\nSubmit file for Wildfire analyis at: https://wildfire.paloaltonetworks.com/."

            Write-Output "Palo Alto Wildfire Results`r`n"
            if ( $fileName ) { Write-Output "Submitted file: $fileName`r`n" }
            Write-Output "Submitted hash: $fileHash`r`n"
            Write-Output "Wildfire Verdict: Hash not found within Wildfire database"
        }
        -101{
            #-101 Error occurred with Palo Alto Wildfire API
            Write-Verbose "An error occurred within the Wildfire API." 

            $wfStatus = "====ERROR - WILDFIRE====\r\nWildfire has encountered an API error.\r\n\r\nWildfire Information:\r\n"
            if ( $fileName ) { $wfStatus += " File Name: $fileName\r\n" }
            $wfStatus += " File SHA256: $fileHash\r\n\r\nRe-check file status at later time."

            Write-Output "Palo Alto Wildfire Results`r`n"
            if ( $fileName ) { Write-Output "Submitted file: $fileName`r`n" }
            Write-Output "Submitted hash: $fileHash`r`n"
            Write-Output "Wildfire Verdict: An internal API error has been returned"
        }
        -100{
            #-100 Hash is currently pending
            Write-Verbose "Submitted hash value is currently pending evaluation."

            $wfStatus = "====INFO - WILDFIRE====\r\nWildfire has reported status pending.\r\n\r\nWildfire Information:"
            if ( $fileName ) { $wfStatus += " File Name: $fileName\r\n" }
            $wfStatus += " File SHA256: $fileHash\r\n\r\nRe-check file status at later time."
            
            Write-Output "Palo Alto Wildfire Results`r`n"
            if ( $fileName ) { Write-Output "Submitted file: $fileName`r`n" }
            Write-Output "Submitted hash: $fileHash`r`n"
            Write-Output "Wildfire Verdict: Status Pending"
        }
        0{
            #0 FIle identified as benign
            Write-Verbose "Submitted hash value is confirmed benign."
            
            $wfStatus = "====INFO - WILDFIRE====\r\nWildfire has reported status benign.\r\n\r\n"
            if ( $fileName ) { $wfStatus += " File Name: $fileName\r\n" }
            $wfStatus += " File SHA256: $fileHash"
            
            Write-Output "Palo Alto Wildfire Results`r`n" 
            if ( $fileName ) { Write-Output "Submitted file: $fileName`r`n" }
            Write-Output "Submitted hash: $fileHash`r`n" 
            Write-Output "Wildfire Verdict: File Benign" 
        }
        1{
            #1 File identified as malware
            Write-Verbose "Submitted hash value is confirmed as malware."
        }
        2{
            #2 File identified as grayware
            Write-Verbose "Submitted hash value is confirmed as grayware."
        }
        default{
            #Unknown error occurred
            Write-Verbose "An unknown error has occurred within Wildfire.ps1."
            
            $wfStatus = "====ERROR - WILDFIRE SCRIPT====\r\nAn unknown error has occurred.\r\n\r\nWildfire Information:\r\n"
            if ( $fileName ) { $wfStatus += " File Name: $fileName\r\n" } 
            $wfStatus += " File SHA256: $fileHash\r\n\r\nPlease check the hash format and manually submit at: https://wildfire.paloaltonetworks.com/."

            Write-Output "Palo Alto Wildfire Results`r`n" 
            if ( $fileName ) { Write-Output "Submitted file: $fileName `r`n" }
            Write-Output "Submitted hash: $fileHash `r`n"
            Write-Output "Wildfire Verdict: An unspecified error has occurred"
        }
    }
    if ( $wfVerdict -eq "1" -or $wfVerdict -eq "2" ) {
        [xml]$wfReport = Invoke-WebRequest -uri "https://wildfire.paloaltonetworks.com/publicapi/get/report" -Method Post -Body "apikey=$key;hash=$fileHash;format=xml"
        $wfMalware = $wfReport.wildfire.file_info.malware
        $wfFiletype = $wfReport.wildfire.file_info.filetype
        $wfFileMd5 = $wfReport.wildfire.file_info.md5
        $wfFileSha256 = $wfReport.wildfire.file_info.sha256
        $wfFileSize = $wfReport.wildfire.file_info.size
        $wfStatus = "====ALERT - WILDFIRE====\r\nMALICIOUS FILE DETECTED! Wildfire has reported Malware.\r\n\r\nWildfire Information:\r\n"
        if ( $fileName ) { $wfStatus += " File Name: $fileName\r\n" }
        $wfStatus += " File Type: $wfFiletype\r\n File MD5: $wfFileMd5\r\n File SHA256: $wfFileSha256\r\n File Size: $wfFileSize"
                
        Write-Output "Palo Alto Wildfire Results`r`n"
        if ( $fileName ) { Write-Output "Submitted file: $fileName`r`n" }
        Write-Output "Submitted hash: $fileHash`r`n"
        Write-Output "Wildfire Malware Verdict: $wfMalware`r`n"
        Write-Output "Wildfire returned hashes: MD5 $wfFileMd5 SHA256 $wfFileSha256`r`n"
        Write-Output "Wildfire Reported File Size: $wfFileSize`r`n" 
        Write-Output "Wildfire Reported File Type: $wfFiletype" 
    }
}

# ================================================================================
# Update Case function
# ================================================================================
function Update-Case{
[CmdLetBinding()]
param(
    [Parameter(Mandatory=$true)][string]$csNumber,
    [Parameter(Mandatory=$true)][string]$LRHost,
    [Parameter(Mandatory=$true)][string]$csAPIToken,
    [Parameter(Mandatory=$true)][string]$csNotes
)

# ================================================================================
# Case API - Ignore invalid SSL certification warning.  
# Can be removed if running valid cert on LR Web Console
# ================================================================================
add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

# ================================================================================
# If Case number is supplied stage content for LR Case API
# ================================================================================

$apiKey = "Bearer $csAPIToken"
$caseURL = "https://$LRHost/lr-case-api/cases"
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Content-type", "application/json")
$headers.Add("Authorization", $apiKey)
$headers.Add("Count", "100000")
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# REST Web Request to Lookup case ID from case Num
$caseID = Invoke-RestMethod -Uri $caseURL -Headers $headers -Method GET | ConvertTo-Json | ConvertFrom-Json | Select-Object -ExpandProperty value | Select-Object id,number | Where-Object number -CContains $csNumber | Select-Object id
$noteurl = $caseurl + "/$($caseID.id)/evidence/note"
# REST Web Request to Update the Case
$payload = "{ `"text`": `"$csNotes`" }"
$output = Invoke-RestMethod -Uri $noteurl -Headers $headers -Method POST -Body $payload
}

if ( $caseNumber -and $caseAPIToken -and $LogRhythmHost) {
    Update-Case -csNumber $caseNumber -LRHost $LogRhythmHost -csAPIToken $caseAPIToken -csNotes $wfStatus
}
exit 1