#=========================================================#
#                  365 SafeTracer                         #
#                   Version 1.0                           #
#                  Author: Jtekt                          #
#                   July 16 2019                          #
#=========================================================#
#
# Licensed under the MIT License. See LICENSE file in the project root for full license information.
#
#   
<#
    .SYNOPSIS
        Script designed to extend the use and availability of Office 365 Exchange capabilities.

    .DESCRIPTION
        Establishes authenticated connectivity to Office 365 PowerShell Exchange 365 center.  Supports the following
        capabilities available through the module:
            Get-URLTrace -> RecipientsList and/or URLList


    .INPUTS
        2) URL List.  Comma seperated list of URLs
        
        3) RecipientList.  Comma seperated list of e-mail addresses

        4) Username.  If being executed manually a prompt will be provided.

        5) Password.  If being executed manually a prompt will be provided.
         
        Optional - Update LogRhythm Case
        a) id. - ID should be equal to the LogRhythm Case ID #.

        b) LogRhythm Case API key - The Actions.xml should be updated to include the LogRhythm Case API key
        
        c) LogRhythm Web Console URL - The Actions.xml should be updated to include the LogRhythm Web Console URL

    .OUTPUTS
        The job status for the respective command function called.  For results of content searches go to: https://protection.office.com

    .EXAMPLE
        .\365_SafeTracer.ps1 -id 1104 
        .\365_SnCtroller.ps1 -id 1104 -urllist "http://example.com, https://example.com"
        .\365_SnCtroller.ps1 -urllist "http://example.com, https://example.com" -recipientlist "user1@example.com, user2@example.com, user3@example.com"
        
    
    .LINK
        https://outlook.office.com/
        https://logrhythm.com/
    
    .NOTES
        365 Exchange Permissions required:
            View-Only Recipients
            Message Tracking

#>
[CmdLetBinding()]
param( 
    [Parameter(Mandatory=$false,Position=1)][string]$recipientList,
    [Parameter(Mandatory=$false,Position=2)][string]$urlList,
    [Parameter(Mandatory=$false,Position=3)][string]$startDate,
    [Parameter(Mandatory=$false,Position=4)][string]$endDate,
    [Parameter(Mandatory=$false,Position=5)][string]$command,
    [Parameter(Mandatory=$false,Position=6)][string]$username,
    [Parameter(Mandatory=$false,Position=7)][string]$password,
    [Parameter(Mandatory=$false,Position=8)][string]$id,
    [Parameter(Mandatory=$false,Position=9)][string]$LogRhythmHost,
    [Parameter(Mandatory=$false,Position=10)][string]$caseAPIToken
)
# Mask errors
$ErrorActionPreference= 'continue'

$urls = $urlList.Split(', ',[System.StringSplitOptions]::RemoveEmptyEntries)
$recipients = $recipientList.Split(', ',[System.StringSplitOptions]::RemoveEmptyEntries)

try {
    if (-Not ($password)) {
        $cred = Get-Credential
    } Else {
        $securePass = ConvertTo-SecureString -string $password -AsPlainText -Force
        $cred = New-Object -typename System.Management.Automation.PSCredential -argumentlist $username, $securePass
    }

    $Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $cred -Authentication Basic -AllowRedirection
    Import-PSSession $Session -AllowClobber -DisableNameChecking | Out-Null
} Catch {
    Write-Error "365 Connection - Access Denied..."
    Exit 1
}


# SafeLink Trace
function SafeLinkTrace{
[CmdLetBinding()]
param(
    [Parameter(Mandatory=$false,Position=1)][System.Collections.ArrayList]$urls,
    [Parameter(Mandatory=$false,Position=2)][System.Collections.ArrayList]$recipients
)
if(!$startDate) {
    $startDate = Get-Date
}
if(!$endDate) {
    $endDate = (Get-Date).AddDays(-7)
}
$sltStatus = "`r`n== SmartResponse - 365 Safelink Trace ==`r`n"
if ($urls) {
    $sltStatus += "=- URL Report -=`r`nURL List:`r`n"
    $urls | ForEach-Object {
        $sltStatus += "$_`r`n"
    }
    $sltStatus += "`r`n"
    $urls | ForEach-Object {
        Write-Verbose "Inspecting URL: $_ startDate: $endDate endDate $startDate"
        $sluResults = Get-UrlTrace -UrlOrDomain "$_" -StartDate $endDate -EndDate $startDate
        $sltStatus += "`r`nTrace report for URL: `r`n$_`r`n"

        if ( $sluResults ) {
            $sluResults | ForEach-Object {
                $sltStatus += "Status: Clicked | Clicked On: $($_.Clicked) UTC | By recipient $($_.RecipientAddress)`r`n"
                Write-Verbose "URL: $($_.Url) Date: $($_.Clicked) UTC By recipient $($_.RecipientAddress)"
            }
        } else {
            $sltStatus += "No access recorded.`r`n`r`n"
            Write-Verbose "No access record for URL: $_"
        }
        $sluResults = $null
    }
    $sltStatus += "`r`n"
}
if ($recipients) {
    $sltStatus += "=- Recipient Report -=`r`nRecipient List:`r`n"
    $recipients | ForEach-Object {
        $sltStatus += "$_`r`n"
    }
    $sltStatus += "`r`n"
    for ($r = 0; $r -lt $recipients.Count; $r++) {
        Write-Verbose "Inspecting Recipient: $recipients[$r] startDate: $endDate endDate $startDate"
        $slrResults = Get-UrlTrace -RecipientAddress "$($recipients[$r])" -StartDate $endDate -EndDate $startDate
        $sltStatus += "Trace report for Recipient: $($recipients[$r])`r`n"
        if ( $slrResults ) {
            $($slrResults.Url) | Get-Unique | ForEach-Object {
                $slrClicked = $slrResults | Where-Object -Property "url" -contains "$_"
                $sltStatus += "URL: $_`r`n"
                $slrCount = $slrClicked | Measure-Object -Property "Clicked"
                for ($i = 0; $i -lt $($slrCount.Count); $i++) {
                    $sltStatus += "Clicked On: $($slrClicked[$i].Clicked) UTC`r`n"
                    Write-Verbose "URL: $($slrClicked[$i].Url) Date: $($slrClicked[$i].Clicked) UTC By recipient $($slrClicked[$i].RecipientAddress)"
                }
                $slrCount = $null
                $sltStatus += "`r`n"
            }
            $sltStatus += "`r`n"
        } else {
            $sltStatus += "No access records recorded.`r`n"
            Write-Verbose "No access record for recipient: $recipients[$r]"
        }
        $slrResults = $null
    }
}
$sltStatus += "SafeTrace Scope: $endDate - $startDate`r`nExecution Date: "+(Get-Date)
return "$sltStatus"
}

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
$output = Invoke-RestMethod -Uri $noteurl -Headers $headers -Method POST -Body $payload -verbose
}

$sltResults = SafeLinkTrace -urls $urls -recipients $recipients
if ( $id -and $caseAPIToken -and $LogRhythmHost) {
    $caseNotes = $sltResults.Replace("`r`n","\r\n")
    Update-Case -csNumber $id -LRHost $LogRhythmHost -csAPIToken $caseAPIToken -csNotes "$caseNotes"
    Write-Host $sltResults
} else {
    Write-Host $sltResults
}
Remove-PSSession $Session
Exit 0