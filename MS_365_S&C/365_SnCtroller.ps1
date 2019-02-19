#=========================================================#
#      365 Security and Compliance Controller             #
#                   Version 1.5                           #
#                  Author: Jtekt                          #
#                 February 19 2019                        #
#=========================================================#
#
# Licensed under the MIT License. See LICENSE file in the project root for full license information.
#
#   
#
[CmdLetBinding()]
param( 
    [Parameter(Mandatory=$true,Position=1)][string]$id,
    [Parameter(Mandatory=$false,Position=2)][string]$sender,
    [Parameter(Mandatory=$false,Position=3)][string]$recipient,
    [Parameter(Mandatory=$false,Position=4)][string]$subject,
    [Parameter(Mandatory=$false,Position=5)][string]$attachmentName,
    [Parameter(Mandatory=$false,Position=6)][string]$command,
    [Parameter(Mandatory=$false,Position=7)][string]$username,
    [Parameter(Mandatory=$false,Position=8)][string]$password,
    [Parameter(Mandatory=$false,Position=6)][string]$LogRhythmHost,
    [Parameter(Mandatory=$false,Position=7)][string]$caseAPIToken
)
# Mask errors
$ErrorActionPreference= 'continue'


try {
    if (-Not ($password)) {
        $cred = Get-Credential
    } Else {
        $securePass = ConvertTo-SecureString -string $password -AsPlainText -Force
        $cred = New-Object -typename System.Management.Automation.PSCredential -argumentlist $username, $securePass
    }
    $Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://ps.compliance.protection.outlook.com/powershell-liveid/ -Credential $cred -Authentication Basic -AllowRedirection
    Import-PSSession $Session -AllowClobber > $null
} Catch {
    Write-Host "Access Denied..."
    Write-Host $_
    break;
}


function Purge{
[CmdLetBinding()]
param( 
    [Parameter(Mandatory=$true,Position=1)][string]$uid 
)
    $status += "====365 Security n Compliance Controller====\r\nName: $uid\r\n"
    New-ComplianceSearchAction -SearchName "$uid" -Purge -PurgeType SoftDelete -Confirm:$false
    $purgeStatus = Get-ComplianceSearchAction -Identity "$uid`_Purge"
    DO {
        sleep 4
        Write-Host "Job: $($purgeStatus.Name) Status: $($purgeStatus.Status)"
        $purgeStatus = Get-ComplianceSearchAction -Identity "$uid`_Purge"
        if ( $purgeStatus -eq $null) {
            $purgeStatus = "Failed"
        }
    } Until (($purgeStatus.Status -eq "Completed") -xor ($purgeStatus -eq "Failed") )
    if ($purgeStatus.Status -eq "Completed") {
        $status += "Type: Purge\r\nName: $($purgeStatus.Name)\r\nAction: $($purgeStatus.Action)\r\nRunBy: $($purgeStatus.RunBy)\r\nStatus: $($purgeStatus.Status)\r\nEnd Time: $($purgeStatus.JobEndTime)"
    }
    if ($purgeStatus -eq "Failed") {
        $status += "\r\nPurge Command failed."
    }
    return "$status"
}

function Search{
[CmdLetBinding()]
param( 
    [Parameter(Mandatory=$true,Position=1)][string]$uid,
    [Parameter(Mandatory=$false,Position=2)][string]$funcSender,
    [Parameter(Mandatory=$false,Position=3)][string]$funcRecipient,
    [Parameter(Mandatory=$false,Position=4)][string]$funcSubject,
    [Parameter(Mandatory=$false,Position=5)][string]$funcAttach
)
    $status = "====365 Security n Compliance Controller====\r\nName: $uid\r\n"
    if ( $funcSender -AND $funcRecipient -AND $funcSubject -AND $funcAttach ) {

        New-ComplianceSearch -name "$uid" -Description "LogRhythm SR $uid" -ContentMatchQuery "(from:$funcSender AND to:$funcRecipient AND subject=`"$funcSubject`" AND attachmentnames:$funcAttach)" -ExchangeLocation "All" -force
        $criteria = "\r\nCriteria:\r\nSubject: $funcSubject\r\nSender: $funcSender\r\nRecipient: $funcRecipient\r\nAttachment Name: $funcAttach\r\n"

    } elseif ( $funcSender -AND $funcRecipient -AND $funcSubject ) {

        New-ComplianceSearch -name "$uid" -Description "LogRhythm SR $uid" -ContentMatchQuery "(from:$funcSender AND to:$funcRecipient AND subject=`"$funcSubject`")" -ExchangeLocation "All" -force
        $criteria = "\r\nCriteria:\r\nSubject: $funcSubject\r\nSender: $funcSender\r\nRecipient: $funcRecipient\r\n"

    } elseif ( $funcSender -AND $funcSubject -AND $funcAttach ) {

        New-ComplianceSearch -name "$uid" -Description "LogRhythm SR $uid" -ContentMatchQuery "(from:$funcSender AND subject=`"$funcSubject`" AND attachmentnames:$funcAttach)" -ExchangeLocation "All" -force
        $criteria = "\r\nCriteria:\r\nSubject: $funcSubject\r\nSender: $funcSender\r\nAttachment Name: $funcAttach\r\n"

    } elseif ( $funcRecipient -AND $funcSubject -AND $funcAttach ) {

        New-ComplianceSearch -name "$uid" -Description "LogRhythm SR $uid" -ContentMatchQuery "(to:$funcRecipient AND subject=`"$funcSubject`" AND attachmentnames:$funcAttach)" -ExchangeLocation "All" -force
        $criteria = "\r\nCriteria:\r\nSubject: $funcSubject\r\nRecipient: $funcRecipient\r\nAttachment Name: $funcAttach\r\n"

    } elseif ( $funcSender -AND $funcSubject ) {

        New-ComplianceSearch -name "$uid" -Description "LogRhythm SR $uid" -ContentMatchQuery "(from:$funcSender AND subject=`"$funcSubject`")" -ExchangeLocation "All" -force
        $criteria = "\r\nCriteria:\r\nSubject: $funcSubject\r\nSender: $funcSender\r\n"

    } elseif ( $funcRecipient -AND $funcSubject )  {

        New-ComplianceSearch -name "$uid" -Description "LogRhythm SR $uid" -ContentMatchQuery "(to:`funcRecipient AND subject=`"$funcSubject`")" -ExchangeLocation "All" -force
        $criteria = "\r\nCriteria:\r\nSubject: $funcSubject\r\nRecipient: $funcRecipient\r\n"

    } elseif ( $funcRecipient -AND $funcSender  )  {

        New-ComplianceSearch -name "$uid" -Description "LogRhythm SR $uid" -ContentMatchQuery "(to:$funcRecipient AND from:$funcSender)" -ExchangeLocation "All" -force
        $criteria = "\r\nCriteria:\r\nSender: $funcSender\r\nRecipient: $funcRecipient\r\n"

    } elseif ( $funcSender -AND $funcAttach )  {

        New-ComplianceSearch -name "$uid" -Description "LogRhythm SR $uid" -ContentMatchQuery "(from:$funcSender AND attachmentnames:$funcAttach)" -ExchangeLocation "All" -force
        $criteria = "\r\nCriteria:\r\nSender: $funcSender\r\nAttachment Name: $funcAttach\r\n"

    } elseif ( $funcRecipient -AND $funcAttach )  {

        New-ComplianceSearch -name "$uid" -Description "LogRhythm SR $uid" -ContentMatchQuery "(to:$funcRecipient AND attachmentnames:$funcAttach)" -ExchangeLocation "All" -force
        $criteria = "\r\nCriteria:\r\nRecipient: $funcRecipient\r\nAttachment Name: $funcAttach\r\n"

    } elseif ( $funcSubject -AND $funcAttach )  {

        New-ComplianceSearch -name "$uid" -Description "LogRhythm SR $uid" -ContentMatchQuery "(subject=`"$funcSubject`" AND attachmentnames:$funcAttach)" -ExchangeLocation "All" -force
        $criteria = "\r\nCriteria:\r\nSubject: $funcSubject\r\nAttachment Name: $funcAttach\r\n"

    } elseif ( $funcSender  )  {

        New-ComplianceSearch -name "$uid" -Description "LogRhythm SR $uid" -ContentMatchQuery "(from:`"$funcSender`")" -ExchangeLocation "All" -force
        $criteria = "\r\nCriteria:\r\nSender: $funcSender\r\n"

    } elseif ( $funcSubject  )  {

        New-ComplianceSearch -name "$uid" -Description "LogRhythm SR $uid" -ContentMatchQuery "(subject=`"$funcSubject`")" -ExchangeLocation "All" -force
        $criteria = "\r\nCriteria:\r\nSubject: $funcSubject\r\n"

    } elseif ( $funcAttach ) {

        New-ComplianceSearch -name "$uid" -Description "LogRhythm SR $uid" -ContentMatchQuery "(attachmentnames:$funcAttach)" -ExchangeLocation "All" -force
        $criteria = "\r\nCriteria:\r\nAttachment Name: $funcAttach\r\n"

    } else {

        $criteria = "\r\nCriteria:\r\nNo criteria provided.\r\n"

    }

    Start-ComplianceSearch -Identity "$uid"
    #Start on returning audit search results
    $p1 = Get-ComplianceSearch -Identity "$uid"
    DO {
        sleep 15
        Write-Host "Job: $($p1.Name) Status: $($p1.Status)"
        $p1 = Get-ComplianceSearch -Identity "$uid"
        if ( $p1 -eq $null) {
            $p1 = "Failed"
        }
    } Until ( ($p1.Status -eq "Completed" ) -xor ($p1 -eq "Failed") )
    if ($($p1.Status) -eq "Completed") {
        $status += "Type: Search\r\nRunBy: $($p1.RunBy)\r\nStatus: $($p1.Status)\r\n$($criteria)\r\nEnd Time: $($p1.JobEndTime)"
        $status += "\r\nTo access results go to: https://protection.office.com/"
    }
    if ($p1 -eq "Failed") {
        $status += "\r\nSearch Command failed."
    }
    return "$status"
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





if ( $sender -OR $recipient -OR $subject -OR $attachmentName ) {
    #Search
    if ( $command -eq "Search" ) {
       Write-Host "ID: $id Sender: $sender Recipient: $recipient Subject: $subject Attachment: $attachmentName"
       $sdStatus = Search -uid $id -funcSender $sender -funcRecipient $recipient -funcSubject $subject -funcAttach $attachmentName | Select-Object -skip 1
        #Update LogRhythm case.
        if ( $id -and $caseAPIToken -and $LogRhythmHost) {
            Update-Case -csNumber $id -LRHost $LogRhythmHost -csAPIToken $caseAPIToken -csNotes "$sdStatus" 
        }

    }
    #Search and Purge
    if ( $command -eq "SnP" ) {
        $sdStatus = Search -uid $id -funcSender $sender -funcRecipient $recipient -funcSubject $subject -funcAttach $attachmentName | Select-Object -skip 1
        if ( $id -and $caseAPIToken -and $LogRhythmHost) {
            Update-Case -csNumber $id -LRHost $LogRhythmHost -csAPIToken $caseAPIToken -csNotes "$sdStatus" 
        }
        $pgStatus = Purge -uid $id | Select-Object -skip 1
        if ( $id -and $caseAPIToken -and $LogRhythmHost) {
            Update-Case -csNumber $id -LRHost $LogRhythmHost -csAPIToken $caseAPIToken -csNotes "$pgStatus" 
        }
    }
} elseif ( $command -eq "Purge" -And $id ) {
    #Purge
    $pgStatus = Purge -uid $id | Select-Object -skip 1
    if ( $id -and $caseAPIToken -and $LogRhythmHost) {
        Update-Case -csNumber $id -LRHost $LogRhythmHost -csAPIToken $caseAPIToken -csNotes "$pgStatus" 
    }
} else {
    # No command provided.  Close out session and exit.
    Write-Host "Please provide a search criteria."
    Remove-PSSession $Session
    Exit 1
}

Remove-PSSession $Session
Exit 0