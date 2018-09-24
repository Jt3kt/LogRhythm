#====================================#
#      Shodan SmartResponse          #
#         Version 1.5                #
#        Author: Jtekt               #
#====================================#
#
# Licensed under the MIT License. See LICENSE file in the project root for full license information.
#
#   
# Case update function borrowed from LogRhythm PIE Project 
#     https://github.com/LogRhythm-Labs/PIE
#

[CmdLetBinding()]
param( 
    [Parameter(Mandatory=$true,Position=1)][string]$key,
    [Parameter(Mandatory=$false,Position=2)][string]$targetHost,
    [Parameter(Mandatory=$false,Position=3)][string]$id,
    [Parameter(Mandatory=$false,Position=4)][string]$command,
    [Parameter(Mandatory=$false,Position=5)][string]$caseNumber,
    [Parameter(Mandatory=$false,Position=6)][string]$LogRhythmHost,
    [Parameter(Mandatory=$false,Position=7)][string]$caseAPIToken
)
# Mask errors
$ErrorActionPreference= 'continue'

# Global Parameters
# Validator regex expressions
$IPregex='(?<Address>((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))'
$FQDNregex='(?<fqdn>(https?:\/\/([\w_-]+((\.[\w_-]+)+))([\w.,@?^=%&:\/~+#-]*[\w@?^=%&\/~+#-])?))'
$MD5regex='(?<Hash>([a-f0-9]{32}))'
$SHA256regex='(?<Hash>([A-Fa-f0-9]{64}))'
# ================================================================================
# Retrieve Host information from Shodan
# ================================================================================
<#
    .SYNOPSIS
        Submits IP address to Shodan and returns Shodan scan results.

    .INPUTS
        1) Shodan API key
        
        2) Host FQDN or IP address. 

        Optional - Update LogRhythm Case
        a) LogRhythm Case API key
        
        b) LogRhythm Web Console URL

        c) Case # for result submission

    .OUTPUTS
        Host information as provided by Shodan.

    .EXAMPLE
        Writes results to current session.
        .\Shodan.ps1 -key "SHODAN-API-KEY" -targetHost "http://example.com" -command "info"

        Writes results to current session and sends to LogRhythm Case API, appending information as note into existing case.
        .\Shodan.ps1 -key "SHODAN-API-KEY" -targetHost "http://example.com" -command "info" -caseNumber "322" -LogRhythmHost "logrhythm.yourdomain.com:8501" -caseAPIToken "LOGRHYTHM-CASE-API-KEY"

    .LINK
        https://developer.shodan.io/api

    .NOTES
        Optional flags: 
          shodanHostDetails - Responsible for providing summary information.  Geographic location, ISP, Organization
          shodanSSLDetails - SSL certificate information for each detected service running SSL.  SSL based alerts will still be displayed if set to false.
          shodanMinecraftDetails - Provides server version, description, and player counts.
#>
function Host-Info{
[CmdLetBinding()]
param(
    [Parameter(Mandatory=$true)][string]$apiKey,
    [Parameter(Mandatory=$true)][string]$target
)

$shodanHostDetails = $true
$shodanSSLDetails = $true
$shodanGameDetails = $true

# Check if $host is IP or FQDN
$hostIP = $targetHost -match $IPregex
$hostFQDN = $targetHost -match $FQDNregex
if ( $hostIP -eq $true ) { 
    Write-Verbose "Host in IP address format"
    $shodanIP = $targetHost
} elseif ( $hostFQDN -eq $true ) { 
    # Query DNS and obtain domain IP address
    $splitLink = ([System.Uri]"$targetHost").Host
    try {
        $shodanIPQuery = Invoke-RestMethod "https://api.shodan.io/dns/resolve?hostnames=$splitLink&key=$key"
    } catch {
        $error =  $_ | Select-String "error"
        Write-Host $error
        Write-Host "Status Code: $($_.Exception.Response.StatusCode.value__)"
        Write-Host "Status Description: $($_.Exception.Response.StatusDescription)"
        $status = "== Shodan Scan Info ==\r\nError on API call\r\nStatus Code: $($_.Exception.Response.StatusCode.value__)\r\nStatus Description: $($_.Exception.Response.StatusDescription)"
        return "$status"
    }
    $shodanIPQuery | Where-Object -Property $splitLink -Match $IPregex
    $shodanIP = $Matches.Address
} else {
    echo "Error: Invalid URL or IP address format."
    Exit 1
}
$shodanLink = "https://www.shodan.io/host/$shodanIP"

# Query Shodan Host scan
try {
    $shodanHostInfo = Invoke-RestMethod "https://api.shodan.io/shodan/host/$shodanIP`?key=$key"
} catch {
    $error =  $_ | Select-String "error"
    Write-Host "== Shodan Scan Info =="
    Write-Host $error
    Write-Host "Status Code: $($_.Exception.Response.StatusCode.value__)"
    Write-Host "Status Description: $($_.Exception.Response.StatusDescription)"
    $status = "== Shodan Scan Info ==\r\nError on API call\r\nStatus Code: $($_.Exception.Response.StatusCode.value__)\r\nStatus Description: $($_.Exception.Response.StatusDescription)"
    return "$status"
}

#Determine Shodan services identified.
$shodanModules = $shodanHostInfo.data | Select-Object -ExpandProperty _shodan | Select-Object -ExpandProperty module
if ( $shodanHostDetails -eq $true ) {
    $status = "====INFO - SHODAN====\r\nInformation on $target`:$shodanIP\r\nReported location:\r\n Country: $($shodanHostInfo.country_name)"
    if ( $($shodanHostInfo.city) ) { $status += "\r\n City: $($shodanHostInfo.city)" } 
    if ( $($shodanHostInfo.region_code) ) { $status += "\r\n Region: $($shodanHostInfo.region_code)" }
    if ( $($shodanHostInfo.postal_code) ) { $status += "\r\n Postal: $($shodanHostInfo.postal_code)" }
    if ( $($shodanHostInfo.tags) ) { $status += "\r\n Detected tags: $($shodanHostInfo.tags)" }
    if ( $($shodanHostInfo.org) ) { $status += "\r\n Organization: $($shodanHostInfo.org)" }
    if ( $($shodanHostInfo.org) -ne $($shodanHostInfo.isp) ) {
        if ( $($shodanHostInfo.isp) ) { $status += "\r\n Internet Service Provider: $($shodanHostInfo.isp)" }
    }
}

#Break out and report on Shodan data
for($i=0; $i -le ($shodanHostInfo.data.Length-1); $i++){
    $status += "\r\n\r\n*** Service $($shodanHostInfo.data[$i]._shodan.module) ***"
    $status += "\r\nService Summary: $shodanIP`:$($shodanHostInfo.data[$i].port) $($shodanHostInfo.data[$i].transport.ToUpper())"
    if ( $($shodanHostInfo.data[$i].tags) ) { $status += "\r\nReported Tags: $($shodanHostInfo.data[$i].tags)" }
    if ( $($shodanHostInfo.data[$i].product) ) { $status += "\r\nDetected Product: $($shodanHostInfo.data[$i].product)" }
    if ( $($shodanHostInfo.data[$i].http.server) ) { $status += "\r\nHTTP Server: $($shodanHostInfo.data[$i].http.server)" }
    if ( $($shodanHostInfo.data[$i].version) ) { $status += "\r\nVersion: $($shodanHostInfo.data[$i].version)" }
    $error = $($shodanHostInfo.data[$i].data) | Select-String -Pattern "ssl error"
    if ( $error ){
        $status += "\r\n$($shodanHostInfo.data[$i].data)"
    }
    #Video game
    if ( $shodanGameDetails -eq $true) {
        #Minecraft
        if ( $shodanHostInfo.data[$i].product -eq "Minecraft" ) {
            $status += "\r\n-Minecraft Server Info-\r\n"
            $status += "\r\nServer Version: $($shodanHostInfo.data[$i].minecraft.version.name)"
            $status += "\r\nServer Description: $($shodanHostInfo.data[$i].minecraft.description)"
            $status += "\r\nMax Players: $($shodanHostInfo.data[$i].minecraft.players.max)"
            $status += "\r\nCurrent Players: $($shodanHostInfo.data[$i].minecraft.players.online)"
        }
        #Steam
        if ( $($shodanHostInfo.data[$i]._shodan.module) -eq "steam-a2s" ) {
            $status += "\r\n-Steam Server Info-\r\n"
            $status += $shodanHostInfo.data | Select-Object -ExpandProperty data
        }
    }
    #SSL
    if ( $shodanHostInfo.data[$i].ssl ){
        $shodanCert = $shodanHostInfo.data[$i] | Select-Object -ExpandProperty ssl
        if ( $shodanSSLDetails -eq $true) {
            $status += "\r\n\r\n-- SSL Certificate Observed --"
            $subject = $shodanCert.cert.subject -replace '[{}@]', ''
            $status += "\r\nCertificate Subject: $subject"
            $status += "\r\nCertificate SHA256: $($shodanCert.cert.fingerprint.sha256)"
            $issuer = $shodanCert.cert.issuer -replace '[{}@]', ''
            $status += "\r\nCertificate Issuer: $issuer"
            $status += "\r\nCertificate Issue date: $($shodanCert.cert.issued)"
            $status += "\r\nCertificate Expiration date: $($shodanCert.cert.expires)"
            $ciphers = $shodanCert.cipher -replace '[{}@]', ''
            $status += "\r\nSupported Ciphers: $ciphers\r\n"
        }
        if ( $($shodanCert.cert.expired) -eq $true ) {
            $status += "\r\nALERT: Expired Certificate Detected!"
        }
        if ( $($shodanCert.cert.issuer) -imatch "Let's Encrypt" ) {
            $status += "\r\nALERT: Let's Encrypt Certificate Authority Detected!"             
        } elseif ( $($shodanHostInfo.data[$i].tags) -imatch "self-signed" ) {
            $status += "\r\nALERT: Self Signed Certificate Detected!"
        }
    }
    #FTP
    if ( $shodanHostInfo.data[$i]._shodan.module -eq "ftp" ) {
        $status += "\r\nAnonymous Login: $($shodanHostInfo.data[$i].ftp.anonymous)"
    }   
}
$status += "\r\n\r\n**** End Service Summary ****"
$status += "\r\n\r\nLast scanned on $($shodanHostInfo.last_update).  Full details available here: $shodanLink."
Write-Host $status.Replace("\r\n","`r`n")
Return "$status"
}



# ================================================================================
# Shodan Scan Host
# ================================================================================
<#
    .SYNOPSIS
        Submits IP address to Shodan for Scheduling a Scan

    .INPUTS
        1) Shodan API key
        
        2) Host FQDN or IP address. 

        Optional - Update LogRhythm Case
        a) LogRhythm Case API key
        
        b) LogRhythm Web Console URL

        c) Case # for result submission

    .OUTPUTS
        Confirmation ID

    .EXAMPLE
        Writes results to current session.
        .\Shodan.ps1 -key "SHODAN-API-KEY" -targetHost "http://example.com" -command "scan"

        Writes results to current session and sends to LogRhythm Case API, appending information as note into existing case.
        .\Shodan.ps1 -key "SHODAN-API-KEY" -targetHost "http://example.com" -command "scan" -caseNumber "322" -LogRhythmHost "logrhythm.yourdomain.com:8501" -caseAPIToken "LOGRHYTHM-CASE-API-KEY"

    .LINK
        https://developer.shodan.io/api

    .NOTES
        The confirmation ID is required for retrieving Scan Status
#>
function Host-Scan{
[CmdLetBinding()]
param(
    [Parameter(Mandatory=$true)][string]$apiKey,
    [Parameter(Mandatory=$true)][string]$target
)
    # Start building parameters for REST Method invokation.
    $Params =  @{}
    $Params.add('Body', @{'ips'=$target})
    $Params.add('Method', 'Post')
    try {
        $ReturnedObject = Invoke-RestMethod -Uri "https://api.shodan.io/shodan/scan?key=$apiKey" @Params
    } catch {
        $error =  $_ | Select-String "error"
        Write-Host $error
        Write-Host "StatusCode: $($_.Exception.Response.StatusCode.value__)"
        Write-Host "StatusDescription: $($_.Exception.Response.StatusDescription)"
        $status = "== Shodan Host Scan ==\r\nError on API call\r\nStatus Code: $($_.Exception.Response.StatusCode.value__)\r\nStatus Description: $($_.Exception.Response.StatusDescription)"
        return "$status"
    }
    if ( $( $ReturnedObject.id) ) {
        Write-Host "Shodan Scan scheduled on target: $target"
        Write-Host "Scan ID: $($ReturnedObject.id)"
        $status = "== Shodan Host Scan ==\r\nShodan Scan scheduled on target: $target\r\nScan ID: $($ReturnedObject.id)"
        return "$status"
    }
}

# ================================================================================
# Shodan API Info
# ================================================================================
<#
    .SYNOPSIS
        Queries Shodan for current API key usage

    .INPUTS
        1) Shodan API key
        
    .OUTPUTS
        Current Shodan API usage

    .EXAMPLE
        Writes results to current session.
        .\Shodan.ps1 -key "SHODAN-API-KEY" -command "api-info"

    .LINK
        https://developer.shodan.io/api

    .NOTES
        Cannot be sent to LogRhythm case.
#>
function Api-Info{
[CmdLetBinding()]
param(
    [Parameter(Mandatory=$true)][string]$apiKey
)
    $ReturnedObject = Invoke-RestMethod -Uri "https://api.shodan.io/api-info?key=$apiKey"
    Write-Host "== Shodan API Info =="
    Write-Host "HTTPS: $($ReturnedObject.https)"
    Write-Host "Unlocked: $($ReturnedObject.unlocked)"
    Write-Host "Unlocked Left: $($ReturnedObject.unlocked_left)"
    Write-Host "Telnet: $($ReturnedObject.telnet)"
    Write-Host "Scan credits remaining: $($ReturnedObject.scan_credits)"
    Write-Host "Query credits remaining: $($ReturnedObject.query_credits)"
    Write-Host "`r`nAdditional details available at: https://developer.shodan.io/dashboard"
}


# ================================================================================
# Shodan Retrieve Scan Info
# ================================================================================
<#
    .SYNOPSIS
        Returns Shodan's Host scan status

    .INPUTS
        1) Shodan API key

        2) Shodan Scan ID
        
    .OUTPUTS
        Request scan status

    .EXAMPLE
        Writes results to current session.
        .\Shodan.ps1 -key "SHODAN-API-KEY" -command "api-info"

    .LINK
        https://developer.shodan.io/api

    .NOTES
        Possible return values: Submitting, Queue, Processing, Done
#>
function Scan-Status{
[CmdLetBinding()]
param(
    [Parameter(Mandatory=$true)][string]$apiKey,
    [Parameter(Mandatory=$true)][string]$idValue
)

    try {
        $returnedResult = Invoke-RestMethod "https://api.shodan.io/shodan/scan/$idValue`?key=$apiKey" -Method Get
    } catch {
        $error =  $_ | Select-String "error"
        Write-Host $error
        Write-Host "Status Code: $($_.Exception.Response.StatusCode.value__)"
        Write-Host "Status Description: $($_.Exception.Response.StatusDescription)"
        $status = "== Shodan Scan Status ==\r\nError on API call\r\nStatus Code: $($_.Exception.Response.StatusCode.value__)\r\nStatus Description: $($_.Exception.Response.StatusDescription)"
        return "$status"
    }
    if ( $returnedResult ) {
        Write-Host "Shodan Scan Status"
        Write-Host "Scan ID: $($returnedResult.id)"
        Write-Host "Scan Status: $($returnedResult.status)"
        Write-Host "Created date: $($returnedResult.created)"
        $status = "== Shodan Scan Status ==\r\nScan ID: $($returnedResult.id)\r\nScan Status: $($returnedResult.status)\r\n$($returnedResult.created)"
        return "$status"
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

if ( $command -eq "info" ) {
   $sdStatus = Host-Info $key $targetHost 
}

if ( $command -eq "scan" ) {
   $sdStatus = Host-Scan $key $targetHost 
}

if ( $command -eq "status" ) {
    $sdStatus = Scan-Status $key $id
}


if ( $command -eq "api-info" ) {
   Api-Info $key
}

if ( $caseNumber -and $caseAPIToken -and $LogRhythmHost) {
    Update-Case -csNumber $caseNumber -LRHost $LogRhythmHost -csAPIToken $caseAPIToken -csNotes "$sdStatus"
}