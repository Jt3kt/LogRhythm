#====================================#
#      Shodan SmartResponse          #
#         Version 0.7                #
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
        Submits IP address to Shodan and returns Shodan scan results.

    .DESCRIPTION


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


    .LINK
        https://developer.shodan.io/api

    .NOTES


    #>

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
$shodanHostDetails = $true
$shodanSSLDetails = $true

# ================================================================================
# Retrieve Host information from Shodan
# ================================================================================
function Host-Info{
[CmdLetBinding()]
param(
    [Parameter(Mandatory=$true)][string]$apiKey,
    [Parameter(Mandatory=$true)][string]$target
)


# Check if $host is IP or FQDN
    if ( $target ) {
        $hostIP = $targetHost -match $IPregex
        $hostFQDN = $targetHost -match $FQDNregex
        Write-Verbose $hostIP
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
            $shodanLink = "https://www.shodan.io/host/$shodanIP"
            Write-Verbose $shodanLink
        } else {
            echo "Error: Invalid URL or IP address format."
            Exit 1
        }

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
        $shodanScanDate = $shodanHostInfo.last_update
        $shodanCountry = $shodanHostInfo.country_name
        $shodanRegion = $shodanHostInfo.region_code
        $shodanCity = $shodanHostInfo.city
        $shodanPostal = $shodanHostInfo.postal_code
        $shodanPorts = $shodanHostInfo.ports
        $shodanTags = $shodanHostInfo.tags

        #Determine Shodan services identified.
        $shodanModules = $shodanHostInfo.data | Select-Object -ExpandProperty _shodan | Select-Object -ExpandProperty module
        if ( $shodanHostDetails -eq $true ) {
            $shodanStatus = "====INFO - SHODAN====\r\nInformation on $link`:$shodanIP.\r\nReported location:\r\n Country: $shodanCountry"
            if ( $shodanCity ) { $shodanStatus += "\r\n City: $shodanCity" } 
            if ( $shodanRegion ) { $shodanStatus += "\r\n Region: $shodanRegion" }
            if ( $shodanPostal ) { $shodanStatus += "\r\n Postal: $shodanPostal" }
            if ( $shodanTags ) { $shodanStatus += "\r\nDetected tags: $shodanTags" }
            $shodanStatus += "\r\nLast scanned on $shodanScanDate."
            Write-Host "====INFO - SHODAN====`r`nInformation on $targetHost`: $shodanIP`r`nReported location:`r`n Country: $shodanCountry"
            if ( $shodanCity ) { Write-Host " City: $shodanCity" } 
            if ( $shodanRegion ) { Write-Host " Region: $shodanRegion" }
            if ( $shodanPostal ) { Write-Host " Postal: $shodanPostal" }
            if ( $shodanTags ) { Write-Host "`r`nDetected tags: $shodanTags" }
        }

        #Break out and report on Shodan data
        for($i=0; $i -le ($shodanHostInfo.data.Length-1); $i++){
            Write-Host "`r`n*** Service $($shodanHostInfo.data[$i]._shodan.module) ***"
            Write-Host "Service Summary: $shodanIP`:$($shodanHostInfo.data[$i].port) $($shodanHostInfo.data[$i].transport.ToUpper())"
            if ( $($shodanHostInfo.data[$i].tags) ) { Write-Host "Reported Tags: $($shodanHostInfo.data[$i].tags)" }
            if ( $($shodanHostInfo.data[$i].product) ) { Write-Host "Detected Product: $($shodanHostInfo.data[$i].product)" }
            if ( $($shodanHostInfo.data[$i].http.server) ) { Write-Host "HTTP Server: $($shodanHostInfo.data[$i].http.server)" }
            $error = $shodanHostInfo.data[$i] | Select-String "error"
            if ( $error ){
                Write-Host $shodanHostInfo.data[$i].Data
            }
            if ( $shodanHostInfo.data[$i].ssl ){
                $shodanCert1 = $shodanHostInfo.data[$i] | Select-Object -ExpandProperty ssl
                $shodanCertSubject = $shodanCert1.cert.subject
                $shodanCertSHA256 = $shodanCert1.cert.fingerprint.sha256
                $shodanCertIssuer = $shodanCert1.cert.issuer
                $shodanCertIssued = $shodanCert1.cert.issued
                $shodanCertExpiration = $shodanCert1.cert.expires
                $shodanCertCiphers = $shodanCert1.cipher
                Write-Host "`r`n-- SSL Certificate Observed --"
                Write-Host "Certificate Subject: $shodanCertSubject"
                Write-Host "Certificate SHA256: $shodanCertSHA256"
                Write-Host "Certificate Issuer: $shodanCertIssuer"
                Write-Host "Certificate Issue date: $shodanCertIssued"
                Write-Host "Certificate Expiration: $shodanCertExpiration"
                Write-Host "Supported Ciphers: $shodanCertCiphers`r`n"
                if ( $shodanCert1.cert.expired -eq $true ) {
                    $shodanStatus = "ALERT: Expired Certificate Detected!"
                    Write-Host "ALERT: Expired Certificate Detected!"
                }
                if ( $shodanCertIssuer -imatch "Let's Encrypt" ) {
                    $shodanStatus = "ALERT: Let's Encrypt Certificate Authority Detected!"
                    Write-Host "ALERT: Let's Encrypt Certificate Authority Detected!"                   
                } elseif ( $shodanTags -imatch "self-signed" ) {
                    $shodanStatus = "ALERT: Self Signed Certificate Detected!"
                    Write-Host "ALERT: Self Signed Certificate Detected!"
                }
                Write-Host "-- End SSL Observation --"
            }
            if ( $i -eq ($shodanHostInfo.data.Length-1) ) {
                Write-Host "`r`n*** End Service Summary ***"
            }
        }
        Write-Host "`r`nLast scanned on $shodanScanDate.  Full details available here: $shodanLink."
    }
}


# ================================================================================
# Shodan Scan Host
# ================================================================================
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
   Host-Info $key $targetHost 
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