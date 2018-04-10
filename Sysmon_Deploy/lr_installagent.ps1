#Requires -Version 5.0
#Requires -RunAsAdministrator
#This script is designed to uninstall the LogRhythm System Monitor Agent silently from an endpoint domain joined Windows device.
#
# Script requires Sysmon.exe files and .sha256 files provided by support.logrhythm.com.
# Sysmon agents are validated prior to deployment and again prior to initiating install on remote host.  
# First check is to validate install source is un-modified from LogRhythm.
# Second check is to validate install file was successfully transferred to target host.
#
# Written by Jtekt 09 April 2018 
# Version 0.7
# Sample usage: 
# lr_installagent.ps1 -computer COMPUTERNAME -
param (
    [Parameter(Mandatory=$true,Position=1)][string]$computer,
    #InstallAddLocal options = ( System_Monitor | RT_FIM_DRIVER | ALL)
    [Parameter(Mandatory=$true,Position=2)][string]$installAddLocal = "ALL",
    [Parameter(Mandatory=$true,Position=3)][string]$lrServerAddress = "10.0.0.1",
    [Parameter(Mandatory=$true,Position=4)][string]$lrServerPort = "443",
    [Parameter(Mandatory=$false,Position=5)][string]$installDestPath = "C:\temp\sysmon\",
    [Parameter(Mandatory=$false,Position=6)][string]$installFileName = "LRSystemMonitor_64_7.2.6.8002.exe",
    [Parameter(Mandatory=$false,Position=7)][string]$force = $false
 )
$Global:serviceName = "LogRhythm System Monitor Service"
$Global:fileSource = "C:\temp\sysmon\"
$Global:serviceStatus = $null
$Global:installFileHash = $($installFileName)+".sha256"
$Global:installStatus = $null
$Global:copyStatus = $null
$Global:installArguments = ' /s /v" /qn ADDLOCAL=' + $installAddLocal + ' HOST='+ $lrServerAddress + ' SERVERPORT=' + $lrServerPort + '"'

Function installStatus {
    $app = Get-WmiObject Win32_Product -ComputerName $computer | Where-Object { $_.name -eq $Global:serviceName } 
        if ($app -eq $null){
            Write-Verbose $Global:serviceName" not found on "$computer
            $Global:installStatus = $false
        }
        else {
            Write-Verbose $Global:serviceName" recorded as "$app
            $Global:installStatus = $true
        }
    }

Function copyApp{
    $fileHash = Get-FileHash $Global:fileSource$installFileName -Algorithm SHA256
    $fullPath = $installDestPath+$installFileName
    [string]$sourceHash = Get-Content $Global:fileSource$Global:installFileHash -First 1
    if ($sourceHash -eq $fileHash.hash){
        Write-Verbose "Source file hashes match."
        #Establish connection to target.
        $Session = New-PSSession -ComputerName $computer
        #Begin existing file/folder structure check & file verification.
        #Verify target directory
        $dirstatus = Invoke-Command -ComputerName $computer -scriptBlock {Test-Path $args -PathType Container} -ArgumentList $installDestPath
        if ($dirstatus -eq $false) {
            Write-Verbose "Creating target directory $installDestPath on $computer."
            Invoke-Command -ComputerName $computer -scriptBlock {New-Item -Path $args -type Directory -Force} -ArgumentList $installDestPath
        }
        else{
            Write-Verbose "Directory existed.  Checking for install file."
            $filestatus = Invoke-Command -ComputerName $computer -scriptBlock {Test-Path $args[0] -PathType Leaf} -ArgumentList $fullPath
            Write-Verbose "File status is $filestatus."    
        }
        if ($filestatus -eq $true){
            Write-Verbose "$installFileName found on $computer under $installDestPath."
        }
        else {
            Copy-Item -Path $Global:fileSource$installFileName -Destination $installDestPath$installFileName -ToSession $session
            Copy-Item -Path $Global:fileSource$installFileHash -Destination $installDestPath$Global:installFileHash -ToSession $session
            Start-Sleep 120
        }
        #verify remote hash
        $remoteFileHash = Invoke-Command -ComputerName $computer -scriptBlock {Get-FileHash $args -Algorithm SHA256} -ArgumentList $fullPath
        if ($sourceHash -eq $remoteFileHash.hash){
            Write-Host "Copied $installFileName hash verified.  Proceeding to install."
            $Global:copyStatus = $true
        }
        else{
            Write-Host "Copied $installFileName hash mismatch.  Cleanup target destination folder and re-run."
            $Global:copyStatus = $false
        }

    }
    else {
        Write-Host "Install file hash does not match source hash on local file server." 

    }
}

Function installApp {
    installStatus
    if ($Global:installStatus -eq $true)
    {
        Write-Host $Global:serviceName" is already installed."
    }
    else {
        copyApp
        if ($Global:copyStatus -eq $true)
        {
            Write-Verbose "Install initiating."
            $newproc = Invoke-WmiMethod -class Win32_process -name Create -ArgumentList ("cmd.exe /C start /MIN "+$installDestPath+$installFileName+$installArguments) -ComputerName $computer 
            if ($newproc.ReturnValue -eq 0 ) 
            { 
                Write-Verbose "Command invoked sucessfully." 
                Start-Sleep -Seconds 150
                $Global:installStatus = $true
            }
        }
        elseif ( $Global:copyStatus -eq $false ) 
        {
            Write-Host "File copy interrupted.  Aborting install."
        }
    }
}

Function serviceStatus {
    $servstat = Invoke-Command -ComputerName $computer -scriptBlock {Get-Service scsm | Select-Object status}
    Write-Verbose $servstat
    if ($servstat -like '*Running*'){
        $Global:serviceStatus = $true
        Write-Host $Global:serviceName" is running on "$computer"."
    }
    elseif ($servstat -like '*Stopped*') {
        $Global:serviceStatus = $false
        Write-Host $Global:serviceName" not running on "$computer"."
    }
    else{
        $Global:serviceStatus = $false
        $Global:installStatus = $false
        Write-Host $Global:serviceName" not installed on "$computer"."
    }
}

Function serviceStart {
    if ($Global:installStatus -eq $true){
        Write-Host "Starting "$Global:serviceName" on "$computer"."
        Invoke-Command -ComputerName $computer -scriptBlock {Start-Service scsm};
        Start-Sleep -Seconds .5
        serviceStatus
        if ($Global:serviceStatus = $true) {
            Invoke-Command -ComputerName $computer -scriptBlock {Set-Service scsm -StartupType Automatic};
            Write-Host $Global:serviceName" set to start automatically."
        }
        else{
            Write-Host $Global:serviceName" did not start successfully."
        }        
    }
}
 
installApp
serviceStart
