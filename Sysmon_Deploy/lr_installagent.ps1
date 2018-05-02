#Requires -Version 5.1
#Requires -RunAsAdministrator
#This script is designed to uninstall the LogRhythm System Monitor Agent silently from an endpoint domain joined Windows device.
#
# Requirements: 
#  Script requires Sysmon executable files and .sha256 files provided by support.logrhythm.com.
#
# Instructions:
#  Extract LRWindowSystemMonitorAgents to folder available to Powershell Execution resource.
#  Set  the $Global:fileSource to the absolute folder path where the files are extracted.  Be sure to include the .sha256 hash files.
#
# Sysmon agents are validated prior to deployment and again prior to initiating install on remote host.  
# First check is to validate install source is un-modified from LogRhythm.
# Second check is to validate install file was successfully transferred to target host.
#
# Written by Jtekt 09 April 2018 
# https://github.com/Jtekt/LogRhythm
# Version 1.2
# Sample usage: 
# lr_installagent.ps1 -computer COMPUTERNAME -installAddLocal System_Monitor|RT_FIM_DRIVER|ALL -serverHost IPADDR -serverPort PORT
#
param (
    [Parameter(Mandatory=$true,Position=1)][string]$computer,
    #InstallAddLocal options = ( System_Monitor | RT_FIM_DRIVER | ALL)
    [Parameter(Mandatory=$true,Position=2)][string]$installAddLocal = "ALL",
    [Parameter(Mandatory=$true,Position=3)][string]$serverHost = "10.0.0.1",
    [Parameter(Mandatory=$true,Position=4)][string]$serverPort = "443",
    [Parameter(Mandatory=$false,Position=5)][string]$installStagePath = "C:\temp\sysmon\",
    [Parameter(Mandatory=$false,Position=6)][string]$clientPort = "3333",  
    #Currently not used.
    [Parameter(Mandatory=$false,Position=7)][string]$force = $false,
    [Parameter(Mandatory=$false,Position=8)][string]$debug = $false
 )
#$fileSource = local installation file source folder.  Must be set to in order to operate.
$Global:fileSource = "C:\temp\sysmon\"
$Global:serviceName = "LogRhythm System Monitor Service"
$Global:serviceStatus = $null
$Global:installFileName = $null
$Global:installFileHash = $null
$Global:installStatus = $null
$Global:copyStatus = $null
$Global:installArguments = ' /s /v" /qn ADDLOCAL=' + $installAddLocal + ' HOST='+ $serverHost + ' SERVERPORT=' + $serverPort + '"'
$Global:serviceStatus = $false
$Global:installStatus = $false
$installStagePath = $installStagePath + "\"

trap [Exception] {
    write-error $("Exception: " + $_)
    exit 1
}


if($debugMode -eq 1){$DebugPreference = "Continue"}else{$DebugPreference = "SilentlyContinue"}

#Currently does not support 64Core.
Function identifyInstallFIle {
    try{ 
        $OS_Arch = Invoke-Command -ComputerName $computer -scriptBlock {[environment]::Is64BitOperatingSystem}
    }
    catch{
        Write-host "Unable to determine 32/64bit OS status on $computer.`n$($Error[0].Exception.Message)"
        exit 1
        #continue
    }
    if ($OS_Arch -eq $true){
        #64 Bit
        $Global:installFileName = Get-ChildItem -Path $Global:fileSource LRSystemMonitor_64_*.exe
        $Global:installFileHash = Get-ChildItem -Path $Global:fileSource LRSystemMonitor_64_*.exe.sha256
        Write-Verbose $Global:installFileName" and "$Global:installFileHash" found."
    }
    elseif ($OS_Arch -eq $false){
        #32 Bit
        $Global:installFileName = Get-ChildItem -Path $Global:fileSource LRSystemMonitor_7*.exe
        $Global:installFileHash = Get-ChildItem -Path $Global:fileSource LRSystemMonitor_7*.exe.sha256
    }
    else {
        Write-Host "Unable to determine destination system architecture."
    }
    #Begin local file hash validation.
    $fileHash = Get-FileHash $Global:fileSource$Global:installFileName -Algorithm SHA256
    [string]$sourceHash = Get-Content $Global:fileSource$Global:installFileHash -First 1
    if ($sourceHash -eq $fileHash.hash){
        Write-Verbose "Source file hashes match."
    }
    else{
        Write-Host "Source file hash mismatch.  Please verify install files are valid."
    }
}

Function installStatus {
    #Identify if service is installed on target host.
    try{ 
        $app = Get-WmiObject Win32_Product -ComputerName $computer | Where-Object { $_.name -eq $Global:serviceName }
    }
    catch{
        Write-host "Unable to determine if SCSM service is installed on $computer.`n$($Error[0].Exception.Message)"
        exit 1
        #continue
    }
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
    $fullPath = $installStagePath+$Global:installFileName
    #Establish connection to target.
    try{ 
        $Session = New-PSSession -ComputerName $computer
    }
    catch{
        Write-host "Unable to establish New-PSSession to $computer.`n$($Error[0].Exception.Message)"
        exit 1
        #continue
    }
    #Begin existing file/folder structure check & file verification.
    #Verify target directory
    try{ 
        $dirstatus = Invoke-Command -ComputerName $computer -scriptBlock {Test-Path $args -PathType Container} -ArgumentList $installStagePath
    }
    catch{
        Write-host "Error while attempting to verify installation directory.`n$($Error[0].Exception.Message)"
        exit 1
        #continue
    }
    if ($dirstatus -eq $false) {
        Write-Verbose "Creating target directory $installStagePath on $computer."
        try{ 
            Invoke-Command -ComputerName $computer -scriptBlock {New-Item -Path $args -type Directory -Force} -ArgumentList $installStagePath
			Start-Sleep .5
        }
        catch{
            Write-host "Error while attempting to create directory $installStagePath.`n$($Error[0].Exception.Message)"
            exit 1
            #continue
        }
    }
    else{
        Write-Verbose "Directory existed.  Checking for install file."
        Write-Verbose "Checking for $fullPath"
        try{ 
            $filestatus = Invoke-Command -ComputerName $computer -scriptBlock {Test-Path $args[0] -PathType Leaf} -ArgumentList $fullPath
        }
        catch{
            Write-host "Error while checking for $fullPath.`n$($Error[0].Exception.Message)"
            exit 1
            #continue
        }
        Write-Verbose "File status is $filestatus."    
    }
    if ($filestatus -eq $true){
        Write-Verbose "$installFileName found on $computer under $installStagePath."
    }
    else {
        try{ 
            Copy-Item -Path $Global:fileSource$installFileName -Destination $installStagePath$installFileName -ToSession $session
			Start-Sleep 120
        }
        catch{
            Write-host "Error while attempting to copy $installFileName to $installStagePath.`n$($Error[0].Exception.Message)"
            exit 1
            #continue
        }
        try{ 
            Copy-Item -Path $Global:fileSource$installFileHash -Destination $installStagePath$Global:installFileHash -ToSession $session
        }
        catch{
            Write-host "Error while attempting to copy $installFileHash to $installStagePath.`n$($Error[0].Exception.Message)"
            exit 1
            #continue
        }
    }
    #Begin verifying remote hash
    [string]$sourceHash = Get-Content $Global:fileSource$Global:installFileHash -First 1
    try{ 
        $remoteFileHash = Invoke-Command -ComputerName $computer -scriptBlock {Get-FileHash $args -Algorithm SHA256} -ArgumentList $fullPath
    }
    catch{
        Write-host "Error while attempting to retrieve sha256 hash for $fullPath.`n$($Error[0].Exception.Message)"
        exit 1
        #continue
    }
    if ($sourceHash -eq $remoteFileHash.hash){
        Write-Host "Copied $installFileName hash verified.  Proceeding to install."
        $Global:copyStatus = $true
    }
    else{
        Write-Host "Copied $installFileName hash mismatch.  Cleanup target destination folder and re-run."
        $Global:copyStatus = $false
    }
}

#Function is responsible for executing the System Monitor agent install silently.
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
            try{ 
                $newproc = Invoke-WmiMethod -class Win32_process -name Create -ArgumentList ("cmd.exe /C start /MIN "+$installStagePath+$installFileName+$installArguments) -ComputerName $computer 
            }
            catch{
                Write-host "Error while attempting kick off installation process.`n$($Error[0].Exception.Message)"
                exit 1
                #continue
            }
            if ($newproc.ReturnValue -eq 0 ) 
            { 
                Write-Verbose "Command invoked sucessfully." 
                #This sleep may need to be tuned for your environment based on maximum time observed installing on target hosts.
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

#Function to identify status of LogRhythm Sysmon Agent service.
Function serviceStatus {
    try{ 
        $servstat = Invoke-Command -ComputerName $computer -scriptBlock {Get-Service scsm | Select-Object status}
    }
    catch{
        Write-host "Error while attempting identify SCSM service status.`n$($Error[0].Exception.Message)"
        exit 1
        #continue
    }
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

#Function starts LogRhythm Sysmon Agent service and sets to start Automatically.
Function serviceStart {
    if ($Global:installStatus -eq $true){
        Write-Host "Starting "$Global:serviceName" on "$computer"."
        try{ 
            Invoke-Command -ComputerName $computer -scriptBlock {Start-Service scsm};
        }
        catch{
            Write-host "Error while attempting to start scsm service.`n$($Error[0].Exception.Message)"
            exit 1
            #continue
        }
        Start-Sleep -Seconds .5
        serviceStatus
        if ($Global:serviceStatus = $true) {
            try{ 
                Invoke-Command -ComputerName $computer -scriptBlock {Set-Service scsm -StartupType Automatic};
            }
            catch{
                Write-host "Error while attempting to set automatic starting on scsm service.`n$($Error[0].Exception.Message)"
                exit 1
                #continue
            }
            Write-Host $Global:serviceName" set to start automatically."
        }
        else{
            Write-Host $Global:serviceName" did not start successfully."
        }        
    }
}

#Function cleans up files deployed to host as part of carrying out installation.
Function cleanupFiles{
    if ($Global:installStatus -eq $true){
        try{ 
            $dirstatus = Invoke-Command -ComputerName $computer -scriptBlock {Test-Path $args -PathType Container} -ArgumentList $installStagePath
        }
        catch{
            Write-host "Error while attempting to verify installation directory.`n$($Error[0].Exception.Message)"
            exit 1
            #continue
        }
        Write-Verbose $dirstatus
        if ($dirstatus -eq $false) {
            Write-Verbose "No folder to cleanup."
        }
        else{
            Write-Host "Begin cleanup of $installStagePath"
            $fileList = Invoke-Command -ComputerName $computer -scriptBlock {Get-ChildItem -Path $args } -ArgumentList $installStagePath
            foreach ($file in $fileList){
                $fullpath = $installStagePath+$file
                try{
                    Invoke-Command -ComputerName $computer -scriptBlock {Remove-Item -Path $args } -ArgumentList $fullpath
                }
                catch{
                    Write-host "Error while deleting $fullpath on $computer.  Cleanup manually.`n$($Error[0].Exception.Message)"
                    exit 1
                    #continue
                }
                Write-Verbose "$fullpath successfully deleted."
            }
            try{
                Invoke-Command -ComputerName $computer -scriptBlock {Remove-Item -Path $args } -ArgumentList $installStagePath
            }
            catch{
                Write-host "Error while deleting $installStagePath on $computer.  Cleanup manually.`n$($Error[0].Exception.Message)"
                exit 1
                #continue
            }
            Write-Host "Deleted temporary install files stored at: $installStagePath.`nCleanup complete."
        }
    }
}

identifyInstallFIle
installApp
serviceStart
cleanupFiles
Exit 0
