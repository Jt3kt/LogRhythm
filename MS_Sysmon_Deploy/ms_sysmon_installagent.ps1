#Requires -Version 5.1
#Requires -RunAsAdministrator
# This script is designed to install the Microsoft Sysmon agent silently from an endpoint domain joined Windows device.
#
# Requirements: 
#  Script requires Sysmon executable files provided by Microsoft.
#   https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon
#
# Optional:
#  Sysmon configuration file.  Sample available from SwiftOnSecurity: https://github.com/SwiftOnSecurity/sysmon-config
# 
#
# Instructions:
#  Extract Sysmon to folder available to Powershell Execution resource.
#  Set the $Global:fileSource to the absolute folder path where the files are extracted.
#
# Sha256 hashes are genearted prior to transmitting to target host.    
#
# The copyFile function has been written to be standalone to support portability.
#
# Written by Jtekt 07 May 2018 
# https://github.com/Jtekt/LogRhythm
# Version 0.5
# Sample usage: 
#  Install and apply client configuration
# ms_sysmon_installagent.ps1 -computer COMPUTERNAME -srcConfig CONFIGNAME -installStagePath C:\temp\ms_sysmon 
#  Update client configuration
# ms_sysmon_installagent.ps1 -computer COMPUTERNAME -srcConfig CONFIGNAME -installStagePath C:\temp\ms_sysmon -force true
#
param (
    [Parameter(Mandatory=$true,Position=1)][string]$computer,
    [Parameter(Mandatory=$false,Position=2)][string]$srcConfig = 'sysmonconfig-export.xml',
    [Parameter(Mandatory=$false,Position=3)][string]$installStagePath = "C:\temp\ms_sysmon",
    [Parameter(Mandatory=$false,Position=4)][string]$installSys64 = $false,
    [Parameter(Mandatory=$false,Position=5)][string]$force = $false
)
#$fileSource = local installation file source folder.  Must be set to in order to operate.
$Global:fileSource = "C:\temp\ms_sysmon\"
$Global:serviceName = 'Sysmon'
$Global:serviceStatus = $null
$Global:installFileName = $null
$Global:installFileHash = $null
$Global:srcFileHash = $null
$Global:installStatus = $null
$Global:copyStatus = $null
$Global:serviceStatus = $false
$Global:installStatus = $false
$Global:OS_Arch = $null
$installStagePath = $installStagePath + "\"
$Global:installArguments = ' -accepteula -i '+$installStagePath+$srcConfig

trap [Exception] {
    write-error $("Exception: " + $_)
    exit 1
}

if($debugMode -eq 1){$DebugPreference = "Continue"}else{$DebugPreference = "SilentlyContinue"}

#Identifies source installation files and generates source hashes for file validation.
Function identifyInstallFIle {
    try{ 
        $Global:OS_Arch = Invoke-Command -ComputerName $computer -scriptBlock {[environment]::Is64BitOperatingSystem} -ErrorAction Stop
    }
    catch{
        Write-host "Unable to determine 32/64bit OS status on $computer.`n$($Error[0].Exception.Message)"
        exit 1
        #continue
    }
    if ($Global:OS_Arch -eq $true){
        if ($installSys64 -eq $true){
            $Global:installFileName = Get-ChildItem -Path $Global:fileSource Sysmon64.exe
            #Create sha256
            $Global:installFileHash = Get-FileHash $Global:fileSource$Global:installFileName -Algorithm SHA256
            Write-Verbose $Global:installFileName" and temporary "$Global:installFileHash" created."
        }
        else{
            #32 Bit set to install.
            $Global:installFileName = Get-ChildItem -Path $Global:fileSource Sysmon.exe
            #Create sha256
            $Global:installFileHash = Get-FileHash $Global:fileSource$Global:installFileName -Algorithm SHA256
            Write-Verbose $Global:installFileName" and temporary "$Global:installFileHash" created."
        }
    }
    elseif ($Global:OS_Arch -eq $false){
        #32 Bit
        $Global:installFileName = Get-ChildItem -Path $Global:fileSource Sysmon.exe
        #Create sha256
        $Global:installFileHash = Get-FileHash $Global:fileSource$Global:installFileName -Algorithm SHA256
        Write-Verbose $Global:installFileName" and temporary "$Global:installFileHash" created."
    }
    else {
        Write-Host "Unable to determine destination system architecture."
    }
    $Global:srcFileHash = Get-FileHash $Global:fileSource$srcConfig -Algorithm SHA256
}

Function copyFile{
    Param(
        [Parameter(Mandatory=$true, position=1)]
        $filename,
        [Parameter(Mandatory=$true, position=2)]
        $target,
        [Parameter(Mandatory=$true, position=3)]
        $srcPath,
        [Parameter(Mandatory=$true, position=5)]
        $destPath,
        [Parameter(Mandatory=$false, position=6)]
        $fileHash,
        [Parameter(Mandatory=$false, position=7)]
        $fileForce
    )
    $fullPath = $destPath+$filename
    #Establish connection to target.
    try{ 
        $Session = New-PSSession -ComputerName $target -ErrorAction Stop
    }
    catch{
        Write-host "Unable to establish New-PSSession to $target.`n$($Error[0].Exception.Message)"
        exit 1
    }
    #Begin existing file/folder structure check & file verification.
    #Verify target directory
    try{ 
        $dirstatus = Invoke-Command -ComputerName $target -scriptBlock {Test-Path $args -PathType Container} -ArgumentList $destPath -ErrorAction Stop
    }
    catch{
        Write-host "Error while attempting to verify installation directory.`n$($Error[0].Exception.Message)"
        exit 1
    }
    if ($dirstatus -eq $false) {
        Write-Verbose "Creating target directory $destPath on $target."
        try{ 
            Invoke-Command -ComputerName $target -scriptBlock {New-Item -Path $args -type Directory -Force} -ArgumentList $destPath -ErrorAction Stop
			Start-Sleep .5
        }
        catch{
            Write-host "Error while attempting to create directory $destPath.`n$($Error[0].Exception.Message)"
            exit 1
        }
    }
    else{
        Write-Verbose "Directory existed.  Checking for install file."
        Write-Verbose "Checking for $fullPath"
        try{ 
            $filestatus = Invoke-Command -ComputerName $target -scriptBlock {Test-Path $args[0] -PathType Leaf} -ArgumentList $fullPath -ErrorAction Stop
        }
        catch{
            Write-host "Error while checking for $fullPath.`n$($Error[0].Exception.Message)"
            exit 1
        }
        Write-Verbose "File status is $filestatus."    
    }
    if ($filestatus -eq $true){
        Write-Verbose "$filename found on $target under $destPath."
        try{
            if ($fileForce -eq $true){
                #Begin verifying remote hash
                try{ 
                    $remoteOrigHash = Invoke-Command -ComputerName $target -scriptBlock {Get-FileHash $args -Algorithm SHA256} -ArgumentList $fullPath -ErrorAction Stop
                }
                catch{
                    Write-host "Error while attempting to retrieve sha256 hash for $fullPath.`n$($Error[0].Exception.Message)"
                    exit 1
                }
                Copy-Item -Path $srcPath$filename -Destination $destPath$filename -ToSession $session -ErrorAction Stop -Force
                Start-Sleep 8
                try{ 
                    $remoteFileHash = Invoke-Command -ComputerName $target -scriptBlock {Get-FileHash $args -Algorithm SHA256} -ArgumentList $fullPath -ErrorAction Stop
                }
                catch{
                    Write-host "Error while attempting to retrieve sha256 hash for $fullPath.`n$($Error[0].Exception.Message)"
                    exit 1
                }
                #Verify destination file has been altered.
                if ($remoteOrigHash -ne $remoteFileHash){
                    #Verify origin file hash exists.
                    if ($fileHash){
                        #Compare origin file hash vs updated destination file.
                        if ($fileHash.hash -eq $remoteFileHash.hash){
                            Write-Host "Copied $filename and hash verified."
                            $Global:copyStatus = $true
                        }
                        else{
                            Write-Host "Copied $filename hash mismatch.  Cleanup target destination folder and re-run."
                            $Global:copyStatus = $false
                            exit 1
                        }
                    }
                }
            } 
        }
        catch{
            Write-host "Error while attempting to copy $filename to $destPath.`n$($Error[0].Exception.Message)"
            exit 1
        }
    }
    else {
        try{
            Copy-Item -Path $srcPath$filename -Destination $destPath$filename -ToSession $session -ErrorAction Stop
            Start-Sleep 8
        }
        catch{
            Write-host "Error while attempting to copy $filename to $destPath.`n$($Error[0].Exception.Message)"
            exit 1
        }
        #Begin verifying remote hash
        try{ 
            $remoteFileHash = Invoke-Command -ComputerName $target -scriptBlock {Get-FileHash $args -Algorithm SHA256} -ArgumentList $fullPath -ErrorAction Stop
        }
        catch{
            Write-host "Error while attempting to retrieve sha256 hash for $fullPath.`n$($Error[0].Exception.Message)"
            exit 1
        }
        if ($fileHash){
            if ($fileHash.hash -eq $remoteFileHash.hash){
                Write-Host "Copied $filename and hash verified."
                $Global:copyStatus = $true
            }
            else{
                Write-Host "Copied $filename hash mismatch.  Cleanup target destination folder and re-run.`nIf attempting to update client config add -force true to command."
                $Global:copyStatus = $false
                exit 1
            }
        }
    }
}



#Function is responsible for executing the MS Sysmon install silently.
Function installApp {
    if ($Global:installStatus -eq $true)
    {
        Write-Host $Global:serviceName" is already installed."
    }
    else {
        if ($Global:copyStatus -eq $true)
        {
            Write-Verbose "Install initiating."
            try{ 
                $newproc = Invoke-WmiMethod -class Win32_process -name Create -ArgumentList ("cmd.exe /C start /MIN "+$installStagePath+$installFileName+$installArguments) -ComputerName $computer -ErrorAction Stop
                Write-Verbose $installStagePath$installFileName$installArguments
            }
            catch{
                Write-host "Error while attempting kick off installation process.`n$($Error[0].Exception.Message)"
                exit 1
            }
            if ($newproc.ReturnValue -eq 0 ) 
            { 
                Write-Verbose "Command invoked sucessfully." 
                #This sleep may need to be tuned for your environment based on maximum time observed installing on target hosts.
                Start-Sleep 1
                $Global:installStatus = $true
            }
        }
        elseif ( $Global:copyStatus -eq $false ) 
        {
            Write-Host "File copy interrupted.  Aborting install."
            Exit 1
        }
    }
}

#Function is responsible for updating MS Sysmon config.
Function updateConfig {
    if ($Global:installStatus -eq $true)
    {
        if ($Global:copyStatus -eq $true)
        {
            Write-Host "Update config initiating."
            try{ 
                $newproc = Invoke-WmiMethod -class Win32_process -name Create -ArgumentList ("cmd.exe /C start /MIN "+$installStagePath+$installFileName+" -c "+$installStagePath+$srcConfig) -ComputerName $computer -ErrorAction Stop
                Write-Verbose $installStagePath$installFileName" -c "$installStagePath$srcConfig
            }
            catch{
                Write-host "Error while attempting kick off config update process.`n$($Error[0].Exception.Message)"
                exit 1
                #continue
            }
            if ($newproc.ReturnValue -eq 0 ) 
            { 
                Write-Host "Update config invoked sucessfully." 
                #This sleep may need to be tuned for your environment based on maximum time observed installing on target hosts.
                Start-Sleep 1
                $Global:installStatus = $true
            }
        }
        elseif ( $Global:copyStatus -eq $false ) 
        {
            Write-Host "File copy interrupted.  Aborting configuration update."
            Exit 1
        }
    }
}

#Function to identify status of MS Sysmon Agent service.
Function serviceStatus {
    try{ 
        $servstat = Invoke-Command -ComputerName $computer -scriptBlock {Get-Service Sysmon | Select-Object status} -ErrorAction Stop
    }
    catch{
        Write-Verbose "Error while attempting identify $Global:serviceName service status.`n$($Error[0].Exception.Message)"
        $Global:serviceStatus = $false
        $Global:installStatus = $false
    }
    if ($servstat -like '*Running*'){
        $Global:serviceStatus = $true
        $Global:installStatus = $true
        Write-Host $Global:serviceName" is running on $computer."
    }
    elseif ($servstat -like '*Stopped*') {
        $Global:serviceStatus = $false
        $Global:installStatus = $true
        Write-Verbose $Global:serviceName" not running on "$computer"."
    }
    else{
        $Global:serviceStatus = $false
        $Global:installStatus = $false
        Write-Host $Global:serviceName" not installed on "$computer"."
    }
}

#Function starts MS Sysmon Agent service and sets to start Automatically.
Function serviceStart {
    serviceStatus
    if ($Global:installStatus -eq $true){
        if ($Global:serviceStatus -eq $false){
            if ($installSys64 -eq $true){
                Write-Host "Starting "$Global:serviceName" on "$computer"."
                try{ 
                    Invoke-Command -ComputerName $computer -scriptBlock {Start-Service Sysmon64} -ErrorAction Stop
                }
                catch{
                    Write-host "Error while attempting to start Sysmon64 service.`n$($Error[0].Exception.Message)"
                    Exit 1
                }
                Start-Sleep -Seconds .5
                if ($Global:serviceStatus = $true) {
                    try{ 
                        Invoke-Command -ComputerName $computer -scriptBlock {Set-Service Sysmon64 -StartupType Automatic} -ErrorAction Stop
                    }
                    catch{
                        Write-host "Error while attempting to set automatic starting on Sysmon64 service.`n$($Error[0].Exception.Message)"
                        Exit 1
                    }
                    Write-Host $Global:serviceName" set to start automatically."
                }
                else{
                    Write-Host $Global:serviceName" did not start successfully."
                }        
            }
            if ($installSys64 -eq $false){
                Write-Host "Starting "$Global:serviceName" on "$computer"."
                try{ 
                    Invoke-Command -ComputerName $computer -scriptBlock {Start-Service Sysmon} -ErrorAction Stop
                }
                catch{
                    Write-host "Error while attempting to start Sysmon service.`n$($Error[0].Exception.Message)"
                    Exit 1
                }
                Start-Sleep -Seconds .5
                if ($Global:serviceStatus = $true) {
                    try{ 
                        Invoke-Command -ComputerName $computer -scriptBlock {Set-Service Sysmon -StartupType Automatic} -ErrorAction Stop
                    }
                    catch{
                        Write-host "Error while attempting to set automatic starting on Sysmon service.`n$($Error[0].Exception.Message)"
                        Exit 1
                    }
                    Write-Host $Global:serviceName" set to start automatically."
                }
                else{
                    Write-Host $Global:serviceName" did not start successfully."
                }
            }
            else {
                Write-Host "Destination system architecture not defined."
            }      
        }
        elseif($Global:serviceStatus -eq $true){
            Write-Host $Global:serviceName" started successfully."
            try{ 
                Invoke-Command -ComputerName $computer -scriptBlock {Set-Service Sysmon -StartupType Automatic} -ErrorAction Stop
            }
            catch{
                Write-host "Error while attempting to set automatic starting on Sysmon service.`n$($Error[0].Exception.Message)"
                Exit 1
            }
            Write-Host $Global:serviceName" set to start automatically."
        }
    }
}

serviceStatus
identifyInstallFIle
Write-Verbose "file status is $Global:installStatus"
if ($Global:installStatus -eq $true) {
    #Update Sysmon configuration file.
    copyFile $srcConfig $computer $Global:fileSource $installStagePath $Global:srcFileHash $force
    updateConfig
    if ($Global:serviceStatus = $false) {
        serviceStart
    }
}
elseif ($Global:installStatus -eq $false) {
    copyFile $Global:installFileName $computer $Global:fileSource $installStagePath $Global:installFileHash $force
    copyFile $srcConfig $computer $Global:fileSource $installStagePath $Global:srcFileHash $force
    installApp
    serviceStart
}
Exit 0