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
# Written by Jtekt 07 May 2018 
# https://github.com/Jtekt/LogRhythm
# Version 0.5
# Sample usage: 
# ms_sysmon_installagent.ps1 -computer COMPUTERNAME -srcConfig CONFIGNAME -installStagePath C:\temp\sysmon
#
param (
    [Parameter(Mandatory=$true,Position=1)][string]$computer,
    [Parameter(Mandatory=$false,Position=2)][string]$srcConfig = 'sysmonconfig-export.xml',
    [Parameter(Mandatory=$false,Position=3)][string]$installStagePath = "C:\temp\ms_sysmon",
    [Parameter(Mandatory=$false,Position=4)][string]$installSys64 = $false
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

#Function is responsible for copying source files to destination host
Function copyApp{
    #Function variables used for file validation.
    $fullPath = $installStagePath+$Global:installFileName
    $fullPath2 = $installStagePath+$srcConfig
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
        $dirstatus = Invoke-Command -ComputerName $computer -scriptBlock {Test-Path $args -PathType Container} -ArgumentList $installStagePath -ErrorAction Stop
    }
    catch{
        Write-host "Error while attempting to verify installation directory.`n$($Error[0].Exception.Message)"
        exit 1
        #continue
    }
    if ($dirstatus -eq $false) {
        Write-Verbose "Creating target directory $installStagePath on $computer."
        try{ 
            Invoke-Command -ComputerName $computer -scriptBlock {New-Item -Path $args -type Directory -Force} -ArgumentList $installStagePath -ErrorAction Stop
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
            $filestatus = Invoke-Command -ComputerName $computer -scriptBlock {Test-Path $args[0] -PathType Leaf} -ArgumentList $fullPath -ErrorAction Stop
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
            Copy-Item -Path $Global:fileSource$installFileName -Destination $installStagePath$installFileName -ToSession $session -ErrorAction Stop
            Start-Sleep 8
        }
        catch{
            Write-host "Error while attempting to copy $installFileName to $installStagePath.`n$($Error[0].Exception.Message)"
            exit 1
        }
        try{ 
            Copy-Item -Path $Global:fileSource$srcConfig -Destination $installStagePath$srcConfig -ToSession $session -ErrorAction Stop
            STart-Sleep 1
        }
        catch{
            Write-host "Error while attempting to copy $srcConfig to $installStagePath.`n$($Error[0].Exception.Message)"
            exit 1
        }
    }
    #Begin verifying remote hash
    try{ 
        $remoteFileHash = Invoke-Command -ComputerName $computer -scriptBlock {Get-FileHash $args -Algorithm SHA256} -ArgumentList $fullPath -ErrorAction Stop
    }
    catch{
        Write-host "Error while attempting to retrieve sha256 hash for $fullPath.`n$($Error[0].Exception.Message)"
        exit 1
    }
    try{ 
        $remoteFileHash2 = Invoke-Command -ComputerName $computer -scriptBlock {Get-FileHash $args -Algorithm SHA256} -ArgumentList $fullPath2 -ErrorAction Stop
    }
    catch{
        Write-host "Error while attempting to retrieve sha256 hash for $fullPath2.`n$($Error[0].Exception.Message)"
        exit 1
    }
    if ($Global:installFileHash.hash -eq $remoteFileHash.hash){
        Write-Verbose "Copied $installFileName hash verified."
        $Global:copyStatus = $true
    }
    else{
        Write-Host "Copied $installFileName hash mismatch.  Cleanup target destination folder and re-run."
        $Global:copyStatus = $false
        exit 1
    }
    if ($Global:srcFileHash.hash -eq $remoteFileHash2.hash){
        Write-Verbose "Copied $srcConfig hash verified."
        Write-Host "File copy complete.  Proceeding to install."
        $Global:copyStatus = $true
    }
    else{
        Write-Host "Copied $srcConfig hash mismatch.  Cleanup target destination folder and re-run."
        $Global:copyStatus = $false
        exit 1
    }
}

#Function is responsible for executing the MS Sysmon install silently.
Function installApp {
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
                #Write-Verbose "Invoke-WmiMethod -class Win32_process -name Create -ArgumentList (cmd.exe /C start /MIN +$installStagePath+$installFileName+$installArguments) -ComputerName $computer"
                Write-Verbose $installStagePath$installFileName$installArguments
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
                Start-Sleep -Seconds 10
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
        Write-Verbose $Global:serviceName" is running on "$computer"."
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



identifyInstallFIle
serviceStatus
installApp
serviceStart
Exit 0