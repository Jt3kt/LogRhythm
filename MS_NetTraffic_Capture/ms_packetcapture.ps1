#Requires -Version 5.1
#Requires -RunAsAdministrator
# This script is designed to remotely initiate a local network traffic capture on an endpoint Windows workstation device.
# Endpoint must have netsh available. 
#   
# To open/view the network capture use Microsoft Message Analyzer.  
#     https://www.microsoft.com/en-us/download/details.aspx?id=44226
#
# Written by Jtekt 18 May 2018 
# https://github.com/Jtekt/LogRhythm
# Version 0.3
# Sample usage: 
#  .\PAcketCapture.ps1 hostname.example.com 60 2000 c:\temp\ncap\
#
# PacketTrace function written by Adam Bertram
# https://gallery.technet.microsoft.com/scriptcenter/Start-and-Stop-a-Packet-cce358e8
# 
param (
    [Parameter(Mandatory=$true,Position=1)][string]$computer,
    [Parameter(Mandatory=$true,Position=2)][int]$duration = 60,
    [Parameter(Mandatory=$true,Position=3)][int]$maxFileSize = 2000,
    [Parameter(Mandatory=$false,Position=4)][string]$destPath = "C:\temp\",
    [Parameter(Mandatory=$false,Position=5)][string]$force = $false
 )
$Global:dateStamp = get-date -uformat "%Y%m%d-%H%M"
$destPath += $Global:dateStamp+'\'
$Global:fileName = "LR_Ncap_" + $dateStamp + ".etl"


Function Stage-Path{
    Param(
        [Parameter(Mandatory=$true, position=1)]
        $target,
        [Parameter(Mandatory=$true, position=2)]
        $destPath
    )
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
        Write-host "Error while attempting to create directory.`n$($Error[0].Exception.Message)"
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
        Write-Verbose "Directory existed."
    }
    Write-Verbose "Directory $destPath created on $target."
}


function Start-PacketTrace { 
<#     
    .SYNOPSIS 
        This function starts a packet trace using netsh. Upon completion, it will begin capture all 
        packets coming into and leaving the local computer and will continue to do do until 
        Stop-PacketCapture is executed. 
    .EXAMPLE 
        PS> Start-PacketTrace -TraceFilePath C:\Tracefile.etl 
 
            This example will begin a packet capture on the local computer and place all activity 
            in the ETL file C:\Tracefile.etl. 
     
    .PARAMETER TraceFilePath 
        The file path where the trace file will be placed and recorded to. This file must be an ETL file. 
         
    .PARAMETER Force 
        Use the Force parameter to overwrite the trace file if one exists already 
     
    .INPUTS 
        None. You cannot pipe objects to Start-PacketTrace. 
 
    .OUTPUTS 
        None. Start-PacketTrace returns no output upon success. 
#> 
    [CmdletBinding()] 
    [OutputType()] 
    param 
    ( 
        [Parameter(Mandatory=$true,Position=1)] 
        [ValidateNotNullOrEmpty()] 
        [ValidateScript({ Test-Path -Path ($_ | Split-Path -Parent) -PathType Container })] 
        [ValidatePattern('.*\.etl$')] 
        [string]$TraceFilePath,
        [Parameter(Mandatory=$true,Position=2)]
        [int]$mFileSize,
        [Parameter()] 
        [switch]$Force
    ) 
    begin { 
        Set-StrictMode -Version Latest 
        $ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop 
    } 
    process { 
        try { 
            if (Test-Path -Path $TraceFilePath -PathType Leaf) { 
                if (-not ($Force.IsPresent)) { 
                    throw "An existing trace file was found at [$($TraceFilePath)] and -Force was not used. Exiting.." 
                } else { 
                    Remove-Item -Path $TraceFilePath 
                } 
            } 
            $OutFile = "$PSScriptRoot\temp.txt" 
            $Process = Start-Process "$($env:windir)\System32\netsh.exe" -ArgumentList "trace start capture=yes persistent=no maxSize=$mFileSize tracefile=$TraceFilePath" -RedirectStandardOutput $OutFile -Wait -NoNewWindow -PassThru 
            if ($Process.ExitCode -notin @(0, 3010)) { 
                throw "Failed to start the packet trace. Netsh exited with an exit code [$($Process.ExitCode)]" 
            } else { 
                Write-Verbose -Message "Successfully started netsh packet capture. Capturing all activity to [$($TraceFilePath)]" 
            } 
        } catch { 
            Write-Error -Message "$($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" 
        } finally { 
            if (Test-Path -Path $OutFile -PathType Leaf) { 
                Remove-Item -Path $OutFile 
            }     
        } 
    } 
} 

 
function Stop-PacketTrace { 
<#     
    .SYNOPSIS 
        This function stops a packet trace that is currently running using netsh. 
    .EXAMPLE 
        PS> Stop-PacketTrace 
 
            This example stops any running netsh packet capture.     
    .INPUTS 
        None. You cannot pipe objects to Stop-PacketTrace. 
 
    .OUTPUTS 
        None. Stop-PacketTrace returns no output upon success. 
#> 
    [CmdletBinding()] 
    [OutputType()] 
    param 
    () 
    begin { 
        Set-StrictMode -Version Latest 
        $ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop 
    } 
    process { 
        try { 
            $OutFile = "$PSScriptRoot\temp.txt" 
            $Process = Start-Process "$($env:windir)\System32\netsh.exe" -ArgumentList 'trace stop' -Wait -NoNewWindow -PassThru -RedirectStandardOutput $OutFile 
            if ((Get-Content $OutFile) -eq 'There is no trace session currently in progress.'){ 
                Write-Verbose -Message 'There are no trace sessions currently in progress' 
            } elseif ($Process.ExitCode -notin @(0, 3010)) { 
                throw "Failed to stop the packet trace. Netsh exited with an exit code [$($Process.ExitCode)]" 
            } else { 
                Write-Verbose -Message 'Successfully stopped netsh packet capture' 
            } 
        } catch { 
            Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" 
        } finally { 
            if (Test-Path -Path $OutFile -PathType Leaf) { 
                Remove-Item -Path $OutFile 
            } 
        } 
    } 
} 



Write-Host $destPath$fileName
Stage-Path $computer $destPath
Invoke-Command -ComputerName $computer -ScriptBlock ${function:Start-PacketTrace} -ArgumentList $destPath$fileName,$maxFileSize
Start-Sleep -s $duration
Invoke-Command -ComputerName $computer -ScriptBlock ${function:Stop-PacketTrace}