#Requires -Version 4.0
#This script is designed to identify if a user is logged into a Windows Domain joined device.
#Determine the status of the current session as Logged In/Locked/Not Logged In
#Identify the active session and initiate a user logoff when the session is Locked.
# This function will return the logged-on status of a local or remote computer 
# Written by Jtekt 22 March 2018 
# Version 0.5
# Sample usage: 
# packetcapture.ps1 -computer COMPUTERNAME -duration DURINSECONDS -destinationpath EX:C:\temp\
# 
#Script adapted from PacketTrace script.
# PacketTrace function written by Adam Bertram
# https://gallery.technet.microsoft.com/scriptcenter/Start-and-Stop-a-Packet-cce358e8
# 
# 
param (
    [Parameter(Mandatory=$true)]
    [string]$computer,
    [Parameter(Mandatory=$true)] 
    $duration,
    [Parameter(Mandatory=$true)]
    [ValidateScript({ Test-Path -Path ($_ | Split-Path -Parent) -PathType Container })] 
    $destinationpath
 )
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
        [Parameter(Mandatory)] 
        [ValidateNotNullOrEmpty()] 
        [ValidateScript({ Test-Path -Path ($_ | Split-Path -Parent) -PathType Container })] 
        [ValidatePattern('.*\.etl$')] 
        [string]$TraceFilePath, 
     
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
            $Process = Start-Process "$($env:windir)\System32\netsh.exe" -ArgumentList "trace start capture=yes persistent=no maxSize=2000MB tracefile=$TraceFilePath" -RedirectStandardOutput $OutFile -Wait -NoNewWindow -PassThru 
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
#endregion function Start-PacketTrace 
 
#region function Stop-PacketTrace 
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



$DateStamp = get-date -uformat "%Y%m%d-%H%M"
$filename = "LR_Ncap_" + $DateStamp + ".etl"
#Default capture time
if ($duration -eq $NULL) {
    $duration = 60
}
if ($destinationpath -eq $NULL) {
    $destinationpath = "C:\temp\"
}

Invoke-Command -ComputerName $computer -ScriptBlock ${function:Start-PacketTrace} -ArgumentList $destinationpath$filename
Start-Sleep -s $duration
Invoke-Command -ComputerName $computer -ScriptBlock ${function:Stop-PacketTrace}