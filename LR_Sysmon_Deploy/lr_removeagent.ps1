#Requires -Version 4.0
#Requires -RunAsAdministrator
#This script is designed to uninstall the LogRhythm System Monitor Agent silently from an endpoint domain joined Windows device.
# Written by Jtekt 04 April 2018 
# Version 0.5
# Sample usage: 
# lr_removeagent.ps1 -computer COMPUTERNAME
param (
    [Parameter(Mandatory=$true,Position=1)][string]$computer,
    [Parameter(Mandatory=$false,Position=3)][string]$force = $false
 )
#Compared Username
$Global:app = $null
$Global:AppName = "LogRhythm System Monitor Service"
$Global:installStatus = $null


Function getAppInfo {
$Global:app = Get-WmiObject Win32_Product -ComputerName $computer | Where-Object { $_.name -eq $Global:AppName } 

## Debug code - Prints out identified Session ID
    if ($Global:app -eq $null){
#Debug:
        Write-Verbose $Global:AppName" not found on "$computer
        $Global:installStatus = $false
    }
    else {
#Debug:
        Write-Verbose $Global:AppName" recorded as "$Global:app
        $Global:installStatus = $true
    }
}

# Add logic to compare supplied application name and returned application name.
#Function compareAppInfo {
#    if ( -eq ){
#        $Global:UserCompare = 1
#    }
#    else {
#
#    }
#}

Function removeApp {
    if ($Global:installStatus -eq $true){
        $Global:app.Uninstall()
    }
    else {
        Write-Host $Global:AppName" not found on "$computer
    }
}
##1603 = product not uninstalled successfully.  

getAppInfo
removeApp