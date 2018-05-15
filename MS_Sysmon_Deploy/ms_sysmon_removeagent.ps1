#Requires -Version 5.1
#Requires -RunAsAdministrator
#This script is designed to uninstall the Microsoft Sysinternals Sysmon silently from an endpoint domain joined Windows device.
# Written by Jtekt 15 May 2018 
# Version 0.5
# Sample usage: 
# lr_removeagent.ps1 -computer COMPUTERNAME
param (
    [Parameter(Mandatory=$true,Position=1)][string]$computer
 )
$Global:serviceName = 'Sysmon'
$Global:serviceStatus = $null
$Global:installStatus = $null

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

Function removeApp {
    if ($Global:installStatus -eq $true){
        try{ 
            $newproc = Invoke-WmiMethod -class Win32_process -name Create -ArgumentList ("cmd.exe /C start /MIN sysmon -u") -ComputerName $computer -ErrorAction Stop
        }
        catch{
            Write-host "Error while attempting kick off config update process.`n$($Error[0].Exception.Message)"
            exit 1
            #continue
        }
        if ($newproc.ReturnValue -eq 0 ) 
        { 
            Write-Host "Uninstall invoked sucessfully." 
            #This sleep may need to be tuned for your environment based on maximum time observed installing on target hosts.
            Start-Sleep 1
            $Global:installStatus = $false
        }
    }
    else {
        Write-Host $Global:serviceName" not found on "$computer
    }
}

serviceStatus
removeApp