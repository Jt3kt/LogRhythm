#Requires -Version 4.0
#Requires -RunAsAdministrator
#This script is designed to uninstall the LogRhythm System Monitor Agent silently from an endpoint domain joined Windows device.
# Written by Jtekt 09 April 2018 
# Version 0.5
# Sample usage: 
# lr_installagent.ps1 -computer COMPUTERNAME
param (
    [Parameter(Mandatory=$true,Position=1)][string]$computer,
    [Parameter(Mandatory=$false,Position=2)][string]$installDestPath = "C:\temp\sysmon\",
    [Parameter(Mandatory=$false,Position=3)][string]$installFileName = "LRSystemMonitor_64_7.2.6.8002.exe",
    [Parameter(Mandatory=$false,Position=4)][string]$installArguments = ' /s /v" /qn ADDLOCAL=ALL HOST=10.4.22.209 SERVERPORT=443"',
    [Parameter(Mandatory=$false,Position=5)][string]$autostart = $true,
    [Parameter(Mandatory=$false,Position=6)][string]$force = $false
 )
#Compared Username
$Global:serviceName = "LogRhythm System Monitor Service"
$Global:fileSource = "C:\temp\sysmon\"
$Global:serviceStatus = $null
$Global:installStatus = $null


#.\LRSystemMonitor_64_7.2.6.8002.exe /s /v" /qn ADDLOCAL=ALL HOST=10.4.22.209 SERVERPORT=443"


#Invoke-Command -ComputerName lieehart -scriptBlock {Set-Service scsm -StartupType Automatic};
Function installStatus {
    $app = Get-WmiObject Win32_Product -ComputerName $computer | Where-Object { $_.name -eq $Global:serviceName } 
    
    ## Debug code - Prints out identified Session ID
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
    Copy-Item -Path $Global:fileSource$Global:installFileName -Destination "\\$computer\$installDestPath$installFileName" -Verbose
}
Function installApp {
    installStatus
    if ($Global:installStatus -eq $true)
    {
        Write-Host $Global:serviceName" is already installed."
    }
    else {
        #copyApp
        Write-Verbose "Install initiating."
        $newproc = Invoke-WmiMethod -class Win32_process -name Create -ArgumentList ("cmd.exe /C start /MIN "+$installDestPath+$installFileName+$installArguments) -ComputerName $computer 
        if ($newproc.ReturnValue -eq 0 ) { 
            Write-Verbose " Comman invoked Sucessfully" 
            Start-Sleep -Seconds 60
            $Global:installStatus = $true
        }
    }
}

Function serviceStatus {
    $servstat = Invoke-Command -ComputerName $computer -scriptBlock {Get-Service scsm | Select-Object status}
    Write-Verbose $servstat
    if ($servstat -like '*Running*'){
        $Global:serviceStatus = $true
        Write-Verbose $Global:serviceName" is running on "$computer
    }
    elseif ($servstat -like '*Stopped*') {
        $Global:serviceStatus = $false
        Write-Verbose $Global:serviceName" not running on "$computer
    }
    else{
        $Global:serviceStatus = $false
        $Global:installStatus = $false
        Write-Verbose $Global:serviceName" not installed on "$computer
    }
}

Function serviceStart {
    if ($Global:installStatus -eq $true){
        Invoke-Command -ComputerName $computer -scriptBlock {Start-Service scsm};
        Start-Sleep -Seconds .5
        serviceStatus
        if ($Global:serviceStatus = $true) {
            Invoke-Command -ComputerName $computer -scriptBlock {Set-Service scsm -StartupType Automatic};
            Write-Verbose $Global:serviceName" set to start automatically."
        }
        else{
            Write-Host $Global:serviceName" did not start successfully."
        }        
    }
}

 
installApp
serviceStart