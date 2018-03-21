#Requires -Version 4.0
#Requires -RunAsAdministrator
#This script is designed to identify if a user is logged into a Windows Domain joined device.
#Determine the status of the current session as Logged In/Locked/Not Logged In
#Identify the active session and initiate a user logoff when the session is Locked.
# This function will return the logged-on status of a local or remote computer 
# Written by Jtekt 20 March 2018 
# Version 1.1
# Sample usage: 
# lr_logoff.ps1 -computer COMPUTERNAME -username USERNAME (-force)
param (
    [Parameter(Mandatory=$true)][string]$computer,
    [Parameter(Mandatory=$true)][string]$username,
    [switch]$force = $false
 )
#Compared Username
[string[]]$Global:Global:CUserName = $null
$Global:UserCompare = $null
$Global:SysStatus = $null
[int]$Global:sessid = $null
## Testing code - Enables rapid testing against default host/user
#if ($computer -eq $NULL) {
#    $computer = 'SBT1FS31'
#}
#if ($UserName -eq $NULL) {
#    $UserName = 'h36271'
#}

# Identify user sessions
Function getSessions {
[string]$sess = Invoke-Command -ComputerName $computer -scriptBlock {query session} | Select-String -Pattern $username 
if($sess){
    $Global:sessid = $sess.Substring(45,1)
}
else{
    Write-Host "Found no target."
}
## Debug code - Prints out identified Session ID
#Write-Host 'Printing Global:sessid'$Global:sessid
}

# Define user logoff
Function logUserOff {
    if($Global:sessid){
        Invoke-Command -ComputerName $computer -scriptBlock {logoff $args[0]} -ArgumentList $Global:sessid
    }
    else{
        Write-Host "Provided no target."
    }

}

# This function will return the logged-on status of a local or remote computer 
# Written by BigTeddy 10 September 2012
# Modified by Jtekt 20 March 2018 
# Version 1.2
# Sample usage: 
# GetRemoteLogonStatus '<remoteComputerName>' 
function GetRemoteLogonStatus ($local = $computer) { 
    if (Test-Connection $local -Count 2 -Quiet) {
        try { 
            $user = $null 
            $user = Get-WmiObject -Class win32_computersystem -ComputerName $local | Select-Object -ExpandProperty username -ErrorAction Stop 
            #Write-Host "Pre"
            #Write-Host $computer
            #Write-Host $user
            #Write-Host "Post"
            if($user -eq $null){
                #Write-Host "Unable to return Logon Status."
                $Global:CUserName = "void", "void"
            }
            else{
                $Global:CUserName = $user.Split("{\}")
            }
            } 
        catch { $Global:CUserName = "null"; return } 
        try { 
            $status = Invoke-Command -ComputerName $local -scriptBlock {Get-Process $args[0]} -ArgumentList "logonui" -ErrorAction Stop
            if (($status -and ($user)) ) {
               #"Workstation locked by $user"
                $Global:SysStatus = "Locked"
                } 
            } 
        catch { if ($user) { 
           #$user logged on"
            $Global:SysStatus = "Active" 
        } 
    } 
    } 
    else { "$local Offline" } 
} 

function compareUserNames (){
    if ($Global:CUserName[1] -eq $username){
        #If usernames do not match, Global:UserCompare = true.
        #Debug:
        #Write-Host "True"
        #Write-Host $Global:CUserName[1]
        #Write-Host $username
        $Global:UserCompare = 1
    }
    else {
        #If usernames do not match, Global:UserCompare = false.
        #Debug:
        #Write-Host "False"
        #Write-Host $Global:CUserName[1]
        #Write-Host $username
        $Global:UserCompare = 0
    }
}


GetRemoteLogonStatus
compareUserNames
#Write-Host $Global:CUserName
if($force -eq $true){
    getSessions
    Write-Host "Forcing logoff for"$username" on host "$computer"."
    logUserOff
}
elseif ($Global:UserCompare){
    getSessions
    elseif($Global:SysStatus -eq "Locked"){
        #
        Write-Host "Session locked for"$Global:CUserName[1]"proceeding with logout."
        logUserOff
    }
    elseif ($Global:SysStatus -eq "Active"){
        Write-Host "User"$Global:CUserName[1]"currently logged into an active session."
    }   
}
else{
    Write-Host "No active session identified for"$username" on host "$computer"."
}