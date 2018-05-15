
Written by Jtekt 15 May 2018 
 https://github.com/Jtekt/LogRhythm
 Version 0.5

## [About]

This script is designed to function as a LogRhythm SmartResponse to carry out an install of Microsoft Sysinternals Sysmon agent silently from an endpoint domain joined Windows device.
The intended use for this script is to enable the collection of additional workstation data as a result of an AIE rule that warrants further investigation.

This has been used as a troubleshooting aid to track down and isolate anomolies that occur on workstations by enabling advance logging capabilities based on observed events on the endpoint.

##### :rotating_light: This script and SmartResponse is not officially supported by LogRhythm - use at your own risk! :rotating_light:

#### Features:

    - Remote deployment of Microsoft Sysmon
    - Apply Sysmon configuration policy
    - Update Sysmon configuration policy with -force

## [Additional Information]

Plugin developed and tested with Powershell 5.1 and LogRhythm 7.2.6.

## [Instructions]

The following paramters are passed via LogRhythm:
    $computer - Target computer
    $srcConfig - File name for source sysmon configuration
    $installStagePath - Full path to folder target on target computer.  Omit the tailing \
    $installSys64 - It should not be required to run sysmon64 on a 64bit endpoint, however, if you want to the option is there.
    $force - Forces file copies and subsiquent process/configuration updates.

The following paramters must be set within the ms_sysmon_installagent.ps1 script:
    $Global:fileSource - Provide the full path to the directory where MS Sysinternal and configuration files are available. 
                         Default is C:\temp\ms_sysmon\

## [Examples]
Install and apply client configuration
 ms_sysmon_installagent.ps1 -computer COMPUTERNAME -srcConfig CONFIGNAME -installStagePath C:\temp\ms_sysmon 
Update client configuration
 ms_sysmon_installagent.ps1 -computer COMPUTERNAME -srcConfig CONFIGNAME -installStagePath C:\temp\ms_sysmon -force true


## [Thanks]

Any material that is referenced from another developer; I appreciate the dedication those in the community have and openness to share. Thank you!

- SwiftOnSecurity - Sysmon configuration policy
- Mark Russinovich and Thomas Garnier - Publication and development of Sysmon
