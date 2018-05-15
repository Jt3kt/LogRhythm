
Written by Jtekt 15 May 2018 
 https://github.com/Jtekt/LogRhythm
 Version 0.5

## [About]

This script is designed to function as a LogRhythm SmartResponse to carry out an install of Microsoft Sysinternals Sysmon agent silently from an endpoint domain joined Windows device.
The intended use for this script is to enable the collection of additional workstation data as a result of an AIE rule that warrants further investigation.

This has been used as a troubleshooting aid to track down and isolate anomolies that occur on workstations by enabling advance logging capabilities based on observed events ont he endpoint.

##### :rotating_light: This script and SmartResponse is not officially supported by LogRhythm - use at your own risk! :rotating_light:

#### Features:

    - Remote deployment of Microsoft Sysmon
    - Apply Sysmon configuration policy
    - Update Sysmon configuration policy with -force

## [Additional Information]

Plugin developed and tested with Powershell 5.1 and LogRhythm 7.2.6.


## [Thanks]

Any material that is referenced from another developer; I appreciate the dedication those in the community have and openness to share. Thank you!

- SwiftOnSecurity - Sysmon configuration policy
