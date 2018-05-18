#This script is designed to identify if a user is logged into a Windows Domain joined device.
#Determine the status of the current session as Logged In/Locked/Not Logged In
#Identify the active session and initiate a user logoff when the session is Locked.
# This function will return the logged-on status of a local or remote computer 
# Written by Jtekt 20 March 2018 
# Version 1.1
# Sample usage: 
# user_logoff.ps1 -computer COMPUTERNAME -username USERNAME (-force TRUE/FALSE)
