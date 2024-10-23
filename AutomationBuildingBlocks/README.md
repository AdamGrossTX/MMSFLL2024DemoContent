This is supplemental code used during the session.

Main complete Kiosk Autologon solution
https://github.com/AdamGrossTX/ManagedUserManagement

ExtensionAttributes.ps1
This script is a sample of how to set Entra Device extensionAttributes using data from Entra Users and Intune Devices. The goal is to set attributes that can be used for dynamic grouping and targeting. 
For example, add the Intune primary user's office location and department to the Entra device and now you can create dynamic device groups based on department or site.

MGGraph-Helper.ps1
Helper script for the Microsoft.Graph module to handle things like paging, batching, and throttle limits.
