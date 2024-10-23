Connect-MgGraph

. .\MGGraph-Helper.ps1

$IntuneDevices = Invoke-GraphGet -Uri "https://graph.microsoft.com/beta/deviceManagement/ManagedDevices"
$EntraUsers = Invoke-GraphGet -Uri "https://graph.microsoft.com/beta/users"
$EntraDevices = Invoke-GraphGet -Uri "https://graph.microsoft.com/beta/devices"


foreach ($IntuneDevice in $IntuneDevices) {
    $EntraUser = $EntraUsers | Where-Object { $_.id -eq $IntuneDevice.userId }
    $EntraDevice = $EntraDevices | Where-Object { $_.deviceId -eq $IntuneDevice.AzureADDeviceId }
    $Body = @{
        extensionAttributes = 
        @{
            extensionAttribute1 = $EntraUser.userPrincipalName
            extensionAttribute2 = $EntraUser.userId
            extensionAttribute3 = $IntuneDevice.model
            extensionAttribute4 = $EntraUser.city
            extensionAttribute5 = $EntraUser.department
            extensionAttribute6 = $EntraUser.officeLocation
            extensionAttribute7 = $IntuneDevice.notes
        }
    }

    Invoke-GraphPatch -Uri "https://graph.microsoft.com/beta/devices/$($EntraDevice.id)" -Body $Body
}


$EntraDevices = Invoke-GraphGet -Uri "https://graph.microsoft.com/beta/devices"
$IntraDevicesInIntune = $EntraDevices | Where-Object {$_.deviceId -in $IntuneDevices.AzureADDeviceId}
$IntraDevicesInIntune | Select-Object -Property * -ExpandProperty extensionAttributes -ExcludeProperty extensionAttributes | Select-Object -Property id, deviceName, extensionAttribute1, extensionAttribute2, extensionAttribute3, extensionAttribute4, extensionAttribute5, extensionAttribute6, extensionAttribute7