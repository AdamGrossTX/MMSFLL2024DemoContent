<#
    Author: Adam Gross - @AdamGrossTX
    GitHub: https://github.com/AdamGrossTX
#>
using namespace System.Net

param($Request, $TriggerMetadata)
$result = @()
$status = [HttpStatusCode]::Unauthorized

#region Custom Vars
$user = $Request.Query.User
[bool]$getEntraDevice = ($Request.Query.getEntraDevice -eq $True)
[bool]$getIntuneDevice = ($Request.Query.getIntuneDevice -eq $True)
[bool]$getGroups = ($Request.Query.getGroups -eq $True)
[bool]$getUser = -not([string]::IsNullOrEmpty($user))


#Default to get everything unless parameters are used
$getAll = (-not($getUser -or $getEntraDevice -or $getIntuneDevice))


#$Debug = $True

if ($Debug) {
    $IntuneDeviceId = $Request.Query.IntuneDeviceId
    $EntraDeviceId = $Request.Query.EntraDeviceId
}

function Get-GraphData {
    [cmdletbinding()]
    param (
        $ver = "beta",
        $query
    )

    try { 
        $RequestParams = @{
            Uri     = "https://graph.microsoft.com/$($ver)/$($query)"
            Method  = "Get"
            Headers = $Script:GraphHeaders
        }
        $Response = Invoke-RestMethod @RequestParams -ErrorAction Stop
        if ($Response.value) {
            $result += $Response.value
            while ($Response.'@odata.nextLink') {
                $RequestParams = @{
                    URI    = $Response.'@odata.nextLink'
                    Method = "Get"
                }
                $Response = Invoke-RestMethod @RequestParams -ErrorAction Stop
                $result += $Response.value
                $Response = $null
            }
            return $result
        }
        else {
            #single result returned. handle it.
            return $Response
        }
    }
    catch {
        $_.exception
        throw $_
    }
}

function Confirm-ClientCertAuth {
    [cmdletbinding()]
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$EntraDeviceCert = $script:EntraDeviceCert,
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$IntuneDeviceCert = $script:IntuneDeviceCert
    )
    try {
        $ValidIntuneDevice = $false
        $ValidEntraDevice = $false
        $ValidEntraDeviceThumbprint = $false
        
        $Script:EntraDeviceId = $EntraDeviceCert.Subject.Replace("CN=", "")
        $Script:IntuneDeviceId = $IntuneDeviceCert.Subject.Replace("CN=", "")

        if ($EntraDeviceId) {
            $EntraDeviceQuery = "devices(deviceId='$($EntraDeviceId)')?`$select=id,displayName,alternativeSecurityIds"
            $EntraDevice = Get-GraphData -Query $EntraDeviceQuery
            
            if ($EntraDevice) {
                $ValidEntraDevice = $true
                if ($EntraDevice.alternativeSecurityIds) {
                    [byte[]]$SecIdSecIdBytes = [Convert]::FromBase64String($EntraDevice.alternativeSecurityIds.key)
                    $encoding = New-Object System.Text.UnicodeEncoding
                    $DecodedID = $encoding.GetString($SecIdSecIdBytes)
                    if ($DecodedID -like "*$($EntraDeviceCert.Thumbprint)*") {
                        $ValidEntraDeviceThumbprint = $true
                    }
                    else {
                        $status = [HttpStatusCode]::Unauthorized
                        $result += "Invalid Entra Thumbprint"
                    }
                }
            }
            else {
                $status = [HttpStatusCode]::Unauthorized
                $result += "Error - Invalid Entra Device"
            }
        }

        if ($IntuneDeviceID) {
            $IntuneDeviceQuery = "deviceManagement/ManagedDevices/$($IntuneDeviceID)"
            $IntuneDevice = Get-GraphData -Query $IntuneDeviceQuery
            if ($IntuneDevice) {
                $ValidIntuneDevice = $true
            }
            else {
                $status = [HttpStatusCode]::Unauthorized
                $result += "Error - Invalid Intune Device"
            }
        }

        if ($ValidIntuneDevice -and $ValidEntraDevice -and $ValidEntraDeviceThumbprint) {
            $retobj = [PSCustomObject] @{
                EntraDeviceObject = $EntraDevice
                IntuneDeviceObject = $IntuneDevice
            }
            return $retobj
        }
        else {
            return $false
        }
    }
    catch {
        throw $_
    }
}

try {

    #region HeaderCerts
    if ($Request.Headers.EntraDeviceCert) {
        try {
            $script:EntraDeviceCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]([Convert]::FromBase64String($Request.Headers.EntraDeviceCert))
            if ((-not $EntraDeviceCert)) {
                $status = [HttpStatusCode]::Unauthorized
                $result += "Error - Invalid or Missing Entra Device Cert in Header."
                exit
            }
        }
        catch {
            $status = [HttpStatusCode]::Unauthorized
            $result += "Error - EntraDeviceCert format is invalid."
            exit
        }
    }
    else {
        if ($Debug -ne $True) {
            $status = [HttpStatusCode]::Unauthorized
            $result += "Error - Invalid or Missing Entra Device Cert in Header."
            exit
        }
    }
    if ($Request.Headers.IntuneDeviceCert) {
        try {
            $script:IntuneDeviceCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]([Convert]::FromBase64String($Request.Headers."IntuneDeviceCert"))
            if ((-not $IntuneDeviceCert)) {
                $status = [HttpStatusCode]::Unauthorized
                $result += "Error - Missing Intune Device Cert in Header."
                exit
            }
        }
        catch {
            $status = [HttpStatusCode]::Unauthorized
            $result += "Error - IntuneDeviceCert format is invalid."
            exit
        }
    }
    else {
        if ($Debug -ne $True) {
            $status = [HttpStatusCode]::Unauthorized
            $result += "Error - Missing Intune Device Cert in Header."
            exit
        }
    }
    #endregion

    #region Get Graph AccessToken with Managed System Identity
    $BaseURI = 'https://graph.microsoft.com/'
    $tokenParams = @{
        Uri     = "${Env:MSI_ENDPOINT}?resource=${BaseURI}&api-version=2017-09-01"
        Method  = "Get"
        Headers = @{ Secret = $Env:MSI_SECRET }
    }
    $Response = Invoke-RestMethod @tokenParams
    $Token = $Response.access_token
    $Script:GraphHeaders = @{
        "Authorization"    = "Bearer $token"
        "Content-Type"     = "application/json"
        "ConsistencyLevel" = "Eventual"
    }
    #endregion


    if ($Debug -ne $True) {
        $ValidObjects = Confirm-ClientCertAuth -EntraDeviceCert $EntraDeviceCert -IntuneDeviceCert $IntuneDeviceCert

        if (-not ($ValidObjects)) {
            $status = [HttpStatusCode]::Unauthorized
            $result += "Error - Device Cert Validation Failed."
            exit
        }
        else {
            $status = [HttpStatusCode]::OK
        }
    }


    #Insert your code here
    if ($ValidObjects) {
        if (($getIntuneDevice -or $getAll) -and $IntuneDeviceId) {
            $IntuneDeviceObj =  if($ValidObjects.IntuneDeviceObject) {
                $ValidObjects.IntuneDeviceObject
            }
            else {
                $IntuneDeviceQuery = "deviceManagement/managedDevices/$($IntuneDeviceId)?`$select=id,deviceEnrollmentType,azureADDeviceId,managedDeviceName,joinType,enrollmentProfileName,roleScopeTagIds"
                Get-GraphData -Query $IntuneDeviceQuery
            }
        }

        if ($getIntuneDevice -or $getAll) {
            $ScopeTagQuery = "deviceManagement/roleScopeTags?`$top=999"
            $ScopeTagQueryObj = Get-GraphData -Query $ScopeTagQuery
            $ScopeTags = ($ScopeTagQueryObj | Where-Object { $_.id -in $IntuneDeviceObj.roleScopeTagIds }).DisplayName
        }

        if (($getEntraDevice -or $getAll) -and $EntraDeviceId) {
            $EntraDeviceObj =  if($ValidObjects.EntraDeviceObject) {
                $ValidObjects.EntraDeviceObject
            }
            else {
                $EntraDeviceQuery = "devices(deviceId='$($EntraDeviceId)')?`$select=id,deviceId,physicalIds,extensionAttributes,enrollmentType"
                Get-GraphData -Query $EntraDeviceQuery
            }
            if ($EntraDeviceObj.extensionAttributes) {
                $DeviceSiteCode = $EntraDeviceObj.extensionAttributes.extensionAttribute3
            }
        }

        if ((($getIntuneDevice -and (-not $user)) -or $getAll) -and $IntuneDeviceId) {
            $UserSearchQuery = "deviceManagement/managedDevices/$($IntuneDeviceId)/users?`$select=id"
            $UserSearchObj = Get-GraphData -Query $UserSearchQuery
            $EntraUserID = $UserSearchObj.id
            
            if ($EntraUserID) {
                $UserQuery = "users/$($EntraUserID)?`$select=id,userPrincipalName,city,department,officelocation,onPremisesDistinguishedName"
                $IntunePrimaryUserObj = Get-GraphData -Query $UserQuery

                if ($IntunePrimaryUserObj.city) {
                    $PrimaryUserSiteCode = $IntunePrimaryUserObj.city
                }
            }
        }

        elseif ($user) {
            $UserSearchQuery = "users/$($user)?`$select=id"
            $UserSearchObj = Get-GraphData -Query $UserSearchQuery
            $EntraUserID = $UserSearchObj.id

            if ($EntraUserID) {
                $UserQuery = "users/$($EntraUserID)?`$select=id,userPrincipalName,extension_321b89e2c67745d0b573c3adff3f197b_cpc_PhysicalDeliveryFacility,extension_321b89e2c67745d0b573c3adff3f197b_cpc_PhysicalDeliveryDetail,onPremisesDistinguishedName"
                $UserObj = Get-GraphData -Query $UserQuery

                if ($UserObj.Location) {
                    $UserSiteCode = $UserObj.Location
                }
            }
        }

        if ($getGroups) {
            if ($EntraUserID) {
                $UserGroupsQuery = "users/$($EntraUserID)/memberOf?`$select=id,displayName&`$top=999"
                $UserGroupsObj = Get-GraphData -Query $UserGroupsQuery
            }

            if ($EntraDeviceObj.id) {
                $DeviceGroupsQuery = "devices/$($EntraDeviceObj.id)/memberOf?`$select=id,displayName&`$top=999"
                $DeviceGroupsObj = Get-GraphData -Query $DeviceGroupsQuery
            }
        }

        $result = 
        if ($intuneDeviceId) {
            [PSCustomObject]@{
                EntraDevice           = $EntraDeviceObj
                IntuneDevice        = $IntuneDeviceObj
                IntunePrimaryUser   = $IntunePrimaryUserObj
                UserGroups          = $UserGroupsObj
                DeviceGroups        = $DeviceGroupsObj
                ScopeTags           = $ScopeTags
                DeviceSiteCode      = $DeviceSiteCode
                PrimaryUserSiteCode = $PrimaryUserSiteCode
                UserSiteCode        = $UserSiteCode
            }
        }
        elseif ($user) {
            [PSCustomObject]@{
                User     = $UserObj
                Groups   = $UserGroupsObj
                SiteCode = $UserSiteCode
            }
        }
        elseif ($EntraDeviceId) {
            [PSCustomObject]@{
                EntraDevice      = $EntraDeviceObj
                DeviceGroups   = $DeviceGroupsObj
                DeviceSiteCode = $DeviceSiteCode
            }
        }
    }
    else {
        $status = [HttpStatusCode]::BadRequest
    }
}
catch {
    $status = [HttpStatusCode]::BadRequest
    $result = @{"Error" = "$_" } | ConvertTo-Json
}
#endregion

#region output
# Associate values to output bindings by calling 'Push-OutputBinding'.
Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = $status
        Body       = $result
    })
#endregion
