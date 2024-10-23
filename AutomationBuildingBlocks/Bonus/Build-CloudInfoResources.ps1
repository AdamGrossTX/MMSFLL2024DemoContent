<#

.NOTES
    Author: Adam Gross - @AdamGrossTX
    GitHub: https://github.com/AdamGrossTX/ManagedUserManagement

#>

Param(
    [string]$objectRootName
)

$RequiredModules = @(
    "Az.Functions",
    "Az.Storage"
)

foreach ($Module in $RequiredModules) {
    if (Get-Module -ListAvailable -Name $Module) {
        Import-Module $Module
    }
    else {
        Write-Host "Az Module is not installed. Installing now" -NoNewline -ForegroundColor Cyan
        Install-Module Az -Force -Scope AllUsers
        Write-Host "Done" -ForegroundColor Green
    }
}

function Set-ManagedIDPermissions {
    [cmdletbinding()]
    param (
        $managedId,
        $graphScope
    )
    try {
        Write-Host "Setting MSI Permission: $($graphScope)" -NoNewline -ForegroundColor Cyan
        $token = (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com/").Token
        $header = @{Authorization = "Bearer $token" }

        $GraphAppId = "00000003-0000-0000-c000-000000000000"
        $GraphServicePrincipal = Get-AzADServicePrincipal -ApplicationId $GraphAppId
        $managedidentity = Get-AzADServicePrincipal -ObjectId $managedId

        foreach ($Permission in $graphscope) {
            $AppRole = $GraphServicePrincipal.AppRole | Where-Object { $_.Value -eq $Permission -and $_.AllowedMemberType -contains "Application" }

            $URI = "https://graph.microsoft.com/v1.0/servicePrincipals/$($managedidentity.Id)/appRoleAssignedTo"
            $Body = @{
                principalId = $managedidentity.Id
                resourceId  = $GraphServicePrincipal.Id
                appRoleId   = $AppRole.Id
            } | ConvertTo-Json

            $Response = Invoke-RestMethod -Method POST -Headers $Header -Body $Body -Uri $URI -ContentType "Application/Json" -ErrorAction Continue
        }
        Write-Host " - Done" -ForegroundColor Green
    }
    catch {
        if (($_.ErrorDetails.message | convertfrom-json).error.message -eq 'Permission being assigned already exists on the object') {
            Write-Host "$(($_.ErrorDetails.message | convertfrom-json).error.message)" -ForegroundColor Red
            throw ($_.ErrorDetails.message | convertfrom-json).error.message
        }
        else {
            throw $_
        }
    }
}

#region Main
Connect-AZAccount -Tenant "a63242f3-50e8-48ff-832d-b085d072866a" | Out-Null
Update-AzConfig -Scope Process -DisplayBreakingChangeWarning $false | Out-Null

$Objects = @{
    ResourceGroup  = "rg$($objectRootName)"
    StorageAccount = "sa$($objectRootName.ToLower())"
    FunctionApp    = "fa$($objectRootName)"
    Location       = "South Central US"
}

$AppSettings = @{
    StorageAccountName = $Objects.StorageAccount
}

Write-Host "Creating the following resources" -ForegroundColor Cyan
$Objects.Keys | ForEach-Object { Write-Host "$($_) : $($Objects[$_])" }

Write-Host "Creating ResourceGroup" -NoNewline -ForegroundColor Cyan
$ResourceGroup = New-AzResourceGroup -Name $Objects.ResourceGroup -Location $Objects.Location
Write-Host " - Done" -ForegroundColor Green

Write-Host "Creating Storage Account" -NoNewline -ForegroundColor Cyan
$StorageAccount = New-AzStorageAccount -ResourceGroupName $ResourceGroup.ResourceGroupName -Name $Objects.StorageAccount -Location $Objects.Location -SkuName Standard_LRS -Kind StorageV2
Write-Host " - Done" -ForegroundColor Green

Write-Host "Creating Function App" -NoNewline -ForegroundColor Cyan
$AzureFunction = New-AzFunctionApp -ResourceGroupName $ResourceGroup.ResourceGroupName -Name $Objects.FunctionApp -Location $Objects.Location -StorageAccountName $StorageAccount.StorageAccountName -Runtime PowerShell -FunctionsVersion 4 -IdentityType SystemAssigned -OSType Windows -AppSetting $AppSettings -RuntimeVersion 7.4
Write-Host " - Done" -ForegroundColor Green

$Permissions = @(
    "Device.Read.All", 
    "Group.Read.All", 
    "User.ReadWrite.All"
    "DeviceManagementManagedDevices.ReadWrite.All",
    "DeviceManagementManagedDevices.Read.All", 
    "DeviceManagementServiceConfig.ReadWrite.All",
    "Directory.ReadWrite.All",
    "DeviceManagementApps.ReadWrite.All",
    "DeviceManagementConfiguration.ReadWrite.All",
    "User.ManageIdentities.All"
    "DeviceManagementRBAC.Read.All",
    "DeviceManagementRBAC.ReadWrite.All"
)

forEach ($Permission in $Permissions) {
    try {
        Set-ManagedIDPermissions -managedId $AzureFunction.IdentityPrincipalId -graphScope $Permission -ErrorAction SilentlyContinue
    }
    catch {
        Write-Host $_ -ForegroundColor Red
        Continue
    }
}


Write-Host " - Done" -ForegroundColor Green
