param (
    [switch]$remediate = $true,
    [switch]$writeRegKeys = $true,
    [switch]$removeKeys = $true,
    [string]$baseURI="<INSERT URI HERE>",
    [string]$companycode = "ASD"
)

#region functions
function Test-Admin {
    [CmdletBinding()]
    param (
    )
    try {
        return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')
    }
    catch {
        throw $_
    }
}

function Get-DSREGCMDStatus {
    [cmdletbinding()]
    param(
        [parameter(HelpMessage = "Use to add /DEBUG to DSREGCMD")]
        [switch]$bDebug #Can't use Debug since it's a reserved word
    )
    try {
        Write-Host "Calling DSREGCMDSTATUS"

        $cmdArgs = if ($bDebug) { "/STATUS", "/DEBUG" } else { "/STATUS" }
        $DSREGCMDStatus = & DSREGCMD $cmdArgs

        $DSREGCMDEntries = [PSCustomObject]@{}

        if ($DSREGCMDStatus) {
            for ($i = 0; $i -le $DSREGCMDStatus.Count ; $i++) {
                if ($DSREGCMDStatus[$i] -like "| *") {
                    $GroupName = $DSREGCMDStatus[$i].Replace("|", "").Trim().Replace(" ", "")
                    $Member = @{
                        MemberType = "NoteProperty"
                        Name       = $GroupName
                        Value      = $null
                    }
                    $DSREGCMDEntries | Add-Member @Member -Force
                    $i++ #Increment to skip next line with +----
                    $GroupEntries = [PSCustomObject]@{}

                    do {
                        $i++
                        if ($DSREGCMDStatus[$i] -like "*::*") {
                            $DiagnosticEntries = $DSREGCMDStatus[$i] -split "(^DsrCmd.+(?=DsrCmd)|DsrCmd.+(?=\n))" | Where-Object { $_ -ne '' }
                            foreach ($Entry in $DiagnosticEntries) {
                                $EntryParts = $Entry -split "(^.+?::.+?: )" | Where-Object { $_ -ne '' }
                                $EntryParts[0] = $EntryParts[0].Replace("::", "").Replace(": ", "")
                                if ($EntryParts) {
                                    $Member = @{
                                        MemberType = "NoteProperty"
                                        Name       = $EntryParts[0].Trim().Replace(" ", "")
                                        Value      = $EntryParts[1].Trim()
                                    }
                                    $GroupEntries | Add-Member @Member -Force
                                    $Member = $null
                                }
                            }
                        }
                        elseif ($DSREGCMDStatus[$i] -like "* : *") {
                            $EntryParts = $DSREGCMDStatus[$i] -split ':'
                            if ($EntryParts) {
                                $Member = @{
                                    MemberType = "NoteProperty"
                                    Name       = $EntryParts[0].Trim().Replace(" ", "")
                                    Value      = if ($EntryParts.Count -gt 2) {
                                                    ( $EntryParts[1..(($EntryParts.Count) - 1)] -join ":").Split("--").Replace("[ ", "").Replace(" ]", "").Trim()
                                    }
                                    else {
                                        $EntryParts[1].Trim()
                                    }
                                }
                                $GroupEntries | Add-Member @Member -Force
                                $Member = $null
                            }
                        }
                    
                    } until($DSREGCMDStatus[$i] -like "+-*" -or $i -eq $DSREGCMDStatus.Count)
    
                    $DSREGCMDEntries.$GroupName = $GroupEntries
                }
            }
            return $DSREGCMDEntries
        }
        else {
            return "No Status Found"
        }
    }
    catch {
        throw $_
    }
}

function Get-EntraDeviceCert {
    [CmdletBinding()]
    param (
    )
    try {
        Write-Host "Getting Azure AD Device Certificate"
        #Get best cert from DSRegCmd
        $dsregcmdStatus = Get-DSREGCMDStatus
        $Thumbprint = $dsregcmdstatus.DeviceDetails.Thumbprint
    
        #Get the local cert that matches the DSRegCMD Cert
        $Certs = Get-ChildItem -Path Cert:\LocalMachine\My 
        $Cert = $Certs | Where-Object { $_.Thumbprint -eq $dsregcmdstatus.DeviceDetails.Thumbprint }

        if ($Cert.Thumbprint -eq $Thumbprint) {
            return $Cert
        }
        else {
            Write-Output "No valid Entra Device Cert Found."
        }
    }
    catch {
        throw $_
    }
}

function Get-IntuneDeviceCert {
    [CmdletBinding()]
    [OutputType([X509Certificate])]
    param (
    )
    try {
        Write-Host "Getting Intune Device Certificate"
        if (Test-Admin) {
            $CertIssuer = "CN=Microsoft Intune MDM Device CA"
            $ProviderRegistryPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Enrollments"
            $ProviderPropertyName = "ProviderID"
            $ProviderPropertyValue = "MS DM Server"
            $ProviderGUID = (Get-ChildItem -Path Registry::$ProviderRegistryPath -Recurse | ForEach-Object { if ((Get-ItemProperty -Name $ProviderPropertyName -Path $_.PSPath -ErrorAction SilentlyContinue | Get-ItemPropertyValue -Name $ProviderPropertyName -ErrorAction SilentlyContinue) -match $ProviderPropertyValue) { $_ } }).PSChildName
            $DMClientPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Enrollments\$($ProviderGUID)\DMClient\MS DM Server"
            $IntuneDeviceId = (Get-ItemPropertyValue -Path Registry::$DMClientPath -Name "EntDMID")

            $Cert = (Get-ChildItem cert:\LocalMachine\my | where-object { $_.Issuer -in $CertIssuer -and $_.Subject -like "*$IntuneDeviceId*" })
            if ($cert) {
                return $Cert
            }
        }
        else {
            Write-Warning "Admin rights required to get Intune cert for web authentication."
        }
    }
    catch {
        throw $_
    }
}
function New-CloudInfoRegKeys {
    [cmdletbinding()]
    param (
        $Object,
        $KeyPath
    )

    try {
        $RegKey = New-Item -Path registry::$KeyPath -Force
        New-ItemProperty -Path registry::$RegKey -Name "LastWriteTime" -Value ((Get-Date).DateTime) -Force | Out-Null
    
        foreach ($prop in ($Object.Psobject.Properties | Where-Object { ($_.MemberType -eq "NoteProperty" -or $_.TypeNameOfValue -in ("System.Object", "System.Object[]") -and ($_.Name -notin ("@odata.context", "@odata.type"))) })) {
            $value = if ($Prop.TypeNameOfValue -eq 'System.Object[]') {
                $Prop.Value | ConvertTo-Json
            }
            elseif ($Prop.TypeNameOfValue -in ('System.Object', 'System.Management.Automation.PSCustomObject')) {
                $Prop.Value | Select-Object -Property * -ExcludeProperty "@odata.context", "@odata.type" | ConvertTo-Json
            }
            else {
                $Prop.Value
            }
            New-ItemProperty -Path registry::$RegKey -Name $prop.Name -Value $value -Force | Out-Null
        }
    }
    catch {
        throw $_
    }
}
#endregion

#region main
try {
    $EntraDeviceCert = Get-EntraDeviceCert
    $IntuneDeviceCert = Get-IntuneDeviceCert
    $IntuneDeviceId = $IntuneDeviceCert.Subject.Replace("CN=", "")

    if ($IntuneDeviceId) {
        if ($remediate.IsPresent) {
            $Headers = @{
                EntraDeviceCert    = [System.Convert]::ToBase64String($EntraDeviceCert.GetRawCertData())
                IntuneDeviceCert = [System.Convert]::ToBase64String($IntuneDeviceCert.GetRawCertData())
            } 
            $IntuneResponse = Invoke-WebRequest -uri "$($baseURI)?getGroups=true" -Headers $Headers
            if ($IntuneResponse) {
                $IntuneObjects = $IntuneResponse.Content | ConvertFrom-Json
            }

            $ParentKeyPath = "HKEY_LOCAL_MACHINE\SOFTWARE\$($CompanyCode)\CloudInfo"
            if ($removeKeys.isPresent) {
                Remove-Item -Path registry::$ParentKeyPath -Recurse -Force -ErrorAction SilentlyContinue
            }

            if ($writeRegKeys.IsPresent) {
                $ParentKey = New-Item -Path registry::$ParentKeyPath -Force
                New-ItemProperty -Path registry::$ParentKey -Name "LastWriteTime" -Value ((Get-Date).DateTime) -Force | Out-Null

                $IntuneDeviceKeyPath = "$($ParentKeyPath)\IntuneDevice"
                $IntunePrimaryUserKeyPath = "$($ParentKeyPath)\IntunePrimaryUser"
                $EntraDeviceKeyPath = "$($ParentKeyPath)\EntraDevice"
                $DefenderDeviceTagPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection\DeviceTagging"

                if ($IntuneObjects.IntuneDevice) {
                    if (Test-Path -Path registry::$IntuneDeviceKeyPath) {
                        Remove-Item -Path registry::$IntuneDeviceKeyPath -Force -Recurse
                    }

                    New-CloudInfoRegKeys -Object $IntuneObjects.intuneDevice -KeyPath $IntuneDeviceKeyPath
                    New-CloudInfoRegKeys -Object $IntuneObjects.EntraDevice -KeyPath $EntraDeviceKeyPath
                    New-CloudInfoRegKeys -Object $IntuneObjects.IntunePrimaryUser -KeyPath $IntunePrimaryUserKeyPath

                    if ($IntuneObjects.ScopeTags) {
                        New-ItemProperty -Path registry::$IntuneDeviceKeyPath -Name "ScopeTags" -Value ($IntuneObjects.ScopeTags | ConvertTo-Json) -Force | Out-Null
                    }

                    if ($IntuneObjects.DeviceSiteCode) {
                        New-ItemProperty -Path registry::$IntuneDeviceKeyPath -Name "DeviceSiteCode" -Value $IntuneObjects.DeviceSiteCode -Force | Out-Null
                        New-Item -Path registry::$DefenderDeviceTagPath -Force | Out-Null
                        New-ItemProperty -Path registry::$DefenderDeviceTagPath -Name "Group" -Value $IntuneObjects.DeviceSiteCode -Force | Out-Null
                    }

                    if ($IntuneObjects.UserGroups) {
                        $value = $IntuneObjects.DeviceGroups | Select-Object -Property * -ExcludeProperty "@odata.context", "@odata.type" | ConvertTo-Json
                        New-ItemProperty -Path registry::$IntuneDeviceKeyPath -Name "deviceGroups" -Value $value -Force | Out-Null
                    }

                    if ($IntuneObjects.DeviceGroups) {
                        $value = $IntuneObjects.UserGroups | Select-Object -Property * -ExcludeProperty "@odata.context", "@odata.type" | ConvertTo-Json
                        New-ItemProperty -Path registry::$IntunePrimaryUserKeyPath -Name "userGroups" -Value $value -Force | Out-Null
                    }
                }
            }
            Write-Host "Created registry keys."
            exit 0
        }
        else {
            Write-Host "Intune Device ID $($IntuneDeviceId) found. Remediation Needed."
            exit 1
        }
    }
    else {
        Throw "No Intune Device ID Found. Something is wrong."
    }
}
catch {
    throw $_
}

#endregion
