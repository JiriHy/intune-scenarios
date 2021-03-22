<#
Adding managed devices to an AAD group, based on primary user group membership.
Useful for Intune delegation scenario.



.COPYRIGHT
Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
Use on your own risk


#>

####################################################

function Get-AuthToken {

    <#
    .SYNOPSIS
    This function is used to authenticate with the Graph API REST interface
    .DESCRIPTION
    The function authenticate with the Graph API Interface with the tenant name
    .EXAMPLE
    Get-AuthToken
    Authenticates you with the Graph API interface
    .NOTES
    NAME: Get-AuthToken
    #>
    
    [cmdletbinding()]
    
    param
    (
        [Parameter(Mandatory=$true)]
        $User
    )
    
    $userUpn = New-Object "System.Net.Mail.MailAddress" -ArgumentList $User
    
    $tenant = $userUpn.Host
    
    Write-Host "Checking for AzureAD module..."
    
        $AadModule = Get-Module -Name "AzureAD" -ListAvailable
        
        if ($AadModule -eq $null) {
            
            Write-Host "AzureAD PowerShell module not found, looking for AzureADPreview"
            $AadModule = Get-Module -Name "AzureADPreview" -ListAvailable
    
        }
    
        if ($AadModule -eq $null) {
            write-host
            write-host "AzureAD Powershell module not installed..." -f Red
            write-host "Install by running 'Install-Module AzureAD' or 'Install-Module AzureADPreview' from an elevated PowerShell prompt" -f Yellow
            write-host "Script can't continue..." -f Red
            write-host
            exit
        }
    
    # Getting path to ActiveDirectory Assemblies
    # If the module count is greater than 1 find the latest version
    
        if($AadModule.count -gt 1){
    
            $Latest_Version = ($AadModule | select version | Sort-Object)[-1]
    
            $aadModule = $AadModule | ? { $_.version -eq $Latest_Version.version }
    
            $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
            $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
    
        }
    
        else {
    
            $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
            $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
    
        }
    
    [System.Reflection.Assembly]::LoadFrom($adal) | Out-Null
    
    [System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null
    
    $clientId = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547"
    
    $redirectUri = "urn:ietf:wg:oauth:2.0:oob"
    
    $resourceAppIdURI = "https://graph.microsoft.com"
    
    $authority = "https://login.microsoftonline.com/$Tenant"
    
        try {
    
        $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority
    
        # https://msdn.microsoft.com/en-us/library/azure/microsoft.identitymodel.clients.activedirectory.promptbehavior.aspx
        # Change the prompt behaviour to force credentials each time: Auto, Always, Never, RefreshSession
    
        $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Auto"
    
        $userId = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList ($User, "OptionalDisplayableId")
        
        $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI,$clientId,$redirectUri,$platformParameters,$userId).Result
    
            # If the accesstoken is valid then create the authentication header
    
            if($authResult.AccessToken){
    
            # Creating header for Authorization token
    
            $authHeader = @{
                'Content-Type'='application/json'
                'Authorization'="Bearer " + $authResult.AccessToken
                'ExpiresOn'=$authResult.ExpiresOn
                }
    
            return $authHeader
    
            }
    
            else {
    
            Write-Host
            Write-Host "Authorization Access Token is null, please re-run authentication..." -ForegroundColor Red
            Write-Host
            break
    
            }
    
        }
    
        catch {
    
        write-host $_.Exception.Message -f Red
        write-host $_.Exception.ItemName -f Red
        write-host
        break
    
        }
    
    }
    
    ####################################################
    
    
    
    
    
    
    function Get-Rest($uri, $token)
    {
    
        $params = @{
            ContentType = 'application/json'
            Headers     = @{
                'authorization' = $token
            }
            Method      = 'Get'
            URI         = $uri
        }
        #endregion
    
        #region execute rest and wait for response
        try
        {
            # With "Invoke-RestMethod" there is no answer returned to check for StatusCode
            $response = Invoke-RestMethod @params
            return $response
        }
        catch
        {
            Write-Host ("Error in the HTTP request...") -ForegroundColor Red
            Write-Host $Error[0] -ForegroundColor Yellow
            break
        }
    }
 
    
    Function Get-ManagedDevices(){
         <#
        .SYNOPSIS
        This function is used to get Intune managed devices from the Graph API REST interface
        .DESCRIPTION
        The function connects to the Graph API Interface and gets managed devices from AAD
        .EXAMPLE
        Get-ManagedDevices
        Returns all managed devices
        #>
        
        [cmdletbinding()]
        param
        ($filter)
        
        # Defining Variables
        $graphApiVersion = "v1.0"
        $Resource = "devicemanagement/manageddevices"
        
        $ManagedDevices = Get-GraphAPIObjects $graphApiVersion $Resource $filter
        return $ManagedDevices
    }

    
        Function Get-Users()
        {   
            # Defining Variables
            $graphApiVersion = "v1.0"
            $Resource = "users"

            # Calling Graph API
            $Users=Get-GraphAPIObjects -Ver $graphApiVersion -Res $Resource
            return $Users
        }
    
       
    
    
            Function Get-GraphAPIObjects()  
            {
    
                <#
                .SYNOPSIS
                This function is used to get objecst from the Graph API REST interface
                .DESCRIPTION
                The function connects to the Graph API Interface and gets objects based on API version Resource URI and Filter
                .EXAMPLE
                Get-GraphAPIObjects -Version "v1.0" -Resource "devices" -Filter '?$filter=deviceId eq ''' + $deviceId + "'"
                Returns a device with specified Id
                #>
                [cmdletbinding()]         
                param
                    (
                    $Version,
                    $Resource,
                    $Filter
                    )    

                
                try {
                    
                        $uri = "https://graph.microsoft.com/$Version/$Resource/$Filter"
                
                        $resp = Get-Rest -token $authToken.Authorization -uri $uri
                        $retVal = $resp.value
                            
                        if($resp.'@odata.nextLink')
                            {
                                while($resp.'@odata.nextLink')
                                {
                                    $resp = Get-Rest -token $authToken.Authorization -uri $resp.'@odata.nextLink'
                                    $retVal += $resp.value
                                }
                            }
                        return $retVal
                    }
                
                    catch {
                
                    $ex = $_.Exception
                    $errorResponse = $ex.Response.GetResponseStream()
                    $reader = New-Object System.IO.StreamReader($errorResponse)
                    $reader.BaseStream.Position = 0
                    $reader.DiscardBufferedData()
                    $responseBody = $reader.ReadToEnd();
                    Write-Host "Response content:`n$responseBody" -f Red
                    Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
                    write-host
                    break
                
                    }
                
                }        
    
    Function Get-AzADgroup()
    {
    [cmdletbinding()]         
    param
    ($GroupName)
                
    $graphApiVersion = "v1.0"
    $Resource = "groups"
    $Filter = '?$filter=DisplayName eq ''' + $GroupName + "'"
                
    $AADGroup=Get-GraphAPIObjects -Ver $graphApiVersion -Res $Resource -Fil $Filter
    return $AADgroup
    }



    Function Get-AADDevice()
    {
    [cmdletbinding()]         
    param
    ($deviceId)
    
    $graphApiVersion = "v1.0"
    $Resource = "devices"
    $Filter = '?$filter=deviceId eq ''' + $deviceId + "'"
    
    $AADDevice=Get-GraphAPIObjects -Ver $graphApiVersion -Res $Resource -Fil $Filter
    return $AADDevice
    }

    Function Get-AADGroupMembers()
    {
        [cmdletbinding()]         
        param
        ($GroupName)
        
    #get GroupId for Group Display Name
        $graphApiVersion = "v1.0"
        $Resource = "groups"
        $Filter = '?$filter=displayName eq ''' + $GroupName + "'"
        $AADGroup=Get-GraphAPIObjects -Ver $graphApiVersion -Res $Resource -Fil $Filter
   
    #get group members         
        $AADGroupId=$AADGroup.id
        $Resource="groups/$AADGroupId/members"
        $Filter=""
        $AADGroupMembers=Get-GraphAPIObjects -Ver $graphApiVersion -Res $Resource -Fil $Filter        

        return $AADGroupMembers
   
    }
    
    
Function Add-AADGroupMember(){

    <#
    .SYNOPSIS
    This function is used to add an member to an AAD Group from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and adds a member to an AAD Group
    .EXAMPLE
    Add-AADGroupMember -GroupId $GroupId -AADMemberID $AADMemberID
    .NOTES
    NAME: Add-AADGroupMember
    #>
    
    [cmdletbinding()]
    
    param
    (
        $GroupId,
        $AADMemberId
    )
    
    # Defining Variables
    $graphApiVersion = "v1.0"
    $Resource = "groups"
        
        try {
    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource/$GroupId/members/`$ref"
    
$JSON = @"

{
            "@odata.id": "https://graph.microsoft.com/v1.0/directoryObjects/$AADMemberId"
}
        
"@
    
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $Json -ContentType "application/json"
    
        }
    
        catch {
    
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
        break
    
        }
    
    }
    
    ####################################################
    ####################################################
    
    #region Authentication
    
    write-host
    
    # Checking if authToken exists before running authentication
    if($global:authToken){
    
        # Setting DateTime to Universal time to work in all timezones
        $DateTime = (Get-Date).ToUniversalTime()
    
        # If the authToken exists checking when it expires
        $TokenExpires = ($authToken.ExpiresOn.datetime - $DateTime).Minutes
    
            if($TokenExpires -le 0){
    
            write-host "Authentication Token expired" $TokenExpires "minutes ago" -ForegroundColor Yellow
            write-host
    
                # Defining Azure AD tenant name, this is the name of your Azure Active Directory (do not use the verified domain name)
    
                if($User -eq $null -or $User -eq ""){
    
                $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
                Write-Host
    
                }
    
            $global:authToken = Get-AuthToken -User $User
    
            }
    }
    
    # Authentication doesn't exist, calling Get-AuthToken function
    
    else {
    
        if($User -eq $null -or $User -eq ""){
    
        $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
        Write-Host
    
        }
    
    # Getting the authorization token
    $global:authToken = Get-AuthToken -User $User
    
    }
    
    #endregion
    
    ####################################################
    ####################################################
    ####################################################
    
    
    
    

    $UserGroupName = "AD usersaa"
    $DeviceGroupName = "_ADusers_devices_personal"
    $Users = Get-AADGroupMembers $UserGroupName
    $Devices = Get-ManagedDevices
    $UserGroup = Get-AzADGroup $UserGroupName
    $DeviceGroup = Get-AzADGroup $DeviceGroupName
  
    Write-Host
    Write-Host "Adding managed devices to a group..." -ForegroundColor Cyan
    Write-Host "User group:  " $UserGroupName
    Write-Host "Devices group:  " $DeviceGroupName
    Write-Host
    
    
    if($Devices){
    
        Write-Host "Intune Managed Devices found:" $Devices.Count -ForegroundColor Yellow
  
        for ($i = 0; $i -lt $Devices.Count; $i++) {
            for ($ii = 0; $ii -lt $Users.Count; $ii++) {
                If ($Devices[$i].userPrincipalName -eq $Users[$ii].userPrincipalName)
                {Add-AADGroupMember -GroupId $DeviceGroup.id -AADMemberId (Get-AADdevice($Devices[$i].azureADDeviceId)).id
                Write-Host "Adding:  "$i " "  $($Devices[$i].DeviceName) " " $($Devices[$i].azureADDeviceId) " "$Devices[$i].userPrincipalName}
            }
        }         
    }
    
    else {
    
    write-host "No Intune Managed Devices found..." -f green
    Write-Host 
    
    }
    
    
    if($Users){
    
        Write-Host "Users in group "$UserGroupName " found:" $Users.Count -ForegroundColor Yellow
        Write-Host
    
       
    
    }
    
    else {
    
    write-host "No Users found in the group "$UserGroupName -f green
    Write-Host
    
    }
    
