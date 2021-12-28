<#
Copyright 2021 FireEye, Inc.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
#>
function Get-ServicePrincipalPermissions {
    <#
      .SYNOPSIS
      Helper function to map Azure AD permissions
    #>
    Param(
        [Parameter(Mandatory = $True)]
        [PSObject]$Assignments,
        [Parameter(Mandatory = $True)]
        [PSCustomObject]$Permissions
    )

    Process {
        Try {
            $mapped_perms = @()
            foreach ($permission in $Assignments) {
                $resource_name = $permission.ResourceDisplayName
                $role_id = $permission.Id    
            
                foreach ($category in $Permissions.$resource_name.PSobject.Properties.Name) {
                    $mapped_perms += $Permissions.$resource_name.$category.$role_id
                }
            }
            return $mapped_perms
        }
        Catch {
            Write-Warning -Message 'Problem within the helper function for mapping Azure Service Principals'
            Write-Warning -Message $_
            break
        }
    }
}

function Get-ApplicationPermissions {
    <#
      .SYNOPSIS
      Helper function to map Azure AD permissions
    #>
    Param(
        [Parameter(Mandatory = $True)]
        [PSObject]$App,
        [Parameter(Mandatory = $True)]
        [PSCustomObject]$Permissions
    )

    Process {
        Try {
            $mapped_perms = @()
            foreach ($permission in $App.RequiredResourceAccess) {
                $resource_id = $permission.ResourceAppId
                $required_roles = $permission.ResourceAccess.Id
            
                foreach ($category in $Permissions.$resource_id.PSobject.Properties.Name) {
                    foreach ($role_id in $required_roles) {
                        $mapped_perms += $Permissions.$resource_id.$category.$role_id
                    }
                }
                $mapped_perms
            }
        }
        Catch {
            Write-Warning -Message 'Problem within the helper function for mapping Azure Application Permissions'
            Write-Warning -Message $_
            break
        }
    }
}

function Invoke-MandiantAuditAzureADDomains {
    Param(
        [Parameter(Mandatory = $True)]
        [string]$OutputPath
    )

    <#
      .SYNOPSIS
      Audits Azure AD Domains for suspicious entries.

      .DESCRIPTION
      Domains maps to Azure AD directories that hold identity information. Authentication for each domain can be configured to be
      managed (run by Azure AD) or federated (provided by a third-party). Threat actors may create or modify federated domains to 
      give them access to Azure AD and services using Azure AD for identity.

      .EXAMPLE
      Invoke-MandiantAuditAzureADDomains -OutputPath C:\InvestigationOutput

    #>
    Process {
        Try {
            If ((Test-Path -Path $OutputPath) -eq $false) {
                Write-Verbose -Message "Output path $OutputPath does not exist creating folder"
                $null = New-Item -ItemType Directory -Path $OutputPath -Force -ErrorAction Stop
            }
        }
        Catch {
            Write-Warning -Message "Output path $OutputPath cannot be created, stopping script"
            Write-Warning -Message $_
            break
        }
        Write-Host "Checking federated domains..." -ForegroundColor Green
        Try {
            $unverified = Get-MsolDomain -Status unverified -ErrorAction Stop
            If ($unverified.Count -ge 1) {
                Write-Host -Object "`t!! An unverified domain is configured in Azure AD `n`tUnverified domains should be deleted from Azure AD" -ForegroundColor Yellow
            }
            foreach ($domain in $unverified) {
                Write-Host -Object "`t`tDomain Name : " -NoNewline -ForegroundColor Yellow 
                Write-Host -Object "`t$($domain.Name)" -ForegroundColor Red
            }
        }
        Catch {
            Write-Warning -Message 'Problem attempting to get a list of unverified domains'
            Write-Warning -Message $_
            break
        }

        Try {
            $federated = Get-MsolDomain -Authentication federated -ErrorAction Stop
            foreach ($domain in $federated) {
                $federation_data = Get-MsolDomainFederationSettings -DomainName $domain.Name -ErrorAction SilentlyContinue
                $issuer = $federation_data.IssuerUri
                [PSCustomObject]@{
                    'Domain Name'            = $domain.Name
                    'Domain Federation Name' = $federation_data.FederationBrandName
                    'Federation Issuer URI'  = $issuer
                } | Export-Csv -NoTypeInformation -Append -Path $(Join-Path -Path $OutputPath -ChildPath 'Federated Domains.csv')

                if ($issuer -match '.*\/\/any\.sts\/.*') {
                    Write-Host -Object "`t!! Evidence of AAD backdoor found. `n`tConsider performing a detailed forensic investigation" -ForegroundColor Yellow
                    Write-Host -Object "`t`tDomain Name: " -NoNewline -ForegroundColor Yellow
                    Write-Host -Object $domain.Name -ForegroundColor Red
                    Write-Host -Object "`t`tDomain federation name: " -NoNewline -ForegroundColor Yellow
                    Write-Host -Object $federation_data.FederationBrandName -ForegroundColor Red
                    Write-Host -Object "`t`tFederation issuer URI: " -NoNewline -ForegroundColor Yellow 
                    Write-Host -Object $federation_data.IssuerUri -ForegroundColor Red
                    continue
                }

                $signing_cert_base64 = $federation_data.SigningCertificate
                if ($signing_cert_base64 -ne $null) {
                    $signing_cert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2
                    $signing_cert.import([Convert]::FromBase64String($signing_cert_base64))
                    $signing_cert_subject = $signing_cert.Subject
                    $signing_cert_issuer = $signing_cert.Issuer
                    $signing_cert_not_before = $signing_cert.NotBefore
                    $signing_cert_not_after = $signing_cert.NotAfter
                    $validity_period = New-TimeSpan $signing_cert_not_before $signing_cert_not_after
                    if ($validity_period.TotalSeconds > 315336000) {
                        Write-Host -Object "`t!! A token signing certificate has a validity period of more than 365 days.`n`tThis may be evidence of a signing certificate not generated by AD FS." -ForegroundColor Yellow
                        Write-Host -Object "`t`tDomain name: " -NoNewline -ForegroundColor Yellow
                        Write-Host -Object $domain.Name -ForegroundColor Red
                        Write-Host -Object "`t`tFederation issuer uri: " -NoNewline -ForegroundColor Yellow
                        Write-Host -Object $federation_data.IssuerUri -ForegroundColor Red
                        Write-Host -Object "`t`tSigning cert not valid before: " -NoNewline -ForegroundColor Yellow
                        Write-Host -Object $signing_cert.NotAfter -ForegroundColor Red
                        Write-Host -Object "`t`tSigning cert not valid after: " -NoNewline -ForegroundColor Yellow
                        Write-Host -Object $signing_cert.NotBefore -ForegroundColor Red
                    }

                    if ($federation_data.NextSigningCertificate -ne $null) {
                        $next_signing_cert_base64 = $federation_data.NextSigningCertificate
                        $next_signing_cert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2
                        $next_signing_cert.import([Convert]::FromBase64String($next_signing_cert_base64))
                        $next_signing_cert_subject = $next_signing_cert.Subject
                        $next_signing_cert_issuer = $next_signing_cert.Issuer
                        $next_signing_cert_not_before = $next_signing_cert.NotBefore
                        $next_signing_cert_not_after = $next_signing_cert.NotAfter

                        $validity_period = New-TimeSpan $next_signing_cert_not_before $next_signing_cert_not_after
                        if ($validity_period.TotalSeconds > 315336000) {
                            Write-Host -Object "`t!! A token signing certificate has a validity period of more than 365 days.`n`tThis may be evidence of a signing certificate not generated by AD FS."
                            Write-Host -Object "`t`tDomain name: " -NoNewline -ForegroundColor Yellow
                            Write-Host -Object $domain.Name -ForegroundColor Red
                            Write-Host -Object "`t`tFederation issuer uri: " -NoNewline -ForegroundColor Yellow
                            Write-Host -Object $federation_data.IssuerUri -ForegroundColor Red
                            Write-Host -Object "`t`tSigning cert not valid before: " -NoNewline -ForegroundColor Yellow
                            Write-Host -Object $next_signing_cert.NotAfter -ForegroundColor Red
                            Write-Host -Object "`t`tSigning cert not valid after: " -NoNewline -ForegroundColor Yellow
                            Write-Host -Object $next_signing_cert.NotBefore -ForegroundColor Red
                        }

                        if ($next_signing_cert_issuer -ne $signing_cert_issuer -or $next_signing_cert_subject -ne $signing_cert_subject) {
                            Write-Host -Object "`t`t!! The signing certificate and next signing certificate do not have the same issuer or subject.`n`tThis could be a sign that one of the signing certificates has been tampered with."
                            Write-Host -Object "`t`tDomain name: " -NoNewline -ForegroundColor Yellow
                            Write-Host -Object $domain.Name -ForegroundColor Red
                            Write-Host -Object "`t`tFederation issuer uri: " -NoNewline -ForegroundColor Yellow
                            Write-Host -Object $federation_data.IssuerUri -ForegroundColor Red
                            Write-Host -Object "`t`tSigning cert subject: " -NoNewline -ForegroundColor Yellow
                            Write-Host -Object $signing_cert.Subject -ForegroundColor Red
                            Write-Host -Object "`t`tSigning cert issuer: " -NoNewline -ForegroundColor Yellow
                            Write-Host -Object $signing_cert.Issuer -ForegroundColor Red
                            Write-Host -Object "`t`tSigning cert thumbprint: " -NoNewline -ForegroundColor Yellow
                            Write-Host -Object $signing_cert.Thumbprint -ForegroundColor Red
                            Write-Host -Object "`t`tNext signing cert subject: " -NoNewline -ForegroundColor Yellow
                            Write-Host -Object $next_signing_cert.Subject -ForegroundColor Red
                            Write-Host -Object "`t`tNext signing cert issuer: " -NoNewline -ForegroundColor Yellow
                            Write-Host -Object $next_signing_cert.Issuer -ForegroundColor Red
                            Write-Host -Object "`t`tNext signing cert thumbprint: " -NoNewline -ForegroundColor Yellow 
                            Write-Host -Object $next_signing_cert.Thumbprint -ForegroundColor Red
                        }
                    } 
                }

                Write-Host -Object "`tFound federated domain.`n`t`tVerify this domain should be federated and that the IssuerUri is expected. `n`t`tNote that subdomains of a federated domain (e.g. sub.acme.com and acme.com) will automatically reported as federated, but they do not have any federation data. `n`t`tThis is a reflection of how Microsoft manages domains in Azure AD and is expected." -ForegroundColor Yellow
                Write-Host -Object "`t`tDomain name: " -NoNewline -ForegroundColor Yellow
                Write-Host -Object $domain.Name -ForegroundColor Red
                Write-Host -Object "`t`tFederation name: " -NoNewline -ForegroundColor Yellow
                Write-Host -Object $federation_data.FederationBrandName -ForegroundColor Red
                Write-Host -Object "`t`tFederation issuer uri: " -NoNewline -ForegroundColor Yellow
                Write-Host -Object $federation_data.IssuerUri -ForegroundColor Red
            }
        }
        Catch {
            Write-Warning -Message 'Problems with auditing Azure Federation settings'
            Write-Warning -Message $_
            break
        }
        
    }
}

function Get-MandiantBulkUAL {
    <#
      .SYNOPSIS
      Wrapper for the Search-UnifiedAidtLog cmdlet that automatically pages through the results up to 50,000 entries per query. 
      Currently, the default cmdlet Search-UnifiedAuditLog is limited to 5000 results per query. This can be limiting during 
      investigations within a large tenant. This cmdlet will recursively query a large session and collect up to 50,000 results. 
      Additionally, Get-BulkUAL will also attempt to handle some of exceptions that occur when collectiong large amounts of data, 
      such as Exchange returning no results.  Be patient while running this script as it is calling remote resources through a 
      Remote PowerShell Session. The default result size is set to 1000 due to observed reliability with Search-UnifiedAuditLog cmdlet

      .PARAMETER StartDate
      Start date for the query

      .PARAMETER EndDate
      End date for the query

      .PARAMETER UserIds
      UserID to to pass to the -UserIds parameter of Search-UnifiedAuditLog. This will not accept a comma separated list

      .PARAMETER Operations
      Operations to to pass to the -Operations parameter of Search-UnifiedAuditLog. This will not accept a comma separated list

      .PARAMETER FreeText
      FreeText to to pass to the -FreeText parameter of Search-UnifiedAuditLog. This will not accept a comma separated list

      .PARAMETER IPAddresses
      FreeText to to pass to the -FreeText parameter of Search-UnifiedAuditLog. This will not accept a comma separated list

      .PARAMETER DateOffset
      Number of days to search the logs for. Defaults to 90 days but can be set up to 189 days if the tenant has Cloud App Security

      .PARAMETER OutputFolder
      Path to the output file that will be written to disk. This will the AuditData JSON extracted from the PowerShell objects. 
      Each entry will be line delimeted for easy post collection parsing. The output file will always append to existing files
      to make repeeated queries

      .PARAMETER DryRun
      Will print the raw search-unifiedauditlog commands that will be executed

      .EXAMPLE
      Get-BulkUAL -StartOffset 189 -Operations UserLoggedin -UserIds josh@someaddress.com

      .EXAMPLE
      Get-BulkUal -StartDate 2020-12-21 -EndDate 2021-01-02 -UserIds "josh@someaddres.com" -IPAddresses 100.1.12.34  -OutputFile 

  #>

    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,
        [string]$OutputFile = "search",
        [ValidateRange(1, 365)]    
        [int]$DateOffset = 90,
        [int]$ResultSize = 1000,
        [datetime]$StartDate,
        [datetime]$EndDate,
        [string]$FreeText,
        [string]$Operations,
        [string]$IPAddresses,
        [string]$UserIds,
        [switch]$DryRun
    )
    begin {
        If ((Test-Path -Path $OutputPath) -eq $false) {
            $null = New-Item -ItemType Directory -Path $OutputPath
        }
    
        [string]$fileTime = Get-Date -Format FileDateTimeUniversal
        [string]$OutputFile = Join-Path -Path $OutputPath -ChildPath "UAL_$($fileTime)_$($OutputFile)_auditlog.json"
        # Validate Parameters

        # If startdate is not specified, use an the $DateOffset to select a time
        if ($StartDate -eq $null) {
            $StartDate = (Get-Date).AddDays(-$DateOffset)
        }
    
        if ($EndDate -eq $null) {
            $EndDate = (Get-Date).AddDays(1)
        }
    
        if ($EndDate -le $StartDate) {
            throw  "Error. Start Date ($StartDate)  must be earlier than End date ($EndDate)"
        }

        # SET FILTER VARIABLES
        if ($FreeText.Length -gt 0) {
            $FreeText = " -FreeText '$FreeText'"
        }
    
        if ($Operations.Length -gt 0) {
            $Operations = " -Operations '$Operations'"
        }

        if ($UserIds.Length -gt 0) {
            $UserIds = " -UserIds '$UserIds'"
        }

        if ($IPAddresses.Length -gt 0) {
            $IPAddresses = " -IPAddresses '$IPAddresses'"
        }

        $query = "Search-UnifiedAuditLog -StartDate '$StartDate' -EndDate '$EndDate' -ResultSize $($ResultSize) $($FreeText)$($Operations)$($IPAddresses)$($UserIds) -SessionCommand ReturnLargeSet" 
        Write-Verbose -Message "Base Query: $($query)"
        Add-Content -Value "$fileTime :: $query" -Path $(Join-Path -Path $OutputPath -ChildPath "UALQuerySearch.txt")
    }
    process {
   
        # Set default variable values
        $go = $True
        $error_count = 0
        $SessionName = ' -SessionID ' + (Get-Date -Format 's') + '_o365auditlog_' + (Get-Random).ToString()
        $query_error = $false

        while ($go -eq $True) {
            # Run the Error Status checks
            Write-Verbose -Message "Error Count: $($error_count)"
            if ($error_count -eq 3) {
                Write-Host -Object 'Failed three time to collect results. There is either an undeteremined error or there really is no results for the query. '
            }

            if ($query_error -eq $True) {
                Write-Host -Object 'There was an error getting results from Exchange Online. Retrying the query with a new session identifer.'
                $SessionName = ' -SessionID ' + (Get-Date -Format 's') + '_o365auditlog_' + (Get-Random).ToString()
                $final_query = $query + $SessionName
                $query_error = $false
            }
        
            else {
                # continue with previously generated Session Name
                $final_query = $query + $SessionName
                # Reset the error counter
                $error_count = 0
            }

            # Run the UAL search and log debugging information
            Write-Verbose -Message "Final Query: $($final_query)"
            Write-Debug -Message $final_query
        
            Try {
                $search_expression = Invoke-Expression -Command $final_query -ErrorAction SilentlyContinue
            }
            Catch {
                Write-Warning -Message "Problem Invoking Expression :: $final_query"
                Write-Warning -Message $_
            }
        
            $resultcount = ($search_expression | Measure-Object -Property ResultCount -Maximum).Maximum
            $resultindex = ($search_expression | Measure-Object -Property ResultIndex -Maximum).Maximum
            Write-Verbose  -Message "Collected $($resultindex) of $($resultcount) events"

            ### Exception handling for some of the nuances of the Search-UnifiedAuditLog command
            if ($resultcount -ge 50000) {
                Write-Error -Message 'Query returned more than 50,000 results; data is being missed. Narrow the time window and rerun the collection. The below query was NOT executed successfully'
                Write-Error $final_query
                Write-Error -Message 'Exiting query session'
                $go = $false
            }
            elseif ($resultcount -eq 0 -and $resultindex -eq -1) {
                $query_error = $True
                $error_count++
                continue
            }
            elseif ($null -eq $resultcount) {
                Write-Host -Object 'Query returned no results'
                Write-Host -Object $final_query
                $go = $false
            }
            elseif ($resultindex -gt $resultcount) {
                Write-Verbose -Message 'The result index is greater than the result count. Rerunning the query '
                Write-Error -Message 'The result index is greater than the result count. Rerunning the query '
                $query_error = $True
                $error_count++
                continue
            }
        
            try {
                $percent = [math]::Round(($resultindex / $resultcount * 100) , 2)
            }
            catch [System.DivideByZeroException] {
                $percent = 0
            }
        
            Write-Progress -Activity 'Searching Unified Audit Log' -Status "$($percent)% Complete" -PercentComplete $percent
        
            # Write the reults to the appropriate output file
            $search_expression |
            Select-Object -ExpandProperty AuditData |
            Out-File -Append -Encoding UTF8 -FilePath $OutputFile
            # Reset error counter
            $error_count = 0
        
            if ($resultindex -eq $resultcount) {
                $go = $false
                # return $true
            }
        }
    }
}

function Invoke-MandiantAuditAzureADServicePrincipals {
    <#
      .SYNOPSIS
      Audits Azure AD Service Principals (Enterprise Applications) for suspicious entries.

      .DESCRIPTION
      Azure AD Service Principals (Enterprise Applications in the Azure Portal) can be backdoored by threat actors.
      This module looks for Azure AD Service Principals that have certificates and/or secrets assigned to them
      and are assigned high-privilege AppRoles. It also looks for so-called "first-party" Service Principals with
      credentials assigned. Service Principals matching this criteria should be investigated.
    #>
    Param(
        [Parameter(Mandatory = $false)]
        [Switch]$IncludeRisky,
        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )
    Process {
      
        If ((Test-Path -Path $OutputPath) -eq $false) {
            Write-Verbose -Message "Output path $OutputPath does not exist creating folder"
            $null = New-Item -ItemType Directory -Path $OutputPath -Force -ErrorAction Stop
        }
                 
        [string]$ModulePath = (get-module -ListAvailable MandiantAzureADInvestigator).Path
        if([string]::IsNullOrEmpty($ModulePath)) {
            $ModulePath = ".\MandiantAzureADInvestigator.psd1"
        }
        [string]$Configfile = $ModulePath.Replace(".psd1", ".json")
        If ((Test-Path -Path $Configfile) -eq $true) {
            Write-Verbose -Message "Configuration File : $ConfigFile"
            $defs = (Get-Content -Path $Configfile | ConvertFrom-Json).ServicePrincipals
        }
        else {
            Write-Warning -Message "Configuration JSON cannot be located : $Configfile"
            Write-Warning -Message $_
            break
        }

        Try {
            Write-Host -Object "Checking for suspicious Service Principals..." -ForegroundColor Green
            $service_principals = Get-AzureADServicePrincipal -All $True

            $results = @()
            $first_party_sps = @()
            foreach ($service_principal in $service_principals) {
                if (($service_principal.PasswordCredentials.Count -ne 0 -or $service_principal.KeyCredentials.Count -ne 0)) {
                    if (($service_principal.AppOwnerTenantId -eq 'f8cdef31-a31e-4b4a-93e4-5f571e91255a')) {
                        $first_party_sps += [PSCustomObject]@{
                            'Object ID'            = $service_principal.ObjectId
                            'App ID'               = $service_principal.AppId
                            'Display Name'         = $service_principal.DisplayName
                            'Key Credentials'      = ($service_principal.KeyCredentials | Out-String)
                            'Password Credentials' = ($service_principal.PasswordCredentials | Out-String)
                        }
                    }
                    else {
                        $app_roles = $service_principal | Get-AzureADServiceAppRoleAssignedTo
                        $hit = $false
                        foreach ($app_role in $app_roles) {
                            $resource_name = $app_role.ResourceDisplayName
                            $perm = $app_role.Id

                            foreach ($category in $defs.$resource_name.PSObject.Properties.Name) {
                                $risky = $defs.$resource_name.$category.PSObject.Properties.Name
                                if ($risky -contains $perm) {
                                    $perms = Get-ServicePrincipalPermissions -Assignments $app_roles -Permissions $defs

                                    $results += [PSCustomObject]@{
                                        'Object ID'            = $service_principal.ObjectId
                                        'App ID'               = $service_principal.AppId
                                        'Display Name'         = $service_principal.DisplayName
                                        'Key Credentials'      = ($service_principal.KeyCredentials | Out-String)
                                        'Password Credentials' = ($service_principal.PasswordCredentials | Out-String)
                                        'Risky Permissions'    = ($perms | Out-String)
                                    }
                                    
                                    $hit = $True
                                    break
                                }
                            }
                            if ($hit) {
                                break
                            }
                        }
                    }
                }
            }

            if ($first_party_sps.Count -gt 0) {
                Write-Host -Object '!! Identified first-party (Microsoft published) Service Principals with added credentials.' -ForegroundColor Yellow
                Write-Host -Object 'Only in rare cases should a first-party Service Principal have an added credential.'
                Write-Host -Object 'Environments that are or were in hybrid-mode for Exchange, Skype, and AAD Password Protection may have false positives.'
                Write-Host -Object 'Verify that the added credential has a legitimate use case and consider further investigation if not'
                foreach($object in $first_party_sps){
                    Write-Host -Object "*******************************************************************"
                    Write-Host -Object "Object ID           : " -NoNewLine -ForegroundColor Cyan   
                    Write-Host -Object $object.'Object ID'
                    Write-Host -Object "App ID              : " -NoNewLine -ForegroundColor Cyan   
                    Write-Host -Object $object.'App ID'
                    Write-Host -Object "Display Name        : " -NoNewLine -ForegroundColor Cyan  
                    Write-Host -Object $object.'Display Name'
                    Write-Host -Object "Key Credentials     : " -NoNewLine -ForegroundColor Cyan  
                    Write-Host -Object $object.'Key Credentials'
                    Write-Host -Object "Password Credentials: " -NoNewLine -ForegroundColor Cyan 
                    Write-Host -Object $object.'Password Credentials'
                }
                $first_party_sps | Export-Csv -NoTypeInformation -Path $(Join-Path -Path $OutputPath -ChildPath 'first-party service principals.csv')
            }

            if ($results.Count -gt 0) {
                Write-Host -Object '!! Identified Service Principals with high-risk API permissions and added credentials.' -ForegroundColor Yellow
                Write-Host -Object 'Verify that the added credential has a legitimate use case and consider further investigation if not'
                ForEach($object in $results){
                    Write-Host -Object "*******************************************************************"
                    Write-Host -Object "Object ID           :  " -NoNewLine -ForegroundColor Cyan 
                    Write-Host -Object $object.'Object ID'
                    Write-Host -Object "App ID              :  " -NoNewLine -ForegroundColor Cyan 
                    Write-Host -Object $object.'App ID'
                    Write-Host -Object "Display Name        :  " -NoNewLine -ForegroundColor Cyan 
                    Write-Host -Object $object.'Display Name'
                    Write-Host -Object "Key Credentials     :  " -NoNewLine -ForegroundColor Cyan 
                    Write-Host -Object $object.'Key Credentials'
                    Write-Host -Object "Password Credentials:  " -NoNewLine -ForegroundColor Cyan 
                    Write-Host -Object $object.'Password Credentials'
                    Write-Host -Object "Risky Permissions   :  " -NoNewLine -ForegroundColor Cyan 
                    Write-Host -Object $object.'Risky Permissions'
                }
                #Write-Host -Object $results.Values
                $results | Export-Csv -NoTypeInformation -Path $(Join-Path -Path $OutputPath -ChildPath 'service principals.csv')
            }
        

        }
        Catch {
            Write-Warning -Message 'Problem extracting Service Principal Information'
            Write-Warning -Message $_
            break
        }
    }
}

function Invoke-MandiantGetCSPInformation {
    <#
    .SYNOPSIS
    Checks the tenant to see if the tenant has any Partner access configured.
    
    .DESCRIPTION
    Microsoft's CSP program allows for external companies to manage customer tenants. 
    Customers can permit the partner to access their tenant as a "delegated admin", accessing
    the tenant with Global Admin Permissions. This can present a risk if the partner is compromised.
    #>

    Process {
        Write-Host -Object "Checking for partner relationships..." -ForegroundColor Green
        $partnerInfo = Get-MsolPartnerInformation
        if($partnerInfo.DapEnabled -eq $true)
        {
            Write-Host -Object "!! Identified partner relationship with Delegated Admin enabled" -ForegroundColor Yellow
            Write-Host -Object "This means that a partner can access your tenant with the same privileges as a Global Admin."
            Write-Host -Object "Verify if this level of privilege is necessary and remove it if not. Go to the Partner Relationships setting in the 365 Admin Center to manage this."
            Write-Host -Object "If necessary, consider implementing Conditional Access Policies to limit partner access to certain IP addresses"

        } else {
            Write-Host -Object "No partner relationship found."
            Write-Host -Object "Make sure to run this check with Global Administrator account as partner relationships are not visible to global or security reader roles."
        }
        
        Write-Host -Object "Checking for partner groups in EXO Role Groups..." -ForegroundColor Green
        $rg = Get-RoleGroup | ? Capabilities -match Partner_Managed | ? Members -match PartnerRoleGroup
        if ($rg)
        {
            Write-Host -Object "!! Identified Exchange Online Role Groups that contain partner groups" -ForegroundColor Yellow
            Write-Host -Object "This means that a partner may have access to your tenant with elevated privileged."
            Write-Host -Object "Verify if this level of privilege is necessary and remove it if not. Go to the Partner Relationships setting in the 365 Admin Center to manage this."
            Write-Host -Object "If necessary, consider implementing Conditional Access Policies to limit partner access to certain IP addresses"
        } else {
            Write-Host -Object "No partner groups found in EXO Role Groups."
        }

    }
}
function Invoke-MandiantAuditAzureADApplications {
    Param(
        [Parameter(Mandatory = $true)]
        $OutputPath
    )
    <#
      .SYNOPSIS
      Audits Azure AD Applications (App Registrations) for suspicious entries.

      .DESCRIPTION
      Azure AD Applications (App Registrations in the Azure Portal) can be backdoored by threat actors.
      This module looks for Azure AD Applications that have certificates and/or secrets assigned to them
      and are assigned high-privilege AppRoles. Applications matching this criteria should be investigated.
    #>
    Process {
        If ((Test-Path -Path $OutputPath) -eq $false) {
            Write-Verbose -Message "Output path $OutputPath does not exist creating folder"
            $null = New-Item -ItemType Directory -Path $OutputPath -Force -ErrorAction Stop
        }
                 
        [string]$ModulePath = (get-module -ListAvailable MandiantAzureADInvestigator).Path
        if([string]::IsNullOrEmpty($ModulePath)) {
            $ModulePath = ".\MandiantAzureADInvestigator.psd1"
        }
        [string]$Configfile = $ModulePath.Replace(".psd1", ".json")
        If ((Test-Path -Path $Configfile) -eq $true) {
            Write-Verbose -Message "Config File $ConfigFile"
            $defs = (Get-Content -Path $Configfile | ConvertFrom-Json).Applications
        }
        else {
            Write-Warning -Message "Configuration JSON cannot be located : $Configfile"
            Write-Warning -Message $_
            break
        }
          
        Try {
            Write-Host -Object "Checking for suspicious Azure AD App Registrations..." -ForegroundColor Green
            $apps = Get-AzureADApplication -All $True

            $results = @()
            foreach ($App in $apps) {
                Write-Verbose -Message "Application Name : $($app.DisplayName) :: $($App.id)"
                if ($App.PasswordCredentials.Count -ne 0 -or $App.KeyCredentials.Count -ne 0) {
                    $hit = $false
                    foreach ($permission in $App.RequiredResourceAccess) {
                        Write-Verbose -Message "Permission :: $permission"
                        $resource_id = $permission.ResourceAppId 
                        $requiredRoles = $permission.ResourceAccess.Id
                        foreach ($category in $defs.$resource_id.PSObject.Properties.Name) {
                            Write-Verbose -Message "Category :: $category"
                            $risky = $defs.$resource_id.$category.PSObject.Properties.Name
                            $res = Compare-Object -ReferenceObject $risky -DifferenceObject $requiredRoles -PassThru -IncludeEqual -ExcludeDifferent
                            if ($res -ne $null) {
                                $Permissions = Get-ApplicationPermissions -App $App -Permissions $defs
                                
                                $results += [PSCustomObject]@{
                                    'Object ID'            = $App.ObjectId
                                    'App ID'               = $App.AppId
                                    'Display Name'         = $App.DisplayName
                                    'Key Credentials'      = ($App.KeyCredentials | Out-String)
                                    'Password Credentials' = ($App.PasswordCredentials | Out-String)
                                    'Risky Permissions'    = ($Permissions | Out-String)
                                }
                            
                                $hit = $True
                                break
                            }
                        }
                        if ($hit) {
                            break
                        }
                    }
                }
            }
            if ($results.Count -gt 0) {
                ForEach($object in $results){
                    Write-Host -Object '!! Identified Applications with high-risk API permissions and added credentials.' -ForegroundColor Yellow
                    Write-Host -Object 'Verify that the added credential has a legitimate use case and consider further investigation if not'
                    Write-Host -Object "*******************************************************************"
                    Write-Host -Object "Object ID           :  " -NoNewLine -ForegroundColor Cyan 
                    Write-Host -Object $object.'Object ID'
                    Write-Host -Object "App ID              :  " -NoNewLine -ForegroundColor Cyan 
                    Write-Host -Object $object.'App ID'
                    Write-Host -Object "Display Name        :  " -NoNewLine -ForegroundColor Cyan 
                    Write-Host -Object $object.'Display Name'
                    Write-Host -Object "Key Credentials     :  " -NoNewLine -ForegroundColor Cyan 
                    Write-Host -Object $object.'Key Credentials'
                    Write-Host -Object "Password Credentials:  " -NoNewLine -ForegroundColor Cyan 
                    Write-Host -Object $object.'Password Credentials'
                    Write-Host -Object "Risky Permissions   :  " -NoNewLine -ForegroundColor Cyan 
                    Write-Host -Object $object.'Risky Permissions'
                }
                $results | Export-Csv -NoTypeInformation -Path $(Join-Path -Path $OutputPath -ChildPath "applications.csv")
            }
        }
        Catch {
            Write-Warning -Message "Problem identifying high risk applications"
            Write-Warning -Message $_
            break
        }  
    }
}

function Connect-MandiantAzureEnvironment {
    <#
      .SYNOPSIS
      Connects to all three Azure Environments in order to execute queries within this PowerShell Module

      .DESCRIPTION
      In order to execute the various commands against the different types of Azure Environments connecting to them all

    #>
    Param(
        [Parameter(Mandatory = $True)]
        [string]$UserPrincipalName,
        [Parameter(ParameterSetName = 'AltCloud', Mandatory = $True)]
        [Parameter(ParameterSetName = 'Standard', Mandatory = $false)]
        [switch]$isAlternateCloud,
        [Parameter(ParameterSetName = 'AltCloud', Mandatory = $True)]
        [ValidateSet('O365China', 'O365Default', 'O365GermanyCloud', 'O365USGovDoD', 'O365USGovGCCHigh')]
        [string]$ExchangeEnvironment,
        [Parameter(ParameterSetName = 'AltCloud', Mandatory = $True)]
        [ValidateSet('AzureChinaCloud', 'AzureCloud', 'AzureGermanyCloud', 'AzurePPE', 'AzureUSGovernment', 'AzureUSGovernment2', 'AzureUSGovernment3')]
        [string]$AzureADEnvironment,
        [Parameter(ParameterSetName = 'AltCloud', Mandatory = $True)]
        [ValidateSet('AzureChinaCloud', 'AzureCloud', 'AzureGermanyCloud', 'AzureOneBox', 'AzurePPE', 'AzureUSGovernmentCloud', 'AzureUSGovernmentCloud2', 'AzureUSGovernmentCloud3', 'USGovernment')]
        [string]$MsolEnvironment
    )

    Try {
        If ($isAlternateCloud -ne $True) {
            $MsolEnvironment = 'AzureCloud'
            $ExchangeEnvironment = 'O365Default'
            $AzureADEnvironment = 'AzureCloud'
        }

        # Connecting to MsolService
        Write-Verbose -Message "Connecting to Azure Environment - Alternate Cloud: $isAlternateCloud"
        Write-Verbose -Message "Connecting to MsolService for: $MsolEnvironment"
        Connect-MsolService -AzureEnvironment $MsolEnvironment -ErrorAction Stop
        # Connecting to AzureAD
        Write-Verbose -Message "Connecting to Azure AD for $AzureADEnvironment"
        Connect-AzureAD -AccountId $UserPrincipalName -AzureEnvironmentName $AzureADEnvironment -ErrorAction Stop
        # Connecting to Exchange Online
        Write-Verbose -Message "Connecting to Exchange Online for $ExchangeEnvironment"
        Connect-ExchangeOnline -UserPrincipalName $UserPrincipalName -ExchangeEnvironmentName $ExchangeEnvironment -ErrorAction Stop
    }
    catch {
        Write-Warning -Message 'Problem connecting to Azure Environment'
        Write-Warning -Message $_
        break
    }
}


function Get-MandiantUnc2452AuditLogs
{
    Param(
        [Parameter(Mandatory = $true)]
        $OutputPath
    )
    <#
    .SYNOPSIS
    Function to get known event log entries for UNC2452 within the Unified Audit Log. By default it searches the last 90 days worth of logs
    #>

    Process
    {
        If ((Test-Path -Path $OutputPath) -eq $false) {
            Write-Verbose -Message "Output path $OutputPath does not exist creating folder"
            $null = New-Item -ItemType Directory -Path $OutputPath -Force -ErrorAction Stop
        }
                 
        [string]$ModulePath = (get-module -ListAvailable MandiantAzureADInvestigator).Path
        if([string]::IsNullOrEmpty($ModulePath)) {
            $ModulePath = ".\MandiantAzureADInvestigator.psd1"
        }
        [string]$Configfile = $ModulePath.Replace(".psd1", ".json")
        If ((Test-Path -Path $Configfile) -eq $true) {
            Write-Verbose -Message "Config File $ConfigFile"
            $defs = (Get-Content -Path $Configfile | ConvertFrom-Json).DefaultAuditQueries
        }
        else {
            Write-Warning -Message "Configuration JSON cannot be located : $Configfile"
            Write-Warning -Message $_
            break
        }
        
        
        foreach ($query in $defs.UNC2452){

            $outputfile = $query.outputfile
            $bulkquery = "$($query.Query) -DateOffset $($query.dateoffset) -OutputFile $($outputfile) -OutputPath $($OutputPath)"

            write-host $query.description
            $results = Invoke-Expression $bulkquery

        }
    }
}

function Get-MandiantApplicationImpersonationHolders
{
    Param(
        [Parameter(Mandatory = $true)]
        $OutputPath
    )
    Try {
        If ((Test-Path -Path $OutputPath) -eq $false) {
            Write-Verbose -Message "Output path $OutputPath does not exist creating folder"
            $null = New-Item -ItemType Directory -Path $OutputPath -Force -ErrorAction Stop
        }
        Write-Host -Object "Auditing ApplicationImpersonation role holders..." -ForegroundColor Green
        Write-Host -Object "Results are written to application_impersonation_holders.csv. If the file is empty, then no users or groups hold this role." -ForegroundColor Green
        $AppImperGroups = Get-RoleGroup | Where-Object Roles -like ApplicationImpersonation
        ForEach ($Group in $AppImperGroups){
            Get-RoleGroupMember $Group.Name | Export-Csv -NoTypeInformation -Append -Path $(Join-Path -Path $OutputPath -ChildPath "application_impersonation_holders.csv")
        }       
    } catch {
        Write-Warning -Message 'Problem auditing Application Impersonation'
        Write-Warning -Message $_
        break
    }
}
function Get-MandiantMailboxFolderPermissions
{
    Param(
        [Parameter(Mandatory = $true)]
        $OutputPath
    )
    Try {
        If ((Test-Path -Path $OutputPath) -eq $false) {
            Write-Verbose -Message "Output path $OutputPath does not exist creating folder"
            $null = New-Item -ItemType Directory -Path $OutputPath -Force -ErrorAction Stop
        }
        Write-Host -Object "Auditing mailbox folder permissions..." -ForegroundColor Green
        Write-Host -Object "This may take awhile (an hour+ if you have a large tenant) hold tight..." -ForegroundColor Green
        Write-Host -Object "Results are written to folder_permissions.csv. If the file is empty you have nothing to do!" -ForegroundColor Green
        $mailboxes = Get-EXOMailbox -ResultSize Unlimited

        [int]$i = 0

        foreach ($mbox in $mailboxes) {
            Write-Progress -Activity "Processing Mailbox $i of $($mailboxes.count)" -PercentComplete ($i/$mailboxes.count*100) -CurrentOperation "User : $($mbox.UserPrincipalName)"
    
            Try{
                #Retrieve Top of Information Store (root) permissions for Anonymous and Default user. Output results if permissions are not set to None
                Get-EXOMailboxFolderPermission -Identity ($mbox.UserPrincipalName) -ErrorAction SilentlyContinue | `
                Where-Object {$_.AccessRights -ne "None" -and ($_.User -match "Anonymous" -or $_.User -match "Default")} | `
                Select-Object  @{Name = 'UserPrincipalName'; Expression = {$mbox.UserPrincipalName}}, FolderName,User,@{Label="AccessRights";Expression={$_.AccessRights -join ","}} | `
                Export-Csv -NoTypeInformation -Append -Path $(Join-Path -Path $OutputPath -ChildPath "folder_permissions.csv")

                #Retrieve Inbox folder permissions for Anonymous and Default user. Output results if permissions are not set to None
                Get-EXOMailboxFolderPermission -Identity ($mbox.UserPrincipalName + ':\inbox') -ErrorAction SilentlyContinue | `
                Where-Object {$_.AccessRights -ne "None" -and ($_.User -match "Anonymous" -or $_.User -match "Default")} | `
                Select-Object  @{Name = 'UserPrincipalName'; Expression = {$mbox.UserPrincipalName}}, FolderName,User,@{Label="AccessRights";Expression={$_.AccessRights -join ","}} | `
                Export-Csv -NoTypeInformation -Append -Path $(Join-Path -Path $OutputPath -ChildPath "folder_permissions.csv")

                $i++

            } Catch {
                Write-Warning -Message "Problem accessing Mailbox Folders permissions for $($mbox.UserPrincipalName)."
                continue
            }
        }


    } catch {
        Write-Warning -Message 'Problem auditing mailbox folder permissions'
        Write-Warning -Message $_
        break
    }
}
function Invoke-MandiantAllChecks
{
    Param(
        [Parameter(Mandatory = $true)]
        $OutputPath
    )
    <#
    .SYNOPSIS
    Wrapper function to run all checks.

    #>
    Process
    {
        
        Write-Host "Running all checks..."
        Invoke-MandiantAuditAzureADApplications -OutputPath $OutputPath
        Invoke-MandiantAuditAzureADServicePrincipals -OutputPath $OutputPath
        Invoke-MandiantAuditAzureADDomains -OutputPath $OutputPath
        Invoke-MandiantGetCSPInformation
        Get-MandiantMailboxFolderPermissions -OutputPath $OutputPath
        Get-MandiantUnc2452AuditLogs -OutputPath $OutputPath
        Get-MandiantApplicationImpersonationHolders -OutputPath $OutputPath
        
    }
}
function Disconnect-MandiantAzureEnvironment {
    <#
      .SYNOPSIS
      Disconnects all two of Azure Environments in order to execute queries within this PowerShell Module

      .DESCRIPTION
      This will disconnect from all the different Azure Environments, it is best to disconnect sessions when you are finished
      
    #>
    Try{
        # Disconnecting to MsolService
        Write-Verbose -Message "Disconnecting to Azure Environment"
        # Connecting to AzureAD
        Write-Verbose -Message "Disconnecting to Azure AD"
        Disconnect-AzureAD
        # Connecting to Exchange Online
        Write-Verbose -Message "Disconnecting to Exchange Online"
        Disconnect-ExchangeOnline
    }
    catch {
        Write-Warning -Message 'Problem Disconnecting to Azure Environment'
        Write-Warning -Message $_
        break
    }
}
