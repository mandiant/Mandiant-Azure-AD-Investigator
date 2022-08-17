<#
Copyright 2022 Mandiant.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
#>
@{

    # Script module or binary module file associated with this manifest.
    RootModule = 'MandiantAzureADInvestigator.psm1'
    
    # Version number of this module.
    ModuleVersion = '1.0'
    
    # Supported PSEditions
    CompatiblePSEditions = 'Desktop'
    
    # ID used to uniquely identify this module
    GUID = '754cca54-2bdd-404b-9d32-a11d83cfc866'
    
    # Author of this module
    Author = 'Douglas Bienstock'
    
    # Company or vendor of this module
    CompanyName = 'Mandiant'
    
    # Description of the functionality provided by this module
    Description = 'Tooling to assist with finding information regarding UNC2452'
    
    # Minimum version of the Windows PowerShell engine required by this module
    PowerShellVersion = '4.0'
    
    # Modules that must be imported into the global environment prior to importing this module
    RequiredModules = @("AzureAD","MSOnline","ExchangeOnlineManagement")
    
    # Script files (.ps1) that are run in the caller's environment prior to importing this module.
    ScriptsToProcess = ".\Initialization.ps1"
    
    # List of all files packaged with this module
    FileList = '.\MandiantAzureADInvestigator.psm1','.\MandiantAzureADInvestigator.psd1','.\Initialization.ps1', '.\MandiantAzureADInvestigator.json'

    # Functions to Export
    FunctionsToExport = 'Connect-MandiantAzureEnvironment','Get-MandiantMailboxFolderPermissions','Invoke-MandiantCheckAuditing','Invoke-MandiantAllChecks','Get-MandiantUnc2452AuditLogs','Invoke-MandiantAuditAzureADDomains','Get-MandiantBulkUAL','Invoke-MandiantAuditAzureADServicePrincipals','Invoke-MandiantAuditAzureADApplications','Invoke-MandiantGetCSPInformation','Disconnect-MandiantAzureEnvironment', 'Get-MandiantApplicationImpersonationHolders'
  
    }
    
    