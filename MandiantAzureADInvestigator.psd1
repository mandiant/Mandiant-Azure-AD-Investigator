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
    CompanyName = 'FireEye Mandiant'
    
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
    FunctionsToExport = 'Connect-MandiantAzureEnvironment','Invoke-MandiantAllChecks','Get-MandiantUnc2542AuditLogs','Invoke-MandiantAuditAzureADDomains','Get-MandiantBulkUAL','Invoke-MandiantAuditAzureADServicePrincipals','Invoke-MandiantAuditAzureADApplications','Disconnect-MandiantAzureEnvironment'
  
    }
    
    