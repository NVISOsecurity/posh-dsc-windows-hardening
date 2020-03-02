Configuration AuditPolicy_WindowsServer2016
{
    param
    (
        [String] $NodeName = 'localhost'
    )

    Import-DscResource -ModuleName 'AuditPolicyDsc'
    Import-DscResource -ModuleName 'ComputerManagementDsc'
    Import-DscResource -ModuleName 'SecurityPolicyDsc'
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'

    Node $NodeName
    {
        # 1: wevtutil sl Security /ms:540100100
        WindowsEventLog Security
        {
           LogName            = 'Security'
           IsEnabled          = $true
           LogMode            = 'Circular'
           MaximumSizeInBytes = 500MB         
        }

        #::250MB
        # 2: wevtutil sl Application /ms:256000100
        WindowsEventLog Application
        {
           LogName            = 'Application'
           IsEnabled          = $true
           LogMode            = 'Circular'
           MaximumSizeInBytes = 250MB  
        }

        #::250MB
        # 3: wevtutil sl Setup /ms:256000100
        WindowsEventLog Setup
        {
           LogName            = 'Setup'
           IsEnabled          = $true
           LogMode            = 'Circular'
           MaximumSizeInBytes = 250MB    
        }

        #::250MB
        # 4: wevtutil sl System /ms:256000100
        WindowsEventLog System
        {
           LogName            = 'System'
           IsEnabled          = $true
           LogMode            = 'Circular'
           MaximumSizeInBytes = 250MB  
        }

        #wevtutil epl System C:\backup\system0506.evtx
        #::250MB
        # 5: wevtutil sl "Windows Powershell" /ms:256000100 (3.5 days)
        WindowsEventLog 'Windows Powershell'
        {
           LogName            = 'Windows Powershell'
           IsEnabled          = $true
           LogMode            = 'Circular'
           MaximumSizeInBytes = 250MB   
        }

        #500MB (Estimate)
        # 6: wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:524288000
        WindowsEventLog 'Microsoft-Windows-PowerShell/Operational'
        {
           LogName            = 'Microsoft-Windows-PowerShell/Operational'
           IsEnabled          = $true
           LogMode            = 'Circular'
           MaximumSizeInBytes = 500MB
        }

        #500MB (Estimate)
        # 7: wevtutil sl "Microsoft-Windows-Sysmon/Operational" /ms:524288000
        # WARNING! Need to have Sysmon installed
        # WindowsEventLog 'Microsoft-Windows-Sysmon/Operational'
        # {
        #    LogName            = 'Microsoft-Windows-Sysmon/Operational'
        #    IsEnabled          = $true
        #    LogMode            = 'Circular'
        #    MaximumSizeInBytes = 500MB
        # }

        #reg add "hklm\software\microsoft\windows\currentversion\policies\system\audit" /v ProcessCreationIncludeCmdLine_Enabled /t #REG_DWORD /d 1
        Registry 'ProcessCreationIncludeCmdLine_Enabled2' {
           Ensure     = 'Present'
           Key        = 'HKEY_LOCAL_MACHINE/SOFTWARE/Microsoft/Windows/CurrentVersion/Policies/System/Audit/'
           ValueName  = 'ProcessCreationIncludeCmdLine_Enabled'
           ValueType  = 'DWord'
           ValueData  = '1'
        }
        #::  Force Advance Audit Policy
        #Reg add "hklm\System\CurrentControlSet\Control\Lsa" /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1
        #  
        Registry 'SCENoApplyLegacyAuditPolicy' {
           Ensure     = 'Present'
           Key        = 'HKEY_LOCAL_MACHINE/system/CurrentControlSet/Control/Lsa/'
           ValueName  = 'SCENoApplyLegacyAuditPolicy'
           ValueType  = 'DWord'
           ValueData  = '1'
        }

        #:
        #reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f
        #  
        Registry 'EnableModuleLogging' {
           Ensure     = 'Present'
           Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
           ValueName  = 'EnableModuleLogging'
           ValueType  = 'DWord'
           ValueData  = '1'
        }

        #:
        #reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging," /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
        # WARNING! Already present in the other file! This could generate a conflict!
        Registry 'EnableScriptBlockLogging2' {
           Ensure     = 'Present'
           Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
           ValueName  = 'EnableScriptBlockLogging'
           ValueType  = 'DWord'
           ValueData  = '1'
        }
        #reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableInvocationHeader /t REG_DWORD /d 1 /f
        # 
        Registry 'EnableInvocationHeader' {
           Ensure     = 'Present'
           Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
           ValueName  = 'EnableInvocationHeader'
           ValueType  = 'DWord'
           ValueData  = '1'
        }

        #reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableTranscripting /t REG_DWORD /d 1 /f
        #  Warning! Already present in the other file! This could generate a conflict!
        Registry 'EnableTranscripting2' {
           Ensure     = 'Present'
           Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
           ValueName  = 'EnableTranscripting'
           ValueType  = 'DWord'
           ValueData  = '1'
        }

        #reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v OutputDirectory /t REG_SZ /d "C:\temp" /f
        # 
        Registry 'OutputDirectory' {
           Ensure     = 'Present'
           Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
           ValueName  = 'OutputDirectory'
           ValueType  = 'String'
           ValueData  = 'C:\temp'
        }

        #Source: https://github.com/PowerShell/AuditPolicyDsc/blob/dev/Examples/Sample_AuditPolicyGuid.ps1
        # 1, Success: enable, Failure: enable
        # Auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
        AuditPolicySubcategory "Audit Credential Validation (Success)"
        {
            Name      = 'Credential Validation'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Credential Validation (Failure)'
        {
            Name      = 'Credential Validation'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        # 2, Success: disable, Failure: disable
        # Auditpol /set /subcategory:"Kerberos Authentication Service" /success:disable /failure:disable
        AuditPolicySubcategory "Audit Kerberos Authentication Service (Success)"
        {
            Name      = 'Kerberos Authentication Service'
            AuditFlag = 'Success'
            Ensure    = 'Absent'
        }

        AuditPolicySubcategory 'Audit Kerberos Authentication Service (Failure)'
        {
            Name      = 'Kerberos Authentication Service'
            AuditFlag = 'Failure'
            Ensure    = 'Absent'
        }

        # 3, Success: disable, Failure: disable
        # Auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:disable /failure:disable
        AuditPolicySubcategory "Audit Kerberos Service Ticket Operations (Success)"
        {
            Name      = 'Kerberos Service Ticket Operations'
            AuditFlag = 'Success'
            Ensure    = 'Absent'
        }

        AuditPolicySubcategory 'Kerberos Service Ticket Operations (Failure)'
        {
            Name      = 'Kerberos Service Ticket Operations'
            AuditFlag = 'Failure'
            Ensure    = 'Absent'
        }

        # 4, Success: enable, Failure: enable
        # Auditpol /set /subcategory:"Other Account Logon Events" /success:enable /failure:enable
        AuditPolicySubcategory "Audit Other Account Logon Events (Success)"
        {
            Name      = 'Other Account Logon Events'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Other Account Logon Events (Failure)'
        {
            Name      = 'Other Account Logon Events'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        # 5, Success: disable, Failure: disable
        # Auditpol /set /subcategory:"Application Group Management" /success:disable /failure:disable
        AuditPolicySubcategory 'Audit Application Group Management (Success)'
        {
            Name      = 'Application Group Management'
            AuditFlag = 'Success'
            Ensure    = 'Absent'
        }

        AuditPolicySubcategory 'Audit Application Group Management (Failure)'
        {
            Name      = 'Application Group Management'
            AuditFlag = 'Failure'
            Ensure    = 'Absent'
        }

        # 6, Success: enable, Failure: enable
        # Auditpol /set /subcategory:"Computer Account Management" /success:enable /failure:enable
        AuditPolicySubcategory 'Audit Computer Account Management (Success)' 
        {
            Name      = 'Computer Account Management'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Computer Account Management (Failure)' 
        {
            Name      = 'Computer Account Management'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

    
        # 7, Success: enable, Failure: enable
        # Auditpol /set /subcategory:"Distribution Group Management" /success:enable /failure:enable
        AuditPolicySubcategory 'Audit Distribution Group Management (Success)' 
        {
            Name      = 'Distribution Group Management'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Distribution Group Management (Failure)' 
        {
            Name      = 'Distribution Group Management'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        # 8, Success:enable, Failure:enable
        # Auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
        AuditPolicySubcategory 'Audit Security Group Management (Success)' 
        {
            Name      = 'Security Group Management'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Security Group Management (Failure)' 
        {
            Name      = 'Security Group Management'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        # 9, Success:enable, Failure:enable
        # Auditpol /set /subcategory:"Other Account Management Events" /success:enable /failure:enable
        AuditPolicySubcategory 'Audit Other Account Management Events (Success)' 
        {
            Name      = 'Other Account Management Events'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Other Account Management Events (Failure)' 
        {
            Name      = 'Other Account Management Events'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        # 10, Success:enable, Failure:enable
        # Auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
        AuditPolicySubcategory 'Audit User Account Management (Success)' 
        {
            Name      = 'User Account Management'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit User Account Management (Failure)' 
        {
            Name      = 'User Account Management'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        # 11, Success:enable, Failure:enable
        # Auditpol /set /subcategory:"Process Termination" /success:enable /failure:enable
        AuditPolicySubcategory 'Audit Process Termination (Success)'
        {
            Name      = 'Process Termination'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Process Termination (Failure)'
        {
            Name      = 'Process Termination'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        # 12, Success:disable, Failure:disable
        # Auditpol /set /subcategory:"DPAPI Activity" /success:disable /failure:disable
        AuditPolicySubcategory 'Audit DPAPI Activity (Success)'

        {
            Name      = 'DPAPI Activity'
            AuditFlag = 'Success'
            Ensure    = 'Absent'
        }

        AuditPolicySubcategory 'Audit DPAPI Activity (Failure)'
        {
            Name      = 'DPAPI Activity'
            AuditFlag = 'Failure'
            Ensure    = 'Absent'
        }

        # 13, Success:enable, Failure:enable
        # Auditpol /set /subcategory:"RPC Events" /success:enable /failure:enable
        AuditPolicySubcategory 'Audit RPC Events (Success)'
        {
            Name      = 'RPC Events'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit RPC Events (Failure)'
        {
            Name      = 'RPC Events'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }
        
        # 14, Success:enable, Failure:enable
        # Auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
        AuditPolicySubcategory 'Audit Process Creation (Success)' 
        {
            Name      = 'Process Creation'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Process Creation (Failure)' 
        {
            Name      = 'Process Creation'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        # 15, Success:disable, Failure:disable
        # Auditpol /set /subcategory:"Detailed Directory Service Replication" /success:disable /failure:disable
        AuditPolicySubcategory 'Audit Detailed Directory Service Replication (Success)'
        {
            Name      = 'Detailed Directory Service Replication'
            AuditFlag = 'Success'
            Ensure    = 'Absent'
        }

        AuditPolicySubcategory 'Audit Detailed Directory Service Replication (Failure)'
        {
            Name      = 'Detailed Directory Service Replication'
            AuditFlag = 'Failure'
            Ensure    = 'Absent'
        }
        

        # 16, Success:disable, Failure:disable
        # Auditpol /set /subcategory:"Directory Service Access" /success:disable /failure:disable
        AuditPolicySubcategory 'Directory Service Access (Success)' 
        {
            Name      = 'Directory Service Access'
            AuditFlag = 'Success'
            Ensure    = 'Absent'
        }

        AuditPolicySubcategory 'Directory Service Access (Failure)' 
        {
            Name      = 'Directory Service Access'
            AuditFlag = 'Failure'
            Ensure    = 'Absent'
        }

        # 17, Success:enable, Failure:enable
        # Auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
        AuditPolicySubcategory 'Directory Service Changes (Success)' 
        {
            Name      = 'Directory Service Changes'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Directory Service Changes (Failure)' 
        {
            Name      = 'Directory Service Changes'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        # 18, Success:disable, Failure:disable
        # Auditpol /set /subcategory:"Directory Service Replication" /success:disable /failure:disable
        AuditPolicySubcategory 'Audit Directory Service Replication (Success)'
        {
            Name      = 'Directory Service Replication'
            AuditFlag = 'Success'
            Ensure    = 'Absent'
        }

        AuditPolicySubcategory 'Audit Directory Service Replication (Failure)'
        {
            Name      = 'Directory Service Replication'
            AuditFlag = 'Failure'
            Ensure    = 'Absent'
        }


        # 19, Success:enable, Failure:disable
        # Auditpol /set /subcategory:"Account Lockout" /success:enable /failure:disable
        AuditPolicySubcategory 'Audit Account Lockout (Success)' 
        {
            Name      = 'Account Lockout' 
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Account Lockout (Failure)' 
        {
            Name      = 'Account Lockout'
            AuditFlag = 'Failure'
            Ensure    = 'Absent'
        }

        # 20, Success:disable, Failure:disable
        # Auditpol /set /subcategory:"IPsec Extended Mode" /success:disable /failure:disable
        AuditPolicySubcategory 'Audit IPsec Extended Mode (Success)'
        {
            Name      = 'IPsec Extended Mode'
            AuditFlag = 'Success'
            Ensure    = 'Absent'
        }

        AuditPolicySubcategory 'Audit IPsec Extended Mode (Failure)'
        {
            Name      = 'IPsec Extended Mode'
            AuditFlag = 'Failure'
            Ensure    = 'Absent'
        }

        # 21, Success:disable, Failure:disable
        # Auditpol /set /subcategory:"IPsec Main Mode" /success:disable /failure:disable
        AuditPolicySubcategory 'Audit IPsec Main Mode (Success)'
        {
            Name      = 'IPsec Main Mode'
            AuditFlag = 'Success'
            Ensure    = 'Absent'
        }

        AuditPolicySubcategory 'Audit IPsec Main Mode (Failure)'
        {
            Name      = 'IPsec Main Mode'
            AuditFlag = 'Failure'
            Ensure    = 'Absent'
        }

        # 22, Success:disable, Failure:disable
        # Auditpol /set /subcategory:"IPsec Quick Mode" /success:disable /failure:disable
        AuditPolicySubcategory 'Audit IPsec Quick Mode (Success)'
        {
            Name      = 'IPsec Quick Mode'
            AuditFlag = 'Success'
            Ensure    = 'Absent'
        }

        AuditPolicySubcategory 'Audit IPsec Quick Mode (Failure)'
        {
            Name      = 'IPsec Quick Mode'
            AuditFlag = 'Failure'
            Ensure    = 'Absent'
        }

        # 23, Success:enable, Failure:disable
        # Auditpol /set /subcategory:"Logoff" /success:enable /failure:disable
        AuditPolicySubcategory 'Audit Logoff (Success)' 
        {
            Name      = 'Logoff'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Logoff (Failure)' 
        {
            Name      = 'Logoff'
            AuditFlag = 'Failure'
            Ensure    = 'Absent'
        }

        # 24, Success:enable, Failure:enable
        # Auditpol /set /subcategory:"Logon" /success:enable /failure:enable 
        AuditPolicySubcategory 'Audit Logon (Success)' 
        {
            Name      = 'Logon'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Logon (Failure)' 
        {
            Name      = 'Logon'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        # 25, Success:disable, Failure:disable
        # Auditpol /set /subcategory:"Network Policy Server" /success:disable /failure:disable
        AuditPolicySubcategory 'Audit Network Policy Server (Success)'
        {
            Name      = 'Network Policy Server'
            AuditFlag = 'Success'
            Ensure    = 'Absent'
        }

        AuditPolicySubcategory 'Audit Network Policy Server (Failure)'
        {
            Name      = 'Network Policy Server'
            AuditFlag = 'Failure'
            Ensure    = 'Absent'
        }

        # 26, Success:enable, Failure:enable
        # Auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable
        AuditPolicySubcategory 'Audit Other Logon/Logoff Events (Failure)' 
        {
            Name      = 'Other Logon/Logoff Events'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Other Logon/Logoff Events (Success)' 
        {
            Name      = 'Other Logon/Logoff Events'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        # 27, Success:enable, Failure:disable
        # Auditpol /set /subcategory:"Special Logon" /success:enable /failure:disable
        AuditPolicySubcategory 'Audit Special Logon (Success)' 
        {
            Name      = 'Special Logon'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Special Logon (Failure)' 
        {
            Name      = 'Special Logon'
            AuditFlag = 'Failure'
            Ensure    = 'Absent'
        }

        # 28, Success:enable, Failure:enable
        # Auditpol /set /subcategory:"Application Generated" /success:enable /failure:enable
        AuditPolicySubcategory 'Audit Application Generated (Success)'
        {
            Name      = 'Application Generated'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Application Generated (Failure)'
        {
            Name      = 'Application Generated'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        # 29, Success:enable, Failure:enable
        # Auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable
        AuditPolicySubcategory 'Audit Certification Services (Success)'
        {
            Name      = 'Certification Services'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Certification Service (Failure)'
        {
            Name      = 'Certification Services'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        # 30, Success:enable
        # Auditpol /set /subcategory:"Detailed File Share" /success:enable
        AuditPolicySubcategory 'Audit Detailed File Share (Success)'
        {
            Name      = 'Detailed File Share'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        # 31, Success:enable, Failure:enable
        # Auditpol /set /subcategory:"File Share" /success:enable /failure:enable
        AuditPolicySubcategory 'Audit File Share (Success)'
        {
            Name      = 'File Share'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit File Share (Failure)'
        {
            Name      = 'File Share'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        # 32, Success:enable, Failure:enable
        # Auditpol /set /subcategory:"File System" /success:enable /failure:enable
        AuditPolicySubcategory 'Audit File System (Success)'
        {
            Name      = 'File System'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit File System (Failure)'
        {
            Name      = 'File System'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        # 33, Success:enable, Failure:disable
        # Auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:disable
        AuditPolicySubcategory 'Audit Filtering Platform Connection (Success)'
        {
            Name      = 'Filtering Platform Connection'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Filtering Platform Connection (Failure)'
        {
            Name      = 'Filtering Platform Connection'
            AuditFlag = 'Failure'
            Ensure    = 'Absent'
        }

        # 34, Success:disable, Failure:disable
        # Auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:disable /failure:disable
        AuditPolicySubcategory 'Audit Filtering Platform Packet Drop (Success)'
        {
            Name      = 'Filtering Platform Packet Drop'
            AuditFlag = 'Success'
            Ensure    = 'Absent'
        }

        AuditPolicySubcategory 'Audit Filtering Platform Packet Drop (Failure)'
        {
            Name      = 'Filtering Platform Packet Drop'
            AuditFlag = 'Failure'
            Ensure    = 'Absent'
        }

        # 35, Success:disable, Failure:disable
        # Auditpol /set /subcategory:"Handle Manipulation" /success:disable /failure:disable
        AuditPolicySubcategory 'Audit Handle Manipulation (Success)'
        {
            Name      = 'Handle Manipulation'
            AuditFlag = 'Success'
            Ensure    = 'Absent'
        }

        AuditPolicySubcategory 'Audit Handle Manipulation (Failure)'
        {
            Name      = 'Handle Manipulation'
            AuditFlag = 'Failure'
            Ensure    = 'Absent'
        }

        # 36, Success:enable, Failure:enable
        # Auditpol /set /subcategory:"Kernel Object" /success:enable /failure:enable
        AuditPolicySubcategory 'Audit Kernel Object (Success)'
        {
            Name      = 'Kernel Object'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Kernel Object (Failure)'
        {
            Name      = 'Kernel Object'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        # 37, Success:disable, Failure:disable
        # Auditpol /set /subcategory:"Other Object Access Events" /success:disable /failure:disable
        AuditPolicySubcategory 'Audit Other Object Access Events (Success)'
        {
            Name      = 'Other Object Access Events'
            AuditFlag = 'Success'
            Ensure    = 'Absent'
        }

        AuditPolicySubcategory 'Audit Other Object Access Events (Failure)'
        {
            Name      = 'Other Object Access Events'
            AuditFlag = 'Failure'
            Ensure    = 'Absent'
        }

        # 38, Success:enable
        # Auditpol /set /subcategory:"Registry" /success:enable
        AuditPolicySubcategory 'Audi Registry (Success)'
        {
            Name      = 'Registry'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        # 39, Success:enable, Failure:enable
        # Auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable
        AuditPolicySubcategory 'Audit Removable Storage (Success)' {
            Name      = 'Removable Storage'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Removable Storage (Failure)' {
            Name      = 'Removable Storage'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        # 40, Success:disable, Failure:disable
        # Auditpol /set /subcategory:"SAM" /success:disable /failure:disable
        AuditPolicySubcategory 'Audit SAM (Success)'
        {
            Name      = 'SAM'
            AuditFlag = 'Success'
            Ensure    = 'Absent'
        }

        AuditPolicySubcategory 'Audit SAM (Failure)'
        {
            Name      = 'SAM'
            AuditFlag = 'Failure'
            Ensure    = 'Absent'
        }

        # 41, Success:enable, Failure:enable
        # Auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
        AuditPolicySubcategory 'Audit Policy Change (Success)' 
        {
            Name      = 'Audit Policy Change'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Policy Change (Failure)' 
        {
            Name      = 'Audit Policy Change'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        # 42, Success:enable, Failure:disable
        # Auditpol /set /subcategory:"Authentication Policy Change" /success:enable /failure:disable
        AuditPolicySubcategory 'Audit Authentication Policy Change (Success)' 
        {
            Name      = 'Authentication Policy Change'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Authentication Policy Change (Failure)' 
        {
            Name      = 'Authentication Policy Change'
            AuditFlag = 'Failure'
            Ensure    = 'Absent'
        }

        # 43, Success:enable, Failure:enable
        # Auditpol /set /subcategory:"Authorization Policy Change" /success:enable /failure:enable
        AuditPolicySubcategory 'Audit Authorization Policy Change (Success)' 
        {
            Name      = 'Authorization Policy Change'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Authorization Policy Change (Failure)' 
        {
            Name      = 'Authorization Policy Change'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        # 44, Success:disable, Failure:disable
        # Auditpol /set /subcategory:"Filtering Platform Policy Change" /success:disable /failure:disable
        AuditPolicySubcategory 'Audit Filtering Platform Policy Change (Success)'
        {
            Name      = 'Filtering Platform Policy Change'
            AuditFlag = 'Success'
            Ensure    = 'Absent'
        }

        AuditPolicySubcategory 'Audit Filtering Platform Policy Change (Failure)'
        {
            Name      = 'Filtering Platform Policy Change'
            AuditFlag = 'Failure'
            Ensure    = 'Absent'
        }

        
        # 45, Success:disable, Failure:disable
        # Auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:disable /failure:disable
        AuditPolicySubcategory 'Audit MPSSVC Rule-Level Policy Change (Success)'
        {
            Name      = 'MPSSVC Rule-Level Policy Change'
            AuditFlag = 'Success'
            Ensure    = 'Absent'
        }

        AuditPolicySubcategory 'Audit MPSSVC Rule-Level Policy Change (Failure)'
        {
            Name      = 'MPSSVC Rule-Level Policy Change'
            AuditFlag = 'Failure'
            Ensure    = 'Absent'
        }
     
        # 46, Success:disable, Failure:disable
        # Auditpol /set /subcategory:"Other Policy Change Events" /success:disable /failure:disable
        AuditPolicySubcategory 'Audit Other Policy Change Events (Success)'
        {
            Name      = 'Other Policy Change Events'
            AuditFlag = 'Success'
            Ensure    = 'Absent'
        }

        AuditPolicySubcategory 'Audit Other Policy Change Events (Failure)'
        {
            Name      = 'Other Policy Change Events'
            AuditFlag = 'Failure'
            Ensure    = 'Absent'
        }

        # 47, Success:disable, Failure:disable
        # Auditpol /set /subcategory:"Other Privilege Use Events" /success:disable /failure:disable
        AuditPolicySubcategory 'Audit Other Privilege Use Events (Success)'
        {
            Name      = 'Other Privilege Use Events'
            AuditFlag = 'Success'
            Ensure    = 'Absent'
        }

        AuditPolicySubcategory 'Audit Other Privilege Use Events (Failure)'
        {
            Name      = 'Other Privilege Use Events'
            AuditFlag = 'Failure'
            Ensure    = 'Absent'
        }

        # 48, Success:disable, Failure:disable
        # Auditpol /set /subcategory:"Non Sensitive Privilege Use" /success:disable /failure:disable
        AuditPolicySubcategory 'Audit Non Sensitive Privilege Use (Success)'
        {
            Name      = 'Non Sensitive Privilege Use'
            AuditFlag = 'Success'
            Ensure    = 'Absent'
        }

        AuditPolicySubcategory 'Audit Non Sensitive Privilege Use (Failure)'
        {
            Name      = 'Non Sensitive Privilege Use'
            AuditFlag = 'Failure'
            Ensure    = 'Absent'
        }

        # 49, Success:enable, Failure:enable
        # Auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
        AuditPolicySubcategory 'Audit Sensitive Privilege Use (Failure)' 
        {
            Name      = 'Sensitive Privilege Use'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Sensitive Privilege Use (Success)' 
        {
            Name      = 'Sensitive Privilege Use'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        # 50, Success:enable, Failure:enable
        # Auditpol /set /subcategory:"IPsec Driver" /success:enable /failure:enable
        AuditPolicySubcategory 'Audit IPsec Driver (Failure)' 
        {
            Name      = 'IPsec Driver'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit IPsec Driver (Success)' 
        {
            Name      = 'IPsec Driver'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        # 51, Success:enable, Failure:enable
        # Auditpol /set /subcategory:"Other System Events" /success:enable /failure:enable
        AuditPolicySubcategory 'Audit Other System Events (Failure)' 
        {
            Name      = 'Other System Events'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Other System Events (Success)' 
        {
            Name      = 'Other System Events'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        # 52, Success:enable, Failure:enable
        # Auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
        AuditPolicySubcategory 'Audit Security State Change (Success)' 
        {
            Name      = 'Security State Change'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Security State Change (Failure)' 
        {
            Name      = 'Security State Change'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        # 53, Success:enable, Failure:enable 
        # Auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable
        AuditPolicySubcategory 'Audit Security System Extension (Failure)' 
        {
            Name      = 'Security System Extension'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Security System Extension (Success)' 
        {
            Name      = 'Security System Extension'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        # 54, Success:enable, Failure:enable
        # Auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable
        AuditPolicySubcategory 'Audit System Integrity (Failure)' 
        {
            Name      = 'System Integrity'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit System Integrity (Success)' 
        {
            Name      = 'System Integrity'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

    }
}

AuditPolicy_WindowsServer2016