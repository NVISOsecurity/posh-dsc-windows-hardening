# Configuration Definition
Configuration AzSC_CCEv4_WindowsServer2016 {
    param (
        [string[]]$NodeName ='localhost'
        )
 
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'AuditPolicyDsc'
    Import-DscResource -ModuleName 'SecurityPolicyDsc'
 
    Node $NodeName {
      AccountPolicy AccountPolicies
        {
            Name                                        = 'PasswordPolicies'

            # CceId: CCE-37166-6
            # DataSource: BaselineSecurityPolicyRule
            # Ensure 'Enforce password history' is set to '24 or more password'
            Enforce_password_history                    = 24

            # CceId: CCE-37167-4
            # DataSource: BaselineSecurityPolicyRule
            # Ensure 'Maximum password age' is set to '70 or fewer days, but not 0'
            Maximum_Password_Age                        = 70

            # CceId: CCE-37073-4
            # DataSource: BaselineSecurityPolicyRule
            # Ensure 'Minimum password age' is set to '1 or more day'
            Minimum_Password_Age                        = 1

            # CceId: CCE-36534-6
            # DataSource: BaselineSecurityPolicyRule
            # Ensure 'Minimum password length' is set to '14 or more character'
            Minimum_Password_Length                     = 14

            # CceId: CCE-37063-5
            # DataSource: BaselineSecurityPolicyRule
            # Ensure 'Password must meet complexity requirements' is set to 'Enabled'
            Password_must_meet_complexity_requirements  = 'Enabled'

            # CceId: CCE-36286-3
            # DataSource: BaselineSecurityPolicyRule
            # Ensure 'Store passwords using reversible encryption' is set to 'Disabled'
            Store_passwords_using_reversible_encryption = 'Disabled'
        }

        # CceId: CCE-35818-4
        # DataSource: BaselineSecurityPolicyRule
        # Configure 'Access this computer from the network'
        UserRightsAssignment Accessthiscomputerfromthenetwork {
            Policy       = 'Access_this_computer_from_the_network'
            Identity     = 'Administrators, Authenticated Users'
        }

        # CceId: CCE-37072-6
        # DataSource: BaselineSecurityPolicyRule
        # Configure 'Allow log on through Remote Desktop Services'
       UserRightsAssignment AllowlogonthroughRemoteDesktopServices {
        Policy       = 'Allow_log_on_through_Remote_Desktop_Services'
        Identity     = 'Administrators, Remote Desktop Users' 
        }

        # CceId: CCE-35823-4
        # DataSource: BaselineSecurityPolicyRule
        # Configure 'Create symbolic links'
       UserRightsAssignment Createsymboliclinks {
        Policy       = 'Create_symbolic_links'
        Identity     = 'Administrators'
        }
        
        # CceId: CCE-37954-5
        # DataSource: BaselineSecurityPolicyRule
        # Configure 'Deny access to this computer from the network'
        UserRightsAssignment Denyaccesstothiscomputerfromthenetwork {
            Policy       = 'Deny_access_to_this_computer_from_the_network'
            Identity     = 'Guests, Local Account'
         }

        # CceId: CCE-36860-5
        # DataSource: BaselineSecurityPolicyRule
        # Configure 'Enable computer and user accounts to be trusted for delegation'
        UserRightsAssignment Enablecomputeranduseraccountstobetrustedfordelegation {
            Policy       = 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
            Identity     = ''
         }

        # CceId: CCE-35906-7
        # DataSource: BaselineSecurityPolicyRule
        # Configure 'Manage auditing and security log'
        UserRightsAssignment Manageauditingandsecuritylog {
            Policy       = 'Manage_auditing_and_security_log'
            Identity     = 'Administrators'
         }

        # CceId: CCE-37056-9
        # DataSource: BaselineSecurityPolicyRule
        # Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'
        UserRightsAssignment AccessCredentialManagerasatrustedcaller {
            Policy       = 'Access_Credential_Manager_as_a_trusted_caller'
            Identity     = ''
         }

        # CceId: CCE-36876-1
        # DataSource: BaselineSecurityPolicyRule
        # Ensure 'Act as part of the operating system' is set to 'No One'
        UserRightsAssignment Actaspartoftheoperatingsystem {
            Policy       = 'Act_as_part_of_the_operating_system'
            Identity     = ''
         }

        # CceId: CCE-35912-5
        # DataSource: BaselineSecurityPolicyRule
        # Ensure 'Back up files and directories' is set to 'Administrators'
        UserRightsAssignment Backupfilesanddirectories {
            Policy       = 'Back_up_files_and_directories'
            Identity     = 'Administrators,Backup Operators'
         }

        # CceId: CCE-37452-0
        # DataSource: BaselineSecurityPolicyRule
        # Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE'
        UserRightsAssignment Changethesystemtime {
            Policy       = 'Change_the_system_time'
            Identity     = 'Administrators, LOCAL SERVICE'
         }

        # CceId: CCE-37700-2
        # DataSource: BaselineSecurityPolicyRule       
        # Ensure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE'
        UserRightsAssignment Changethetimezone {
            Policy       = 'Change_the_time_zone'
            Identity     = 'Administrators, LOCAL SERVICE'
         }

        # CceId: CCE-35821-8
        # DataSource: BaselineSecurityPolicyRule
        # Ensure 'Create a pagefile' is set to 'Administrators'
        UserRightsAssignment Createapagefile {
            Policy       = 'Create_a_pagefile'
            Identity     = 'Administrators'
         }

        # CceId: CCE-36861-3
        # DataSource: BaselineSecurityPolicyRule
        # Ensure 'Create a token object' is set to 'No One'
        UserRightsAssignment Createatokenobject {
            Policy       = 'Create_a_token_object'
            Identity     = ''
         }

        # CceId: CCE-37453-8
        # DataSource: BaselineSecurityPolicyRule
        # Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
        UserRightsAssignment Createglobalobjects {
            Policy       = 'Create_global_objects'
            Identity     = 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
         }

        # CceId: CCE-36532-0
        # DataSource: BaselineSecurityPolicyRule
        # Ensure 'Create permanent shared objects' is set to 'No One'
        UserRightsAssignment Createpermanentsharedobjects {
            Policy       = 'Create_permanent_shared_objects'
            Identity     = ''
         }

        # CceId: CCE-36923-1
        # DataSource: BaselineSecurityPolicyRule
        # Ensure 'Deny log on as a batch job' to include 'Guests'
        UserRightsAssignment Denylogonasabatchjob {
            Policy       = 'Deny_log_on_as_a_batch_job'
            Identity     = 'Guests'
         }

        # CceId: CCE-36877-9
        # DataSource: BaselineSecurityPolicyRule
        # Ensure 'Deny log on as a service' to include 'Guests'
        UserRightsAssignment Denylogonasaservice {
            Policy       = 'Deny_log_on_as_a_service'
            Identity     = 'Guests'
         }

        # CceId: CCE-37146-8
        # DataSource: BaselineSecurityPolicyRule
        # Ensure 'Deny log on locally' to include 'Guests'
        UserRightsAssignment Denylogonlocally {
            Policy       = 'Deny_log_on_locally'
            Identity     = 'Guests'
         }

        # CceId: CCE-36867-0
        # DataSource: BaselineSecurityPolicyRule
        # Ensure 'Deny log on through Remote Desktop Services' to include 'Guests'
        UserRightsAssignment DenylogonthroughRemoteDesktopServices {
            Policy       = 'Deny_log_on_through_Remote_Desktop_Services'
            Identity     = 'Guests'
         }

        # CceId: CCE-37877-8
        # DataSource: BaselineSecurityPolicyRule
        # Ensure 'Force shutdown from a remote system' is set to 'Administrators'
        UserRightsAssignment Forceshutdownfromaremotesystem {
            Policy       = 'Force_shutdown_from_a_remote_system'
            Identity     = 'Administrators'
         }

        # CceId: CCE-37639-2
        # DataSource: BaselineSecurityPolicyRule
        # Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'
        UserRightsAssignment Generatesecurityaudits {
            Policy       = 'Generate_security_audits'
            Identity     = 'LOCAL SERVICE, NETWORK SERVICE'
         }

        # CceId: CCE-38326-5
        # DataSource: BaselineSecurityPolicyRule
        # Ensure 'Increase scheduling priority' is set to 'Administrators'
        UserRightsAssignment Increaseschedulingpriority {
            Policy       = 'Increase_scheduling_priority'
            Identity     = 'Administrators'
         }

        # CceId: CCE-36318-4
        # DataSource: BaselineSecurityPolicyRule
        # Ensure 'Load and unload device drivers' is set to 'Administrators'
        UserRightsAssignment Loadandunloaddevicedrivers {
            Policy       = 'Load_and_unload_device_drivers'
            Identity     = 'Administrators'
         }

        # CceId: CCE-36495-0
        # DataSource: BaselineSecurityPolicyRule
        # Ensure 'Lock pages in memory' is set to 'No One'
        UserRightsAssignment Lockpagesinmemory {
            Policy       = 'Lock_pages_in_memory'
            Identity     = ''
         }

        # CceId: CCE-36054-5
        # DataSource: BaselineSecurityPolicyRule
        # Ensure 'Modify an object label' is set to 'No One'
        UserRightsAssignment Modifyanobjectlabel {
            Policy       = 'Modify_an_object_label'
            Identity     = ''
         }

        # CceId: CCE-38113-7
        # DataSource: BaselineSecurityPolicyRule
        # Ensure 'Modify firmware environment values' is set to 'Administrators'
        UserRightsAssignment Modifyfirmwareenvironmentvalues {
            Policy       = 'Modify_firmware_environment_values'
            Identity     = 'Administrators'
         }

        # CceId: CCE-36143-6
        # DataSource: BaselineSecurityPolicyRule
        # Ensure 'Perform volume maintenance tasks' is set to 'Administrators'
        UserRightsAssignment Performvolumemaintenancetasks {
            Policy       = 'Perform_volume_maintenance_tasks'
            Identity     = 'Administrators'
         }

        # CceId: CCE-37131-0
        # DataSource: BaselineSecurityPolicyRule
        # Ensure 'Profile single process' is set to 'Administrators'
        UserRightsAssignment Profilesingleprocess {
            Policy       = 'Profile_single_process'
            Identity     = 'Administrators'
         }

        # CceId: CCE-36052-9
        # DataSource: BaselineSecurityPolicyRule
        # Ensure 'Profile system performance' is set to 'Administrators, NT SERVICE\WdiServiceHost'
        UserRightsAssignment Profilesystemperformance {
            Policy       = 'Profile_system_performance'
            Identity     = 'Administrators,WdiServiceHost'
         }

        # CceId: CCE-37430-6
        # DataSource: BaselineSecurityPolicyRule
        # Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE'
        UserRightsAssignment Replaceaprocessleveltoken {
            Policy       = 'Replace_a_process_level_token'
            Identity     = 'LOCAL SERVICE, NETWORK SERVICE'
         }

        # CceId: CCE-37613-7
        # DataSource: BaselineSecurityPolicyRule
        # Ensure 'Restore files and directories' is set to 'Administrators, Backup Operators'
        UserRightsAssignment Restorefilesanddirectories {
            Policy       = 'Restore_files_and_directories'
            Identity     = 'Administrators, Backup Operators'
         }

        # CceId: CCE-38328-1
        # DataSource: BaselineSecurityPolicyRule
        # Ensure 'Shut down the system' is set to 'Administrators'
        UserRightsAssignment Shutdownthesystem {
            Policy       = 'Shut_down_the_system'
            Identity     = 'Administrators'
         }

        # CceId: CCE-38325-7
        # DataSource: BaselineSecurityPolicyRule
        # Ensure 'Take ownership of files or other objects' is set to 'Administrators'
        UserRightsAssignment Takeownershipoffilesorotherobjects {
            Policy       = 'Take_ownership_of_files_or_other_objects'
            Identity     = 'Administrators'
         }

        # CceId: NOT_ASSIGNED
        # DataSource: BaselineSecurityPolicyRule
        # Bypass traverse checking
        UserRightsAssignment Bypasstraversechecking {
            Policy       = 'Bypass_traverse_checking'
            Identity     = 'Administrators, Authenticated Users, Backup Operators, Local Service, Network Service'
         }

        # CceId: NOT_ASSIGNED
        # DataSource: BaselineSecurityPolicyRule
        # Increase a process working set
        UserRightsAssignment Increaseaprocessworkingset {
            Policy       = 'Increase_a_process_working_set'
            Identity     = 'Administrators, Local Service'
         }

        # CceId: NOT_ASSIGNED
        # DataSource: BaselineSecurityPolicyRule
        # Remove computer from docking station
        UserRightsAssignment Removecomputerfromdockingstation {
            Policy       = 'Remove_computer_from_docking_station'
            Identity     = 'Administrators'
         }

       SecurityOption AccountSecurityOptions {
          Name                                   = 'AccountSecurityOptions'

          # CceId: CCE-37615-2
          # DataSource: BaselineRegistryRule
          # Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'
          Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only = 'Enabled'

          # CceId: CCE-35907-5
          # DataSource: BaselineRegistryRule
          # Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'
          Audit_Shut_down_system_immediately_if_unable_to_log_security_audits = 'Disabled'

          # CceId: CCE-37942-0
          # DataSource: BaselineRegistryRule
          # Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'
          Devices_Prevent_users_from_installing_printer_drivers = 'Enabled'

          # CceId: CCE-36142-8
          # DataSource: BaselineRegistryRule
          # Ensure 'Domain member: Digitally encrypt or sign secure channel data ' is set to 'Enabled'
          Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always = 'Enabled'          

          # CceId: CCE-37130-2
          # DataSource: BaselineRegistryRule
          # Ensure 'Domain member: Digitally encrypt secure channel data ' is set to 'Enabled'
          Domain_member_Digitally_encrypt_secure_channel_data_when_possible = 'Enabled'

          # CceId: CCE-37222-7
          # DataSource: BaselineRegistryRule
          # Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'
          Domain_member_Digitally_sign_secure_channel_data_when_possible = 'Enabled'

          # CceId: CCE-37508-9
          # DataSource: BaselineRegistryRule
          # Ensure 'Domain member: Disable machine account password changes' is set to 'Disabled'
          Domain_member_Disable_machine_account_password_changes = 'Disabled'

          # CceId: CCE-37431-4
          # DataSource: BaselineRegistryRule
          # Ensure 'Domain member: Maximum machine account password age' is set to '30 or fewer days, but not 0'
          Domain_member_Maximum_machine_account_password_age = '30'

          # CceId: CCE-37614-5
          # DataSource: BaselineRegistryRule
          # Ensure 'Domain member: Require strong session key' is set to 'Enabled'
          Domain_member_Require_strong_Windows_2000_or_later_session_key = 'Enabled'

          # CceId: CCE-36056-0
          # DataSource: BaselineRegistryRule
          # Ensure 'Interactive logon: Do not display last user name' is set to 'Enabled'
          Interactive_logon_Do_not_display_last_user_name = 'Enabled'

          # CceId: CCE-37637-6
          # DataSource: BaselineRegistryRule
          # Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'
          Interactive_logon_Do_not_require_CTRL_ALT_DEL = 'Disabled' 

          # CceId: CCE-36325-9
          # DataSource: BaselineRegistryRule
          # Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'
          Microsoft_network_client_Digitally_sign_communications_always = 'Enabled'

          # CceId: CCE-36269-9
          # DataSource: BaselineRegistryRule
          # Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled'
          Microsoft_network_client_Digitally_sign_communications_if_server_agrees = 'Enabled'

          # CceId: CCE-37863-8
          # DataSource: BaselineRegistryRule
          # Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled' 
          Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers = 'Disabled'

          # CceId: CCE-38046-9
          # DataSource: BaselineRegistryRule
          # Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute, but not 0'
          Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session = '15' 

          # CceId: CCE-37864-6
          # DataSource: BaselineRegistryRule
          # Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'
          Microsoft_network_server_Digitally_sign_communications_always = 'Enabled'

          # CceId: CCE-35988-5
          # DataSource: BaselineRegistryRule
          # Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled'
          Microsoft_network_server_Digitally_sign_communications_if_client_agrees = 'Enabled'

          # CceId: CCE-37972-7
          # DataSource: BaselineRegistryRule
          # Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled'
          Microsoft_network_server_Disconnect_clients_when_logon_hours_expire = 'Enabled' 

          # CceId: CCE-36077-6
          # DataSource: BaselineRegistryRule
          # Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled'
          Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares = 'Enabled'

          # CceId: CCE-36316-8
          # DataSource: BaselineRegistryRule
          # Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled'
          Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts = 'Enabled'

          # CceId: CCE-36148-5
          # DataSource: BaselineRegistryRule
          # Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled'
          Network_access_Let_Everyone_permissions_apply_to_anonymous_users = 'Disabled' 

          # CceId: CCE-36021-4
          # DataSource: BaselineRegistryRule
          # Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled'
          Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares = 'Enabled' 

          # CceId: CCE-37623-6
          # DataSource: BaselineRegistryRule
          # Ensure 'Network access: Sharing and security model for local accounts' is set to 'Classic - local users authenticate as themselves' 
          Network_access_Sharing_and_security_model_for_local_accounts = 'Classic - Local users authenticate as themselves'

          # CceId: CCE-37035-3
          # DataSource: BaselineRegistryRule
          # Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled'
          Network_security_Allow_LocalSystem_NULL_session_fallback = 'Disabled'

          # CceId: CCE-38047-7
          # DataSource: BaselineRegistryRule
          # Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled'
          Network_security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities = 'Disabled'

          # CceId: CCE-36326-7
          # DataSource: BaselineRegistryRule
          # Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled'
          Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change = 'Enabled'

          # CceId: CCE-36858-9
          # DataSource: BaselineRegistryRule
          # Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher
          Network_security_LDAP_client_signing_requirements = 'Negotiate Signing' 

          # CceId: CCE-37553-5
          # DataSource: BaselineRegistryRule
          # Ensure 'Network security: Minimum session security for NTLM SSP based clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'
          Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients = 'Both options checked' 

          # CceId: CCE-37835-6
          # DataSource: BaselineRegistryRule
          # Ensure 'Network security: Minimum session security for NTLM SSP based servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'
          Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers = 'Both options checked' 

          # CceId: CCE-36788-8
          # DataSource: BaselineRegistryRule
          # Ensure 'Shutdown: Allow system to be shut down without having to log on' is set to 'Disabled'
          Shutdown_Allow_system_to_be_shut_down_without_having_to_log_on = 'Disabled'

          # CceId: CCE-37885-1
          # DataSource: BaselineRegistryRule
          # Ensure 'System objects: Require case insensitivity for non-Windows subsystems' is set to 'Enabled'
          System_objects_Require_case_insensitivity_for_non_Windows_subsystems = 'Enabled' 

          # CceId: CCE-37644-2
          # DataSource: BaselineRegistryRule
          # Ensure 'System objects: Strengthen default permissions of internal system objects ' is set to 'Enabled'
          System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links = 'Enabled'

          # CceId: CCE-36494-3
          # DataSource: BaselineRegistryRule
          # Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled'
          User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account = 'Enabled'

          # CceId: CCE-36863-9
          # DataSource: BaselineRegistryRule
          # Ensure 'User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop' is set to 'Disabled'
          User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop = 'Disabled'

          # CceId: CCE-37029-6
          # DataSource: BaselineRegistryRule
          # Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop'
          User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode = 'Prompt for consent on the secure desktop'

          # CceId: CCE-36864-7
          # DataSource: BaselineRegistryRule
          # Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'
          User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users = 'Automatically deny elevation request'

          # CceId: CCE-36533-8
          # DataSource: BaselineRegistryRule
          # Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled'
          User_Account_Control_Detect_application_installations_and_prompt_for_elevation = 'Enabled'

          # CceId: CCE-37057-7
          # DataSource: BaselineRegistryRule
          # Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled'
          User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations = 'Enabled'

          # CceId: CCE-36869-6
          # DataSource: BaselineRegistryRule
          # Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled'
          User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode = 'Enabled'

          # CceId: CCE-36866-2
          # DataSource: BaselineRegistryRule
          # Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled'
          User_Account_Control_Switch_to_the_secure_desktop_when_prompting_for_elevation = 'Enabled'

          # CceId: CCE-37064-3
          # DataSource: BaselineRegistryRule
          # Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled'
          User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations = 'Enabled'

          # CceId: NOT_ASSIGNED
          # DataSource: BaselineRegistryRule
          # Recovery console: Allow floppy copy and access to all drives and all folders
          Recovery_console_Allow_floppy_copy_and_access_to_all_drives_and_folders = 'Disabled'

          # CceId: CCE-37432-2
          # DataSource: BaselineSecurityPolicyRule
          # Ensure 'Accounts: Guest account status' is set to 'Disabled'
          Accounts_Guest_account_status = 'Disabled'
       }

        # CceId: CCE-38329-9
        # DataSource: BaselineAuditPolicyRule
        # Ensure 'Audit Application Group Management' is set to 'Success and Failure'
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

        # CceId: CCE-38004-8
        # DataSource: BaselineAuditPolicyRule
        # Ensure 'Audit Computer Account Management' is set to 'Success'    
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
            Ensure    = 'Absent'
        }

        # CceId: CCE-37741-6
        # DataSource: BaselineAuditPolicyRule
        # Ensure 'Audit Credential Validation' is set to 'Success and Failure'
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

        # CceId: CCE-36265-7
        # DataSource: BaselineAuditPolicyRule
        # Ensure 'Audit Distribution Group Management' is set to 'No Auditing'
        AuditPolicySubcategory 'Audit Distribution Group Management (Success)' 
        {
            Name      = 'Distribution Group Management'
            AuditFlag = 'Success'
            Ensure    = 'Absent'
        }

        AuditPolicySubcategory 'Audit Distribution Group Management (Failure)' 
        {
            Name      = 'Distribution Group Management'
            AuditFlag = 'Failure'
            Ensure    = 'Absent'
        }

        # CceId: CCE-38237-4
        # DataSource: BaselineAuditPolicyRule
        # Ensure 'Audit Logoff' is set to 'Success'
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

        # CceId: CCE-38036-0
        # DataSource: BaselineAuditPolicyRule
        # Ensure 'Audit Logon' is set to 'Success and Failure'
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

        # CceId: CCE-37855-4
        # DataSource: BaselineAuditPolicyRule
        # Ensure 'Audit Other Account Management Events' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Other Account Management Events (Success)' 
        {
            Name      = 'Other Account Management Events'
            AuditFlag = 'Success'
            Ensure    = 'Absent'
        }

        AuditPolicySubcategory 'Audit Other Account Management Events (Failure)' 
        {
            Name      = 'Other Account Management Events'
            AuditFlag = 'Failure'
            Ensure    = 'Absent'
        }

        # CceId: NOT_ASSIGNED
        # DataSource: BaselineAuditPolicyRule
        # Ensure 'Audit PNP Activity' is set to 'Success'
        AuditPolicySubcategory 'Audit PNP Activity (Success)' {
            Name      = 'Plug and Play Events'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit PNP Activity (Failure)' {
            Name      = 'Plug and Play Events'
            Ensure    = 'Absent'
            AuditFlag = 'Failure'
        }

        # CceId: CCE-36059-4
        # DataSource: BaselineAuditPolicyRule
        # Ensure 'Audit Process Creation' is set to 'Success'
        AuditPolicySubcategory 'Audit Process Creation (Success)' 
        {
            Name      = 'Process Creation'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        AuditPolicySubcategory 'Audit Process Creation (Failure)' 
        {
            Name      = 'Process Creation'
            AuditFlag = 'Failure'
            Ensure    = 'Absent'
        }

        # CceId: CCE-37617-8
        # DataSource: BaselineAuditPolicyRule
        # Ensure 'Audit Removable Storage' is set to 'Success and Failure'
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

        # CceId: CCE-38034-5
        # DataSource: BaselineAuditPolicyRule
        # Ensure 'Audit Security Group Management' is set to 'Success'
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
            Ensure    = 'Absent'
        }

        # CceId: CCE-36266-5
        # DataSource: BaselineAuditPolicyRule
        # Ensure 'Audit Special Logon' is set to 'Success'
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

        # CceId: CCE-37856-2
        # DataSource: BaselineAuditPolicyRule
        # Ensure 'Audit User Account Management' is set to 'Success and Failure'
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

        # CceId: NOT_ASSIGNED
        # DataSource: BaselineAuditPolicyRule
        # Audit Non Sensitive Privilege Use
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

        # CceId: NOT_ASSIGNED
        # DataSource: BaselineRegistryRule
        # Ensure 'Allow Input Personalization' is set to 'Disabled'
        Registry 'AllowInputPersonalization' {
           Ensure       = 'Present'
           Key          = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\InputPersonalization'
           ValueName    = 'AllowInputPersonalization'
           ValueType    = 'DWord'
           ValueData    = '0'
        }
  
        # CceId: NOT_ASSIGNED
        # DataSource: BaselineRegistryRule
        # Disable SMB v1 client
        Registry 'DependOnService' {
           Ensure       = 'Present'
           Key          = 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation'
           ValueName    = 'DependOnService'
           ValueType    = 'MultiString'
           ValueData    = 'Bowser|#|MRxSmb20|#|NSI'
        }

        # CceId: NOT_ASSIGNED
        # DataSource: BaselineRegistryRule
        # Disable SMB v1 server

        Registry 'SMB1' {
           Ensure       = 'Present'
           Key          = 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters'
           ValueName    = 'SMB1'
           ValueType    = 'DWord'
           ValueData    = '0'
        }

        # CceId: NOT_ASSIGNED
        # DataSource: BaselineRegistryRule
        # Disable Windows Search Service

       Registry 'Start' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Wsearch'
          ValueName    = 'Start'
          ValueType    = 'DWord'
          ValueData    = '4'
       }

        # CceId: NOT_ASSIGNED
        # DataSource: BaselineRegistryRule
        # Ensure 'Enable insecure guest logons' is set to 'Disabled'
        Registry 'AllowInsecureGuestAuth' {
           Ensure       = 'Present'
           Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation'
           ValueName    = 'AllowInsecureGuestAuth'
           ValueType    = 'DWord'
           ValueData    = '0'
        }

        # CceId: CCE-38002-2
        # DataSource: BaselineRegistryRule
        # Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'
        Registry 'NC_AllowNetBridge_NLA' {
           Ensure       = 'Present'
           Key          = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Network Connections'
           ValueName    = 'NC_AllowNetBridge_NLA'
           ValueType    = 'DWord'
           ValueData    = '0'
        }

        # CceId: NOT_ASSIGNED
        # DataSource: BaselineRegistryRule
        # Ensure 'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled'
        Registry 'NC_PersonalFirewallConfig' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Network Connections'
          ValueName    = 'NC_PersonalFirewallConfig'
          ValueType    = 'DWord'
          ValueData    = '0'
        }

        # CceId: CCE-36169-1
        # DataSource: BaselineRegistryRule
        # Ensure 'Configure registry policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE'
        Registry 'NoBackgroundPolicy' {
           Ensure     = 'Present'
           Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\GroupPolicy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
           ValueName  = 'NoBackgroundPolicy'
           ValueType  = 'DWord'
           ValueData  = '0'
        }

        # CceId: CCE-36169-1
        # DataSource: BaselineRegistryRule
        # Ensure 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE'
        Registry 'NoGPOListChanges' {
           Ensure     = 'Present'
           Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\GroupPolicy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
           ValueName  = 'NoGPOListChanges'
           ValueType  = 'DWord'
           ValueData  = '0'
        }

        # CceId: NOT_ASSIGNED
        # DataSource: BaselineRegistryRule
        # Ensure 'Continue experiences on this device' is set to 'Disabled'
        Registry 'EnableCdp' {
           Ensure     = 'Present'
           Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
           ValueName  = 'EnableCdp'
           ValueType  = 'DWord'
           ValueData  = '0'
        }

        # CceId: NOT_ASSIGNED
        # DataSource: BaselineRegistryRule
        # Enable Windows Error Reporting
        Registry 'Disabled2' {
           Ensure     = 'Present'
           Key        = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\Windows Error Reporting'
           ValueName  = 'Disabled'
           ValueType  = 'DWord'
           ValueData  = '0'
        }

        # CceId: CCE-37528-7
        # DataSource: BaselineRegistryRule
        # Ensure 'Turn on convenience PIN sign-in' is set to 'Disabled'
        Registry 'AllowDomainPINLogon' {
           Ensure     = 'Present'
           Key        = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System'
           ValueName  = 'AllowDomainPINLogon'
           ValueType  = 'DWord'
           ValueData  = '0'
        }

        # CceId: CCE-36388-7
        # DataSource: BaselineRegistryRule
        # Ensure 'Configure Offer Remote Assistance' is set to 'Disabled'
        Registry 'fAllowUnsolicited' {
           Ensure     = 'Present'
           Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
           ValueName  = 'fAllowUnsolicited'
           ValueType  = 'DWord'
           ValueData  = '0'
        }

        # CceId: CCE-37281-3
        # DataSource: BaselineRegistryRule
        # Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled'
        Registry 'fAllowToGetHelp' {
           Ensure     = 'Present'
           Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
           ValueName  = 'fAllowToGetHelp'
           ValueType  = 'DWord'
           ValueData  = '0'
        }

        # CceId: CCE-37838-0
        # DataSource: BaselineRegistryRule
        # Ensure 'Do not enumerate connected users on domain-joined computers' is set to 'Enabled'
       Registry 'DontEnumerateConnectedUsers' {
         Ensure     = 'Present'
         Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
         ValueName  = 'DontEnumerateConnectedUsers'
         ValueType  = 'DWord'
         ValueData  = '1'
       }

        # CceId: CCE-35894-5
        # DataSource: BaselineRegistryRule
        # Ensure 'Enumerate local users on domain-joined computers' is set to 'Disabled'
       Registry 'EnumerateLocalUsers' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
          ValueName  = 'EnumerateLocalUsers'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

        # CceId: NOT_ASSIGNED
        # DataSource: BaselineRegistryRule
        # Shutdown: Clear virtual memory pagefile
        Registry 'ClearPageFileAtShutdown' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Memory Management'
          ValueName  = 'ClearPageFileAtShutdown'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

        # CceId: CCE-36512-2
        # DataSource: BaselineRegistryRule
        # Ensure 'Enumerate administrator accounts on elevation' is set to 'Disabled'
       Registry 'EnumerateAdministrators' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI'
          ValueName  = 'EnumerateAdministrators'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

        # CceId: NOT_ASSIGNED
        # DataSource: BaselineRegistryRule
        # Ensure 'Allow Telemetry' is set to 'Enabled: 0 - Security [Enterprise Only]'
       Registry 'AllowTelemetry' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection'
          ValueName  = 'AllowTelemetry'
          ValueType  = 'DWord'
          ValueData  = '0'
        }

        # CceId: CCE-37809-1
        # DataSource: BaselineRegistryRule
        # Ensure 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled'
        Registry 'NoDataExecutionPrevention' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer'
          ValueName  = 'NoDataExecutionPrevention'
          ValueType  = 'DWord'
          ValueData  = '0'
        }

        # CceId: CCE-36660-9
        # DataSource: BaselineRegistryRule
        # Ensure 'Turn off heap termination on corruption' is set to 'Disabled'
       Registry 'NoHeapTerminationOnCorruption' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer'
          ValueName  = 'NoHeapTerminationOnCorruption'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

        # CceId: CCE-36809-2
        # DataSource: BaselineRegistryRule
        # Ensure 'Turn off shell protocol protected mode' is set to 'Disabled'
       Registry 'PreXPSP2ShellProtocolBehavior' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
          ValueName  = 'PreXPSP2ShellProtocolBehavior'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

        # CceId: CCE-38277-0
        # DataSource: BaselineRegistryRule
        # Ensure 'Allow indexing of encrypted files' is set to 'Disabled'
       Registry 'AllowIndexingEncryptedStoresOrItems' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsSearch'
          ValueName  = 'AllowIndexingEncryptedStoresOrItems'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

        # CceId: NOT_ASSIGNED
        # DataSource: BaselineRegistryRule
        # Disable 'Configure local setting override for reporting to Microsoft MAPS'
       Registry 'LocalSettingOverrideSpynetReporting' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\SpyNet'
          ValueName  = 'LocalSettingOverrideSpynetReporting'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

        # CceId: NOT_ASSIGNED
        # DataSource: BaselineRegistryRule
        # Enable 'Turn on behavior monitoring'
       Registry 'DisableBehaviorMonitoring' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
          ValueName  = 'DisableBehaviorMonitoring'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

        # CceId: NOT_ASSIGNED
        # DataSource: BaselineRegistryRule
        # Enable 'Scan removable drives' by setting DisableRemovableDriveScanning to 0
       Registry 'DisableRemovableDriveScanning' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Scan'
          ValueName  = 'DisableRemovableDriveScanning'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

        # CceId: CCE-36400-0
        # DataSource: BaselineRegistryRule
        # Ensure 'Allow user control over installs' is set to 'Disabled'
       Registry 'EnableUserControl' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer'
          ValueName  = 'EnableUserControl'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

        # CceId: CCE-36977-7
        # DataSource: BaselineRegistryRule
        # Ensure 'Sign-in last interactive user automatically after a system-initiated restart' is set to 'Disabled'
       Registry 'DisableAutomaticRestartSignOn' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
          ValueName  = 'DisableAutomaticRestartSignOn'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

        # CceId: CCE-36254-1
        # DataSource: BaselineRegistryRule
        # Ensure 'Allow Basic authentication' is set to 'Disabled'
       Registry 'AllowBasic' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
          ValueName  = 'AllowBasic'
          ValueType  = 'DWord'
          ValueData  = '0'
       } 

        # CceId: CCE-38223-4
        # DataSource: BaselineRegistryRule
        # Ensure 'Allow unencrypted traffic' is set to 'Disabled'
       Registry 'AllowUnencryptedTraffic' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
          ValueName  = 'AllowUnencryptedTraffic'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

        # CceId: CCE-38318-2
        # DataSource: BaselineRegistryRule
        # Ensure 'Disallow Digest authentication' is set to 'Enabled'
        Registry 'AllowDigest' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
          ValueName  = 'AllowDigest'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

        # CceId: CCE-37490-0
        # DataSource: BaselineRegistryRule
        # Ensure 'Always install with elevated privileges' is set to 'Disabled'
        Registry 'AlwaysInstallElevated' {
           Ensure       = 'Present'
           Key          = 'HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer'
           ValueName    = 'AlwaysInstallElevated'
           ValueType    = 'DWord'
           ValueData    = '0'
        }
    }
 }

AzSC_CCEv4_WindowsServer2016
