# Configuration Definition
Configuration CIS_WindowsServer2016_v110 {
   param (
       [string[]]$NodeName ='localhost'
       )


   Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
   Import-DscResource -ModuleName 'AuditPolicyDsc'
   Import-DscResource -ModuleName 'SecurityPolicyDsc'

   Node $NodeName {
      #Source: https://github.com/PowerShell/SecurityPolicyDsc/blob/dev/Examples/Resources/AccountPolicy/1-AccountPolicy_Config.ps1
      AccountPolicy AccountPolicies
        {
            Name                                        = 'PasswordPolicies'
            # 1.1.1 (L1) Ensure 'Enforce password history' is set to '24 or more password(s)'
            Enforce_password_history                    = 24
            # 1.1.2 (L1) Ensure 'Maximum password age' is set to '60 or fewer days, but not 0'
            Maximum_Password_Age                        = 60
            # 1.1.3 (L1) Ensure 'Minimum password age' is set to '1 or more day(s)'
            Minimum_Password_Age                        = 1
            # 1.1.4 (L1) Ensure 'Minimum password length' is set to '14 or more character(s)'
            Minimum_Password_Length                     = 14
            # 1.1.5 (L1) Ensure 'Password must meet complexity requirements' is set to 'Enabled'
            Password_must_meet_complexity_requirements  = 'Enabled'
            # 1.1.6 (L1) Ensure 'Store passwords using reversible encryption' is set to 'Disabled'
            Store_passwords_using_reversible_encryption = 'Disabled'
            # 1.2.1 (L1) Ensure 'Account lockout duration' is set to '15 or more minute(s)'
            Account_lockout_duration                    = 15
            # 1.2.2 (L1) Ensure 'Account lockout threshold' is set to '10 or fewer invalid logon attempt(s), but not 0'
            Account_lockout_threshold                   = 10
            # 1.2.3 (L1) Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)'
            Reset_account_lockout_counter_after         = 15
        }

       # Chapter 2

       #  2.2.1 (L1) Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'
       UserRightsAssignment AccessCredentialManagerasatrustedcaller {
          Policy       = 'Access_Credential_Manager_as_a_trusted_caller'
          Identity     = ''
       }

       #  2.2.2 (L1) Ensure 'Access this computer from the network' is set to 'Administrators, Authenticated Users, ENTERPRISE DOMAIN CONTROLLERS' (DC only)
       UserRightsAssignment Accessthiscomputerfromthenetwork {
          Policy       = 'Access_this_computer_from_the_network'
          Identity     = 'Administrators, Authenticated Users, ENTERPRISE DOMAIN CONTROLLERS'
       }

       #  2.2.3 (L1) Ensure 'Access this computer from the network' is set to 'Administrators, Authenticated Users' (MS only)
       # WARNING! Duplicate. Commented out
      #   UserRightsAssignment Accessthiscomputerfromthenetwork {
      #      Policy       = 'Access_this_computer_from_the_network'
      #      Identity     = 'Administrators, Authenticated Users'
      #   }


       #  2.2.4 (L1) Ensure 'Act as part of the operating system' is set to 'No One'
       UserRightsAssignment Actaspartoftheoperatingsystem {
          Policy       = 'Act_as_part_of_the_operating_system'
          Identity     = ''
       }

      #  2.2.5 (L1) Ensure 'Add workstations to domain' is set to 'Administrators' (DC only)
       UserRightsAssignment Addworkstationstodomain {
          Policy       = 'Add_workstations_to_domain'
          Identity     = 'Administrators'
       }

      #  2.2.6 (L1) Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'
      UserRightsAssignment Adjustmemoryquotasforaprocess {
         Policy       = 'Adjust_memory_quotas_for_a_process'
         Identity     = 'Administrators, LOCAL SERVICE, NETWORK SERVICE'
      }

      #  2.2.7 (L1) Ensure 'Allow log on locally' is set to 'Administrators'
       UserRightsAssignment Allowlogonlocally {
          Policy       = 'Allow_log_on_locally'
          Identity     = 'Administrators'
       }

      #  2.2.8 (L1) Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators' (DC only)
       UserRightsAssignment AllowlogonthroughRemoteDesktopServices {
          Policy       = 'Allow_log_on_through_Remote_Desktop_Services'
          Identity     = 'Administrators'
       }

      #  2.2.9 (L1) Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators, Remote Desktop Users' (MS only)
      # WARNING! Duplicate.
      #  UserRightsAssignment AllowlogonthroughRemoteDesktopServices {
      #     Policy       = 'Allow_log_on_through_Remote_Desktop_Services'
      #     Identity     = 'Administrators, Remote Desktop Users'
      #  }

      #  2.2.10 (L1) Ensure 'Back up files and directories' is set to 'Administrators'
       UserRightsAssignment Backupfilesanddirectories {
          Policy       = 'Back_up_files_and_directories'
          Identity     = 'Administrators'
       }

      #  2.2.11 (L1) Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE'
       UserRightsAssignment Changethesystemtime {
          Policy       = 'Change_the_system_time'
          Identity     = 'Administrators, LOCAL SERVICE'
       }

      #  2.2.12 (L1) Ensure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE'
       UserRightsAssignment Changethetimezone {
          Policy       = 'Change_the_time_zone'
          Identity     = 'Administrators, LOCAL SERVICE'
       }

      #  2.2.13 (L1) Ensure 'Create a pagefile' is set to 'Administrators'
       UserRightsAssignment Createapagefile {
          Policy       = 'Create_a_pagefile'
          Identity     = 'Administrators'
       }

      #  2.2.14 (L1) Ensure 'Create a token object' is set to 'No One'
       UserRightsAssignment Createatokenobject {
          Policy       = 'Create_a_token_object'
          Identity     = ''
       }

      #  2.2.15 (L1) Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
       UserRightsAssignment Createglobalobjects {
          Policy       = 'Create_global_objects'
          Identity     = 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
       }

      #  2.2.16 (L1) Ensure 'Create permanent shared objects' is set to 'No One'
       UserRightsAssignment Createpermanentsharedobjects {
          Policy       = 'Create_permanent_shared_objects'
          Identity     = ''
       }

      #  2.2.17 (L1) Ensure 'Create symbolic links' is set to 'Administrators' (DC only)
       UserRightsAssignment Createsymboliclinks {
          Policy       = 'Create_symbolic_links'
          Identity     = 'Administrators'
       }

      #  2.2.18 (L1) Ensure 'Create symbolic links' is set to 'Administrators, NT VIRTUAL MACHINE\Virtual Machines' (MS only)
      #  WARNING! Duplicate.
      #  UserRightsAssignment Createsymboliclinks {
      #     Policy       = 'Create_symbolic_links'
      #     Identity     = 'Administrators, NT VIRTUAL MACHINE\Virtual Machines'
      #  }

      #  2.2.19 (L1) Ensure 'Debug programs' is set to 'Administrators'
       UserRightsAssignment Debugprograms {
          Policy       = 'Debug_programs'
          Identity     = 'Administrators'
       }

      #  2.2.20 (L1) Ensure 'Deny access to this computer from the network' is set to 'Guests' (DC only)
      # WARNING! Duplicate
      #  UserRightsAssignment Denyaccesstothiscomputerfromthenetwork {
      #     Policy       = 'Deny_access_to_this_computer_from_the_network'
      #     Identity     = 'Guests'
      #  }

      #  2.2.21 (L1) Ensure 'Deny access to this computer from the network' is set to 'Guests, Local account and member of Administrators group' (MS only)
       UserRightsAssignment Denyaccesstothiscomputerfromthenetwork {
          Policy       = 'Deny_access_to_this_computer_from_the_network'
          Identity     = 'Guests, Local account, Administrators'
       }

      #  2.2.22 (L1) Ensure 'Deny log on as a batch job' to include 'Guests'
       UserRightsAssignment Denylogonasabatchjob {
          Policy       = 'Deny_log_on_as_a_batch_job'
          Identity     = 'Guests'
       }

      #  2.2.23 (L1) Ensure 'Deny log on as a service' to include 'Guests'
       UserRightsAssignment Denylogonasaservice {
          Policy       = 'Deny_log_on_as_a_service'
          Identity     = 'Guests'
       }

      #  2.2.24 (L1) Ensure 'Deny log on locally' to include 'Guests'
       UserRightsAssignment Denylogonlocally {
          Policy       = 'Deny_log_on_locally'
          Identity     = 'Guests'
       }

      # 2.2.25 (L1) Ensure 'Deny log on through Remote Desktop Services' is set to 'Guests' (DC only)
       UserRightsAssignment DenylogonthroughRemoteDesktopServices {
          Policy       = 'Deny_log_on_through_Remote_Desktop_Services'
          Identity     = 'Guests'
       }

      #  2.2.26 (L1) Ensure 'Deny log on through Remote Desktop Services' is set to 'Guests, Local account' (MS only)
      #WARNING! Duplicate.
      #  UserRightsAssignment DenylogonthroughRemoteDesktopServices2 {
      #     Policy       = 'Deny_log_on_through_Remote_Desktop_Services2'
      #     Identity     = 'Guests, Local account'
      #  }

      #  2.2.27 (L1) Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'Administrators' (DC only)
      # WARNING! Duplicate
      #  UserRightsAssignment Enablecomputeranduseraccountstobetrustedfordelegation {
      #     Policy       = 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
      #     Identity     = 'Administrators'
      #  }

      #  2.2.28 (L1) Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'No One' (MS only)
       UserRightsAssignment Enablecomputeranduseraccountstobetrustedfordelegation {
          Policy       = 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
          Identity     = ''
       }

      #  2.2.29 (L1) Ensure 'Force shutdown from a remote system' is set to 'Administrators'
       UserRightsAssignment Forceshutdownfromaremotesystem {
          Policy       = 'Force_shutdown_from_a_remote_system'
          Identity     = 'Administrators'
       }

      #  2.2.30 (L1) Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'
       UserRightsAssignment Generatesecurityaudits {
          Policy       = 'Generate_security_audits'
          Identity     = 'LOCAL SERVICE, NETWORK SERVICE'
       }

      #  2.2.31 (L1) Ensure 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' (DC only)
       UserRightsAssignment Impersonateaclientafterauthentication {
          Policy       = 'Impersonate_a_client_after_authentication'
          Identity     = 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
       }

      #  2.2.32 (L1) Ensure 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' and (when the Web Server (IIS) Role with Web Services Role Service is installed) 'IIS_IUSRS' (MS only)
      # WARNING! Duplicate
      #  UserRightsAssignment Impersonateaclientafterauthentication {
      #     Policy       = 'Impersonate_a_client_after_authentication'
      #     Identity     = 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' and (when the Web Server (IIS) Role with Web Services Role Service is installed) 'IIS_IUSRS'
      #  }
      

      #  2.2.33 (L1) Ensure 'Increase scheduling priority' is set to 'Administrators'
       UserRightsAssignment Increaseschedulingpriority {
          Policy       = 'Increase_scheduling_priority'
          Identity     = 'Administrators'
       }

      #  2.2.34 (L1) Ensure 'Load and unload device drivers' is set to 'Administrators'
       UserRightsAssignment Loadandunloaddevicedrivers {
          Policy       = 'Load_and_unload_device_drivers'
          Identity     = 'Administrators'
       }

      #  2.2.35 (L1) Ensure 'Lock pages in memory' is set to 'No One'
       UserRightsAssignment Lockpagesinmemory {
          Policy       = 'Lock_pages_in_memory'
          Identity     = ''
       }

      #  2.2.36 (L2) Ensure 'Log on as a batch job' is set to 'Administrators' (DC Only)
       UserRightsAssignment Logonasabatchjob {
          Policy       = 'Log_on_as_a_batch_job'
          Identity     = 'Administrators'
       }

      #  2.2.37 (L1) Ensure 'Manage auditing and security log' is set to 'Administrators' and (when Exchange is running in the environment) `Exchange Servers' (DC only)
      # WARNING! Duplicate
      #  UserRightsAssignment Manageauditingandsecuritylog {
      #     Policy       = 'Manage_auditing_and_security_log'
      #     Identity     = ''Administrators' and (when Exchange is running in the environment) `Exchange Servers''
      #  }

      #  2.2.38 (L1) Ensure 'Manage auditing and security log' is set to 'Administrators' (MS only)
       UserRightsAssignment Manageauditingandsecuritylog {
          Policy       = 'Manage_auditing_and_security_log'
          Identity     = 'Administrators'
       }

      #  2.2.39 (L1) Ensure 'Modify an object label' is set to 'No One'
       UserRightsAssignment Modifyanobjectlabel {
          Policy       = 'Modify_an_object_label'
          Identity     = ''
       }

      # 2.2.40 (L1) Ensure 'Modify firmware environment values' is set to 'Administrators'
       UserRightsAssignment Modifyfirmwareenvironmentvalues {
          Policy       = 'Modify_firmware_environment_values'
          Identity     = 'Administrators'
       }

      #  2.2.41 (L1) Ensure 'Perform volume maintenance tasks' is set to 'Administrators'
       UserRightsAssignment Performvolumemaintenancetasks {
          Policy       = 'Perform_volume_maintenance_tasks'
          Identity     = 'Administrators'
       }

      #  2.2.42 (L1) Ensure 'Profile single process' is set to 'Administrators'
       UserRightsAssignment Profilesingleprocess {
          Policy       = 'Profile_single_process'
          Identity     = 'Administrators'
       }

      #  2.2.43 (L1) Ensure 'Profile system performance' is set to 'Administrators, NT SERVICE\WdiServiceHost'
       UserRightsAssignment Profilesystemperformance {
          Policy       = 'Profile_system_performance'
          Identity     = 'Administrators, NT SERVICE\WdiServiceHost'
       }

      #  2.2.44 (L1) Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE'
       UserRightsAssignment Replaceaprocessleveltoken {
          Policy       = 'Replace_a_process_level_token'
          Identity     = 'LOCAL SERVICE, NETWORK SERVICE'
       }

      #  2.2.45 (L1) Ensure 'Restore files and directories' is set to 'Administrators'
       UserRightsAssignment Restorefilesanddirectories {
          Policy       = 'Restore_files_and_directories'
          Identity     = 'Administrators'
       }

      #  2.2.46 (L1) Ensure 'Shut down the system' is set to 'Administrators'
       UserRightsAssignment Shutdownthesystem {
          Policy       = 'Shut_down_the_system'
          Identity     = 'Administrators'
       }

      #  2.2.47 (L1) Ensure 'Synchronize directory service data' is set to 'No One' (DC only)
       UserRightsAssignment Synchronizedirectoryservicedata {
          Policy       = 'Synchronize_directory_service_data'
          Identity     = ''
       }

      #  2.2.48 (L1) Ensure 'Take ownership of files or other objects' is set to 'Administrators'
       UserRightsAssignment Takeownershipoffilesorotherobjects {
          Policy       = 'Take_ownership_of_files_or_other_objects'
          Identity     = 'Administrators'
       }

       #Source: https://github.com/PowerShell/SecurityPolicyDsc
       SecurityOption AccountSecurityOptions {
         Name                                   = 'AccountSecurityOptions'
         # 2.3.1.1 (L1) Ensure 'Accounts: Administrator account status' is set to 'Disabled' (MS only)
         Accounts_Administrator_account_status  = 'Disabled'
         # 2.3.1.2 (L1) Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'
         Accounts_Block_Microsoft_accounts = 'Users cant add or log on with Microsoft accounts'
         # 2.3.1.3 (L1) Ensure 'Accounts: Guest account status' is set to 'Disabled' (MS only)
         Accounts_Guest_account_status = 'Disabled'
         # 2.3.1.4 (L1) Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'
         Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only = 'Enabled'
         # 2.3.1.5 (L1) Configure 'Accounts: Rename administrator account'
         Accounts_Rename_administrator_account = 'User_Adm' # WARNING! Any value different from Administrator
         # 2.3.1.6 (L1) Configure 'Accounts: Rename guest account'
         Accounts_Rename_guest_account = 'User_Guest' # WARNING! Any value different from Guest
         # 2.3.2.1 (L1) Ensure 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set to 'Enabled'
         Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings = 'Enabled'
         # 2.3.2.2 (L1) Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'
         Audit_Shut_down_system_immediately_if_unable_to_log_security_audits = 'Disabled'
         # 2.3.4.1 (L1) Ensure 'Devices: Allowed to format and eject removable media' is set to 'Administrators'
         Devices_Allowed_to_format_and_eject_removable_media = 'Administrators'
         # 2.3.4.2 (L1) Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'
         Devices_Prevent_users_from_installing_printer_drivers = 'Enabled'
         # 2.3.5.1 (L1) Ensure 'Domain controller: Allow server operators to schedule tasks' is set to 'Disabled' (DC only)
         Domain_controller_Allow_server_operators_to_schedule_tasks = 'Disabled'
         # 2.3.5.2 (L1) Ensure 'Domain controller: LDAP server signing requirements' is set to 'Require Signature' (DC only) 
         Domain_controller_LDAP_server_signing_requirements = 'Require Signature'
         # 2.3.5.3 (L1) Ensure 'Domain controller: Refuse machine account password changes' is set to 'Disabled' (DC only) 
         Domain_controller_Refuse_machine_account_password_changes = 'Disabled'
         # 2.3.6.1 (L1) Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'
         Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always = 'Enabled' 
         # 2.3.6.2 (L1) Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled'
         Domain_member_Digitally_encrypt_secure_channel_data_when_possible = 'Enabled'
         # 2.3.6.3 (L1) Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled' 
         Domain_member_Digitally_sign_secure_channel_data_when_possible = 'Enabled'
         # 2.3.6.4 (L1) Ensure 'Domain member: Disable machine account password changes' is set to 'Disabled'
         Domain_member_Disable_machine_account_password_changes = 'Disabled'
         # 2.3.6.5 (L1) Ensure 'Domain member: Maximum machine account password age' is set to '30 or fewer days, but not 0'
         Domain_member_Maximum_machine_account_password_age = '30'
         # 2.3.6.6 (L1) Ensure 'Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled'
         Domain_member_Require_strong_Windows_2000_or_later_session_key = 'Enabled'
         # 2.3.7.1 (L1) Ensure 'Interactive logon: Do not display last user name' is set to 'Enabled'
         Interactive_logon_Do_not_display_last_user_name = 'Enabled' 
         # 2.3.7.2 (L1) Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'
         Interactive_logon_Do_not_require_CTRL_ALT_DEL = 'Disabled' 
         # 2.3.7.3 (L1) Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0'
         Interactive_logon_Machine_inactivity_limit = '900' 
         # 2.3.7.4 (L1) Configure 'Interactive logon: Message text for users attempting to log on' 
         Interactive_logon_Message_text_for_users_attempting_to_log_on = 'This computer system is the property of Acme Corporation and is for authorised use by employees and designated contractors only. By continuing to use this system you indicate your awareness of and consent to these terms and conditions of use.It is the users responsibility to LOG OFF IMMEDIATELY if you do not agree to the conditions stated in this notice.'
         # 2.3.7.5 (L1) Configure 'Interactive logon: Message title for users attempting to log on'
         #Interactive_logon_Message_title_for_users_attempting_to_log_on = '<Logon Warning>'
         Interactive_logon_Message_title_for_users_attempting_to_log_on = 'Logon Warning'
         # 2.3.7.6 (L2) Ensure 'Interactive logon: Number of previous logons to cache (in case domain controller is not available)' is set to '4 or fewer logon(s)' (MS only) 
         Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available = '4'
         # 2.3.7.7 (L1) Ensure 'Interactive logon: Prompt user to change password before expiration' is set to 'between 5 and 14 days'
         Interactive_logon_Prompt_user_to_change_password_before_expiration = '14'
         # 2.3.7.8 (L1) Ensure 'Interactive logon: Require Domain Controller Authentication to unlock workstation' is set to 'Enabled' (MS only)
         Interactive_logon_Require_Domain_Controller_authentication_to_unlock_workstation = 'Enabled' 
         # 2.3.7.9 (L1) Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation' or higher
         Interactive_logon_Smart_card_removal_behavior = 'Lock Workstation'
         # 2.3.8.1 (L1) Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled' 
         Microsoft_network_client_Digitally_sign_communications_always = 'Enabled'
         # 2.3.8.2 (L1) Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled' 
         Microsoft_network_client_Digitally_sign_communications_if_server_agrees = 'Enabled'
         # 2.3.8.3 (L1) Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled' 
         Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers = 'Disabled'
         # 2.3.9.1 (L1) Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute(s), but not 0'
         Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session = '15' 
         # 2.3.9.2 (L1) Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled' 
         Microsoft_network_server_Digitally_sign_communications_always = 'Enabled'
         # 2.3.9.3 (L1) Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled' 
         Microsoft_network_server_Digitally_sign_communications_if_client_agrees = 'Enabled'
         # 2.3.9.4 (L1) Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled'
         Microsoft_network_server_Disconnect_clients_when_logon_hours_expire = 'Enabled' 
         # 2.3.9.5 (L1) Ensure 'Microsoft network server: Server SPN target name validation level' is set to 'Accept if provided by client' or higher (MS only) 
         #Microsoft_network_server_Server_SPN_target_name_validation_level = 'Accept if provided by client'
         Microsoft_network_server_Server_SPN_target_name_validation_level = 'Required from client'
         # 2.3.10.1 (L1) Ensure 'Network access: Allow anonymous SID/Name translation' is set to 'Disabled'
         Network_access_Allow_anonymous_SID_Name_translation = 'Disabled' 
         # 2.3.10.2 (L1) Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled' (MS only) 
         Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts = 'Enabled'
         # 2.3.10.3 (L1) Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled' (MS only) 
         Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares = 'Enabled'
         # 2.3.10.4 (L2) Ensure 'Network access: Do not allow storage of passwords and credentials for network authentication' is set to 'Enabled'
         Network_access_Do_not_allow_storage_of_passwords_and_credentials_for_network_authentication = 'Enabled' 
         # 2.3.10.5 (L1) Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled'
         Network_access_Let_Everyone_permissions_apply_to_anonymous_users = 'Disabled' 
         # 2.3.10.6 (L1) Configure 'Network access: Named Pipes that can be accessed anonymously' (DC only)
         Network_access_Named_Pipes_that_can_be_accessed_anonymously = ''
         # 2.3.10.7 (L1) Configure 'Network access: Named Pipes that can be accessed anonymously' (MS only) 
         # 2.3.10.8 (L1) Configure 'Network access: Remotely accessible registry paths' 
         # Commented out because of bug in SecurityPolicyDSC Module https://github.com/dsccommunity/SecurityPolicyDSC/issues/83
         #Network_access_Remotely_accessible_registry_paths = 'System\CurrentControlSet\Control\ProductOptions, System\CurrentControlSet\Control\Server Applications, SOFTWARE\Microsoft\Windows NT\CurrentVersion'
         # 2.3.10.9 (L1) Configure 'Network access: Remotely accessible registry paths and sub-paths' 
         # Commented out because of bug in SecurityPolicyDSC Module https://github.com/dsccommunity/SecurityPolicyDSC/issues/83
         #Network_access_Remotely_accessible_registry_paths_and_subpaths = 'System\CurrentControlSet\Control\Print\Printers, System\CurrentControlSet\Services\Eventlog, Software\Microsoft\OLAP Server, Software\Microsoft\Windows NT\CurrentVersion\Print, Software\Microsoft\Windows NT\CurrentVersion\Windows, System\CurrentControlSet\Control\ContentIndex, System\CurrentControlSet\Control\Terminal Server, System\CurrentControlSet\Control\Terminal Server\UserConfig, System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration, Software\Microsoft\Windows NT\CurrentVersion\Perflib, System\CurrentControlSet\Services\SysmonLog'
         # 2.3.10.10 (L1) Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled' 
         Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares = 'Enabled' 
         # 2.3.10.11 (L1) Ensure 'Network access: Restrict clients allowed to make remote calls to SAM' is set to 'Administrators: Remote Access: Allow' (MS only) 
         #Network_access_Restrict_clients_allowed_to_make_remote_calls_to_SAM = 'Administrators: Remote Access: Allow'
         Network_access_Restrict_clients_allowed_to_make_remote_calls_to_SAM = @(
            MSFT_RestrictedRemoteSamSecurityDescriptor
            {
               Permission = 'Allow'
               Identity   = 'Administrators'
            }
            )

         # 2.3.10.12 (L1) Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None' 
         Network_access_Shares_that_can_be_accessed_anonymously = ''
         # 2.3.10.13 (L1) Ensure 'Network access: Sharing and security model for local accounts' is set to 'Classic - local users authenticate as themselves' 
         Network_access_Sharing_and_security_model_for_local_accounts = 'Classic - local users authenticate as themselves'
         # 2.3.11.1 (L1) Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled' 
         Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM = 'Enabled'
         # 2.3.11.2 (L1) Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled' 
         Network_security_Allow_LocalSystem_NULL_session_fallback = 'Disabled'
         # 2.3.11.3 (L1) Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled' 
         Network_security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities = 'Disabled'
         # 2.3.11.4 (L1) Ensure 'Network security: Configure encryption types allowed for Kerberos' is set to 'AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types' 
         Network_security_Configure_encryption_types_allowed_for_Kerberos = 'AES128_HMAC_SHA1','AES256_HMAC_SHA1','FUTURE'
         # 2.3.11.5 (L1) Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled' 
         Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change = 'Enabled'
         # 2.3.11.6 (L1) Ensure 'Network security: Force logoff when logon hours expire' is set to 'Enabled' 
         Network_security_Force_logoff_when_logon_hours_expire = 'Enabled'
         # 2.3.11.7 (L1) Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'
         Network_security_LAN_Manager_authentication_level = 'Send NTLMv2 responses only. Refuse LM & NTLM' 
         # 2.3.11.8 (L1) Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher
         Network_security_LDAP_client_signing_requirements = 'Negotiate signing' 
         # 2.3.11.9 (L1) Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption' 
         Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients = 'Both options checked'
         # 2.3.11.10 (L1) Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption' 
         Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers = 'Both options checked' 
         # 2.3.13.1 (L1) Ensure 'Shutdown: Allow system to be shut down without having to log on' is set to 'Disabled'
         Shutdown_Allow_system_to_be_shut_down_without_having_to_log_on = 'Disabled' 
         # 2.3.15.1 (L1) Ensure 'System objects: Require case insensitivity for non-Windows subsystems' is set to 'Enabled'
         System_objects_Require_case_insensitivity_for_non_Windows_subsystems = 'Enabled' 
         # 2.3.15.2 (L1) Ensure 'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)' is set to 'Enabled'
         System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links = 'Enabled' 
         # 2.3.17.1 (L1) Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled' 
         User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account = 'Enabled'
         # 2.3.17.2 (L1) Ensure 'User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop' is set to 'Disabled' 
         User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop = 'Disabled'
         # 2.3.17.3 (L1) Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop' 
         User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode = 'Prompt for consent on the secure desktop'
         # 2.3.17.4 (L1) Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests' 
         User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users = 'Automatically deny elevation request'
         # 2.3.17.5 (L1) Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled' 
         User_Account_Control_Detect_application_installations_and_prompt_for_elevation = 'Enabled'
         # 2.3.17.6 (L1) Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled' 
         User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations = 'Enabled'
         # 2.3.17.7 (L1) Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled'
         User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode = 'Enabled'
         # 2.3.17.8 (L1) Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled' 
         User_Account_Control_Switch_to_the_secure_desktop_when_prompting_for_elevation = 'Enabled'
         # 2.3.17.9 (L1) Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled'
         User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations = 'Enabled'

       }

       #  9.1.1 (L1) Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On (recommended)'
       Registry 'EnableFirewallDomain' {
           Ensure      = 'Present'
           Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\EnableFirewall'
           ValueName   = 'EnableFirewall'
           ValueType   = 'DWord'
           ValueData   = '1'
       }

       #  9.1.2 (L1) Ensure 'Windows Firewall: Domain: Inbound connections' is set to 'Block (default)'
       Registry 'DefaultInboundActionDomain' {
           Ensure      = 'Present'
           Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\DefaultInboundAction'
           ValueName   = 'DefaultInboundAction'
           ValueType   = 'DWord'
           ValueData   = '1'
       }

       #  9.1.3 (L1) Ensure 'Windows Firewall: Domain: Outbound connections' is set to 'Allow (default)'
       Registry 'DefaultOutboundActionDomain' {
           Ensure      = 'Present'
           Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\DefaultOutboundAction'
           ValueName   = 'DefaultOutboundAction'
           ValueType   = 'DWord'
           ValueData   = '0'
       }

       # 9.1.4 (L1) Ensure 'Windows Firewall: Domain: Settings: Display a notification' is set to 'No'
       Registry 'DisableNotificationsDomain' {
           Ensure      = 'Present'
           Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\DisableNotifications'
           ValueName   = 'DisableNotifications'
           ValueType   = 'DWord'
           ValueData   = '0'
       }

       # 9.1.5 (L1) Ensure 'Windows Firewall: Domain: Logging: Name' is set to '%SYSTEMROOT%\System32\logfiles\firewall\domainfw.log'
       Registry 'LogFilePathDomain' {
           Ensure      = 'Present'
           Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogFilePath'
           ValueName   = 'DisableNotifications'
           ValueType   = 'String'
           ValueData   = '%windir%\system32\logfiles\firewall\domainfirewall.log'
       }

       # 9.1.6 (L1) Ensure 'Windows Firewall: Domain: Logging: Size limit (KB)' is set to '16,384 KB or greater'
       Registry 'LogFileSizeDomain' {
           Ensure      = 'Present'
           Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogFileSize'
           ValueName   = 'LogFileSize'
           ValueType   = 'DWord'
           ValueData   = '16384'
       }

       #  9.1.7 (L1) Ensure 'Windows Firewall: Domain: Logging: Log dropped packets' is set to 'Yes'
       Registry 'LogDroppedPacketsDomain' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogDroppedPackets'
          ValueName    = 'LogDroppedPackets'
          ValueType    = 'DWord'
          ValueData    = '1'
       }

       #  9.1.8 (L1) Ensure 'Windows Firewall: Domain: Logging: Log successful connections' is set to 'Yes'
       Registry 'LogSuccessfulConnectionsDomain' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogSuccessfulConnections'
          ValueName    = 'LogSuccessfulConnections'
          ValueType    = 'DWord'
          ValueData    = '1'
       }

       #  9.2.1 (L1) Ensure 'Windows Firewall: Private: Firewall state' is set to 'On (recommended)'
       Registry 'EnableFirewallPrivate' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
          ValueName    = 'EnableFirewall'
          ValueType    = 'DWord'
          ValueData    = '1'
       }

       #  9.2.2 (L1) Ensure 'Windows Firewall: Private: Inbound connections' is set to 'Block (default)'
       Registry 'DefaultInboundActionPrivate' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
          ValueName    = 'DefaultInboundAction'
          ValueType    = 'DWord'
          ValueData    = '1'
       }

       #  9.2.3 (L1) Ensure 'Windows Firewall: Private: Outbound connections' is set to 'Allow (default)'
       Registry 'DefaultOutboundActionPrivate' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
          ValueName    = 'DefaultOutboundAction'
          ValueType    = 'DWord'
          ValueData    = '0'
       }

       #  9.2.4 (L1) Ensure 'Windows Firewall: Private: Settings: Display a notification' is set to 'No'
       Registry 'DisableNotificationsPrivate' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
          ValueName    = 'DisableNotifications'
          ValueType    = 'DWord'
          ValueData    = '0'
       }

       #  9.2.5 (L1) Ensure 'Windows Firewall: Private: Logging: Name' is set to '%SYSTEMROOT%\System32\logfiles\firewall\privatefw.log'
       Registry 'LogFilePathPrivate' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
          ValueName    = 'LogFilePath'
          ValueType    = 'String'
          ValueData    = '%windir%\system32\logfiles\firewall\privatefirewall.log'
       }

       #  9.2.6 (L1) Ensure 'Windows Firewall: Private: Logging: Size limit (KB)' is set to '16,384 KB or greater'
       Registry 'LogFileSizePrivate' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
          ValueName    = 'LogFileSize'
          ValueType    = 'DWord'
          ValueData    = '16384'
       }

       #  9.2.7 (L1) Ensure 'Windows Firewall: Private: Logging: Log dropped packets' is set to 'Yes'
       Registry 'LogDroppedPacketsPrivate' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
          ValueName    = 'LogDroppedPackets'
          ValueType    = 'DWord'
          ValueData    = '1'
       }

       #  9.2.8 (L1) Ensure 'Windows Firewall: Private: Logging: Log successful connections' is set to 'Yes'
       Registry 'LogSuccessfulConnectionsPrivate' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
          ValueName    = 'LogSuccessfulConnections'
          ValueType    = 'DWord'
          ValueData    = '1'
       }

       #  9.3.1 (L1) Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)'
       Registry 'EnableFirewallPublic' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
          ValueName    = 'EnableFirewall'
          ValueType    = 'DWord'
          ValueData    = '1'
       }

       #  9.3.2 (L1) Ensure 'Windows Firewall: Public: Inbound connections' is set to 'Block (default)'
       Registry 'DefaultInboundActionPublic' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
          ValueName    = 'DefaultInboundAction'
          ValueType    = 'DWord'
          ValueData    = '1'
       }

       #  9.3.3 (L1) Ensure 'Windows Firewall: Public: Outbound connections' is set to 'Allow (default)'
       Registry 'DefaultOutboundActionPublic' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
          ValueName    = 'DefaultOutboundAction'
          ValueType    = 'DWord'
          ValueData    = '0'
       }

       #  9.3.4 (L1) Ensure 'Windows Firewall: Public: Settings: Display a notification' is set to 'No'
       Registry 'DisableNotificationsPublic' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
          ValueName    = 'DisableNotifications'
          ValueType    = 'DWord'
          ValueData    = '0'
       }

       #  9.3.5 (L1) Ensure 'Windows Firewall: Public: Settings: Apply local firewall rules' is set to 'No'
       Registry 'AllowLocalPolicyMerge' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
          ValueName    = 'AllowLocalPolicyMerge'
          ValueType    = 'DWord'
          ValueData    = '0'
       }

       #  9.3.6 (L1) Ensure 'Windows Firewall: Public: Settings: Apply local connection security rules' is set to 'No'
       Registry 'AllowLocalIPsecPolicyMerge' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
          ValueName    = 'AllowLocalIPsecPolicyMerge'
          ValueType    = 'DWord'
          ValueData    = '0'
       }

       #  9.3.7 (L1) Ensure 'Windows Firewall: Public: Logging: Name' is set to '%SYSTEMROOT%\System32\logfiles\firewall\publicfw.log'
       Registry 'LogFilePathPublic' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
          ValueName    = 'LogFilePath'
          ValueType    = 'String'
          ValueData    = '%windir%\system32\logfiles\firewall\publicfirewall.log'
       }

       #  9.3.8 (L1) Ensure 'Windows Firewall: Public: Logging: Size limit (KB)' is set to '16,384 KB or greater'
       Registry 'LogFileSizePublic' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
          ValueName    = 'LogFileSize'
          ValueType    = 'Dword'
          ValueData    = '16384'
       }

       #  9.3.9 (L1) Ensure 'Windows Firewall: Public: Logging: Log dropped packets' is set to 'Yes'
       Registry 'LogDroppedPacketsPublic' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
          ValueName    = 'LogDroppedPackets'
          ValueType    = 'DWord'
          ValueData    = '1'
       }

       #  9.3.10 (L1) Ensure 'Windows Firewall: Public: Logging: Log successful connections' is set to 'Yes'
       Registry 'LogSuccessfulConnectionsPublic' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
          ValueName    = 'LogSuccessfulConnections'
          ValueType    = 'DWord'
          ValueData    = '1'
       }

       # 17.1.1 (L1) Ensure 'Audit Credential Validation' is set to 'Success and Failure'
       AuditPolicySubcategory "Audit Credential Validation (Success)"
       {
           Name      = 'Credential Validation'
           Ensure    = 'Present'
           AuditFlag = 'Success'
       }

       AuditPolicySubcategory 'Audit Credential Validation (Failure)'
       {
           Name      = 'Credential Validation'
           Ensure    = 'Present'
           AuditFlag = 'Failure'
       }

       # 17.2.1 (L1) Ensure 'Audit Application Group Management' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Application Group Management (Success)'
        {
            Name      = 'Application Group Management'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Application Group Management (Failure)'
        {
            Name      = 'Application Group Management'    
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }

        # 17.2.2 (L1) Ensure 'Audit Computer Account Management' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Computer Account Management (Failure)' 
        {
            Name      = 'Computer Account Management'
            Ensure    = 'Present'
            AuditFlag = 'Failure'      
         }

         AuditPolicySubcategory 'Audit Computer Account Management (Success)' {
            Name      = 'Computer Account Management'
            Ensure    = 'Present'   
            AuditFlag = 'Success'      
         }

       # 17.2.3 (L1) Ensure 'Audit Distribution Group Management' is set to 'Success and Failure' (DC only)
       AuditPolicySubcategory 'Audit Distribution Group Management (Failure)' {
         Name      = 'Distribution Group Management'
         Ensure    = 'Present'
         AuditFlag = 'Failure'
         }

     AuditPolicySubcategory 'Audit Distribution Group Management (Success)' {
         Name      = 'Distribution Group Management'
         Ensure    = 'Present'
         AuditFlag = 'Success'
         }

       # 17.2.4 (L1) Ensure 'Audit Other Account Management Events' is set to 'Success and Failure'
       AuditPolicySubcategory 'Audit Other Account Management Events (Failure)' {
         Name      = 'Other Account Management Events'
         Ensure    = 'Present'
         AuditFlag = 'Failure'
         }

     AuditPolicySubcategory 'Audit Other Account Management Events (Success)' {
         Name      = 'Other Account Management Events'
         Ensure    = 'Present'
         AuditFlag = 'Success'
         }

        # 17.2.5 (L1) Ensure 'Audit Security Group Management' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Security Group Management (Failure)' {
            Name      = 'Security Group Management'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit Security Group Management (Success)' {
            Name      = 'Security Group Management'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        # 17.2.6 (L1) Ensure 'Audit User Account Management' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit User Account Management (Failure)' {
            Name      = 'User Account Management'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit User Account Management (Success)' {
            Name      = 'User Account Management'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        # 17.3.1 (L1) Ensure 'Audit PNP Activity' is set to 'Success' 
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

        # 17.3.2 (L1) Ensure 'Audit Process Creation' is set to 'Success'
        AuditPolicySubcategory 'Audit Process Creation (Success)' {
            Name      = 'Process Creation'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Process Creation (Failure)' {
            Name      = 'Process Creation'
            Ensure    = 'Absent'
            AuditFlag = 'Failure'
        }

        # 17.4.1 (L1) Ensure 'Audit Directory Service Access' is set to 'Success and Failure' (DC only)
        AuditPolicySubcategory 'Audit Directory Service Access (Success)' {
            Name      = 'Directory Service Access'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Directory Service Access (Failure)' {
            Name      = 'Directory Service Access'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }

        # 17.4.2 (L1) Ensure 'Audit Directory Service Changes' is set to 'Success and Failure' (DC only)
        AuditPolicySubcategory 'Audit Directory Service Changes (Success)' {
            Name      = 'Directory Service Changes'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Directory Service Changes (Failure)' {
            Name      = 'Directory Service Changes'
            Ensure    = 'Absent'
            AuditFlag = 'Failure'
        }

        # 17.5.1 (L1) Ensure 'Audit Account Lockout' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Account Lockout (Success)' {
            Name      = 'Account Lockout'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Account Lockout (Failure)' {
            Name      = 'Account Lockout'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }
        
        # 17.5.2 (L1) Ensure 'Audit Group Membership' is set to 'Success'
        AuditPolicySubcategory 'Audit Group Membership (Success)' {
            Name      = 'Group Membership'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Group Membership (Failure)' {
            Name      = 'Group Membership'
            Ensure    = 'Absent'
            AuditFlag = 'Failure'
            }
        
        # 17.5.3 (L1) Ensure 'Audit Logoff' is set to 'Success'
        AuditPolicySubcategory 'Audit Logoff (Success)' {
            Name      = 'Logoff'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Logoff (Failure)' {
            Name      = 'Logoff'
            Ensure    = 'Absent'
            AuditFlag = 'Failure'
        }
        
        # 17.5.4 (L1) Ensure 'Audit Logon' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Logon (Success)' {
            Name      = 'Logon'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Logon (Failure)' {
            Name      = 'Logon'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }
        
        # 17.5.5 (L1) Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Other Logon/Logoff Events (Failure)' {
            Name      = 'Other Logon/Logoff Events'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit Other Logon/Logoff Events (Success)' {
            Name      = 'Other Logon/Logoff Events'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }
        
        # 17.5.6 (L1) Ensure 'Audit Special Logon' is set to 'Success'
        AuditPolicySubcategory 'Audit Special Logon (Success)' {
            Name      = 'Special Logon'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Special Logon (Failure)' {
            Name      = 'Special Logon'
            Ensure    = 'Absent'
            AuditFlag = 'Failure'
        }
        
        # 17.6.1 (L1) Ensure 'Audit Other Object Access Events' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Other Object Access Events (Success)' {
            Name      = 'Other Object Access Events'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Other Object Access Events (Failure)' {
            Name      = 'Other Object Access Events'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }
        
        # 17.6.2 (L1) Ensure 'Audit Removable Storage' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Removable Storage (Success)' {
            Name      = 'Removable Storage'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Removable Storage (Failure)' {
            Name      = 'Removable Storage'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }
        
        # 17.7.1 (L1) Ensure 'Audit Audit Policy Change' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Policy Change (Success)' {
            Name      = 'Audit Policy Change'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Policy Change (Failure)' {
            Name      = 'Audit Policy Change'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }
        
        # 17.7.2 (L1) Ensure 'Audit Authentication Policy Change' is set to 'Success'
        AuditPolicySubcategory 'Audit Authentication Policy Change (Success)' {
            Name      = 'Authentication Policy Change'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Authentication Policy Change (Failure)' {
            Name      = 'Authentication Policy Change'
            Ensure    = 'Absent'
            AuditFlag = 'Failure'
        }
        
        # 17.7.3 (L1) Ensure 'Audit Authorization Policy Change' is set to 'Success'
        AuditPolicySubcategory 'Audit Authorization Policy Change (Success)' {
            Name      = 'Authorization Policy Change'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Authorization Policy Change (Failure)' {
            Name      = 'Authorization Policy Change'
            Ensure    = 'Absent'
            AuditFlag = 'Failure'
        }
        
        # 17.8.1 (L1) Ensure 'Audit Sensitive Privilege Use' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Sensitive Privilege Use (Failure)' {
            Name      = 'Sensitive Privilege Use'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit Sensitive Privilege Use (Success)' {
            Name      = 'Sensitive Privilege Use'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }
        
        # 17.9.1 (L1) Ensure 'Audit IPsec Driver' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit IPsec Driver (Failure)' {
            Name      = 'IPsec Driver'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit IPsec Driver (Success)' {
            Name      = 'IPsec Driver'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }
        
        # 17.9.2 (L1) Ensure 'Audit Other System Events' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Other System Events (Failure)' {
            Name      = 'Other System Events'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit Other System Events (Success)' {
            Name      = 'Other System Events'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }
        
        # 17.9.3 (L1) Ensure 'Audit Security State Change' is set to 'Success'
        AuditPolicySubcategory 'Audit Security State Change (Success)' {
            Name      = 'Security State Change'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Security State Change (Failure)' {
            Name      = 'Security State Change'
            Ensure    = 'Absent'
            AuditFlag = 'Failure'
        }
        
        # 17.9.4 (L1) Ensure 'Audit Security System Extension' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Security System Extension (Failure)' {
            Name      = 'Security System Extension'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit Security System Extension (Success)' {
            Name      = 'Security System Extension'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }
        
        # 17.9.5 (L1) Ensure 'Audit System Integrity' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit System Integrity (Failure)' {
            Name      = 'System Integrity'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit System Integrity (Success)' {
            Name      = 'System Integrity'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }
       
       # 18.1.1.1 (L1) Ensure 'Prevent enabling lock screen camera' is set to 'Enabled'
       Registry 'NoLockScreenCamera' {
           Ensure      = 'Present'
           Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization'
           ValueName   = 'NoLockScreenCamera' 
           ValueType   = 'DWord' 
           ValueData   = '1' 
       }

       #  18.1.1.2 (L1) Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled'
       Registry 'NoLockScreenSlideshow' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization'
          ValueName    = 'NoLockScreenSlideshow'
          ValueType    = 'DWord'
          ValueData    = '1'
       }

       #  18.1.2.2 (L1) Ensure 'Allow input personalization' is set to 'Disabled'
       Registry 'AllowInputPersonalization' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\InputPersonalization'
          ValueName    = 'AllowInputPersonalization'
          ValueType    = 'DWord'
          ValueData    = '0'
       }

       #  18.1.3 (L2) Ensure 'Allow Online Tips' is set to 'Disabled'
       Registry 'AllowOnlineTips' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
          ValueName    = 'AllowOnlineTips'
          ValueType    = 'DWord'
          ValueData    = '0'
       }

       #  18.2.2 (L1) Ensure 'Do not allow password expiration time longer than required by policy' is set to 'Enabled' (MS only)
       Registry 'PwdExpirationProtectionEnabled' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\MicrosoftServices\AdmPwd'
          ValueName    = 'PwdExpirationProtectionEnabled'
          ValueType    = 'DWord'
          ValueData    = '1'
       }

       #  18.2.3 (L1) Ensure 'Enable Local Admin Password Management' is set to 'Enabled' (MS only)
       Registry 'AdmPwdEnabled' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd'
          ValueName    = 'AdmPwdEnabled'
          ValueType    = 'DWord'
          ValueData    = '1'
       }
       
       #  18.2.4 (L1) Ensure 'Password Settings: Password Complexity' is set to 'Enabled: Large letters + small letters + numbers + special characters' (MS only)
       Registry 'PasswordComplexity' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\MicrosoftServices\AdmPwd'
          ValueName    = 'PasswordComplexity'
          ValueType    = 'DWord'
          ValueData    = '4'

       }
       #  18.2.5 (L1) Ensure 'Password Settings: Password Length' is set to 'Enabled: 15 or more' (MS only)
       Registry 'PasswordLength' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd'
          ValueName    = 'PasswordLength'
          ValueType    = 'DWord'
          ValueData    = '15'
       }

       #  18.2.6 (L1) Ensure 'Password Settings: Password Age (Days)' is set to 'Enabled: 30 or fewer' (MS only)
       Registry 'PasswordAgeDays' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\MicrosoftServices\AdmPwd'
          ValueName    = 'PasswordAgeDays'
          ValueType    = 'DWord'
          ValueData    = '30'
       }

       #  18.3.1 (L1) Ensure 'Apply UAC restrictions to local accounts on network logons' is set to 'Enabled' (MS only)
       Registry 'LocalAccountTokenFilterPolicy' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
          ValueName    = 'LocalAccountTokenFilterPolicy'
          ValueType    = 'DWord'
          ValueData    = '0'
       }

       #  18.3.2 (L1) Ensure 'Configure SMB v1 client driver' is set to 'Enabled: Disable driver'
       Registry 'Start' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mrxsmb10'
          ValueName    = 'Start'
          ValueType    = 'DWord'
          ValueData    = '4'
       }

       #  18.3.3 (L1) Ensure 'Configure SMB v1 server' is set to 'Disabled'
       Registry 'SMB1' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
          ValueName    = 'SMB1'
          ValueType    = 'DWord'
          ValueData    = '0'
       }

       #  18.3.4 (L1) Ensure 'Enable Structured Exception Handling Overwrite Protection (SEHOP)' is set to 'Enabled'
       Registry 'DisableExceptionChainValidation' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\kernel'
          ValueName    = 'DisableExceptionChainValidation'
          ValueType    = 'DWord'
          ValueData    = '0'
       }

       #  18.3.5 (L1) Ensure 'Turn on Windows Defender protection against Potentially Unwanted Applications' is set to 'Enabled'
       Registry 'MpEnablePus' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsDefender\MpEngine'
          ValueName    = 'MpEnablePus'
          ValueType    = 'DWord'
          ValueData    = '1'
       }

       #  18.3.6 (L1) Ensure 'WDigest Authentication' is set to 'Disabled'
       Registry 'UseLogonCredential' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
          ValueName    = 'UseLogonCredential'
          ValueType    = 'DWord'
          ValueData    = '0'
       }

       #  18.4.1 (L1) Ensure 'MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)' is set to 'Disabled'
       Registry 'AutoAdminLogon' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsNT\CurrentVersion\Winlogon'
          ValueName    = 'AutoAdminLogon'
          ValueType    = 'String'
          ValueData    = '0'
       }

       #  18.4.2 (L1) Ensure 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'
       Registry 'DisableIPSourceRouting' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
          ValueName    = 'DisableIPSourceRouting'
          ValueType    = 'DWord'
          ValueData    = '2'
       }

       #  18.4.3 (L1) Ensure 'MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'
       Registry 'DisableIPSourceRouting2' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
          ValueName    = 'DisableIPSourceRouting'
          ValueType    = 'DWord'
          ValueData    = '2'
       }

       #  18.4.4 (L1) Ensure 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled'
       Registry 'EnableICMPRedirect' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
          ValueName    = 'EnableICMPRedirect'
          ValueType    = 'DWord'
          ValueData    = '0'
       }

       #  18.4.5 (L2) Ensure 'MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds' is set to 'Enabled: 300,000 or 5 minutes (recommended)'
       Registry 'KeepAliveTime' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
          ValueName    = 'KeepAliveTime'
          ValueType    = 'DWord'
          ValueData    = '300000'
       }

       #  18.4.6 (L1) Ensure 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled
       Registry 'NoNameReleaseOnDemand' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT\Parameters'
          ValueName    = 'NoNameReleaseOnDemand'
          ValueType    = 'DWord'
          ValueData    = '1'
       }

       #  18.4.7 (L2) Ensure 'MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)' is set to 'Disabled'
       Registry 'PerformRouterDiscovery' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
          ValueName    = 'PerformRouterDiscovery'
          ValueType    = 'DWord'
          ValueData    = '1'
       }

       #  18.4.8 (L1) Ensure 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)' is set to 'Enabled'
       Registry 'SafeDllSearchMode' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager'
          ValueName    = 'SafeDllSearchMode'
          ValueType    = 'DWord'
          ValueData    = '1'
       }

       #  18.4.9 (L1) Ensure 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)' is set to 'Enabled: 5 or fewer seconds'
       Registry 'ScreenSaverGracePeriod' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsNT\CurrentVersion\Winlogon'
          ValueName    = 'ScreenSaverGracePeriod'
          ValueType    = 'String'
          ValueData    = '5'
       }

       #  18.4.10 (L2) Ensure 'MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'
       Registry 'TcpMaxDataRetransmissions' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters'
          ValueName    = 'TcpMaxDataRetransmissions'
          ValueType    = 'DWord'
          ValueData    = '5'
       }

       #  18.4.11 (L2) Ensure 'MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'
       Registry 'TcpMaxDataRetransmissions2' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
          ValueName    = 'TcpMaxDataRetransmissions'
          ValueType    = 'DWord'
          ValueData    = '5'
       }

       #  18.4.12 (L1) Ensure 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' is set to 'Enabled: 90% or less'
       Registry 'WarningLevel' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security'
          ValueName    = 'WarningLevel'
          ValueType    = 'DWord'
          ValueData    = '90'
       }

       #  18.5.4.1 (L1) Set 'NetBIOS node type' to 'P-node' (Ensure NetBT Parameter 'NodeType' is set to '0x2 (2)') (MS Only)
       Registry 'NodeType' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\NetBT\Parameters'
          ValueName    = 'NodeType'
          ValueType    = 'DWord'
          ValueData    = '2'
       }

       #  18.5.4.2 (L1) Ensure 'Turn off multicast name resolution' is set to 'Enabled' (MS Only)
       Registry 'EnableMulticast' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsNT\DNSClient'
          ValueName    = 'EnableMulticast'
          ValueType    = 'DWord'
          ValueData    = '0'
       }


       #  18.5.5.1 (L2) Ensure 'Enable Font Providers' is set to 'Disabled'
       Registry 'EnableFontProviders' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
          ValueName    = 'EnableFontProviders'
          ValueType    = 'DWord'
          ValueData    = '0'
       }

       #  18.5.8.1 (L1) Ensure 'Enable insecure guest logons' is set to 'Disabled'
       Registry 'AllowInsecureGuestAuth' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation'
          ValueName    = 'AllowInsecureGuestAuth'
          ValueType    = 'DWord'
          ValueData    = '0'
       }

       
       #  18.5.9.1 (L2) Ensure 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled'
       Registry 'AllowLLTDIOOnDomain' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD'
          ValueName    = 'AllowLLTDIOOnDomain'
          ValueType    = 'DWord'
          ValueData    = '0'
       }
       
       #  18.5.9.1 (L2) Ensure 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled'
       Registry 'AllowLLTDIOOnPublicNet' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD'
          ValueName    = 'AllowLLTDIOOnPublicNet'
          ValueType    = 'DWord'
          ValueData    = '0'
       }
       
       #  18.5.9.1 (L2) Ensure 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled'
       Registry 'EnableLLTDIO' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD'
          ValueName    = 'EnableLLTDIO'
          ValueType    = 'DWord'
          ValueData    = '0'
       }
       
       #  18.5.9.1 (L2) Ensure 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled'
       Registry 'ProhibitLLTDIOOnPrivateNet' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD'
          ValueName    = 'ProhibitLLTDIOOnPrivateNet'
          ValueType    = 'DWord'
          ValueData    = '0'
       }

       #  18.5.9.2 (L2) Ensure 'Turn on Responder (RSPNDR) driver' is set to 'Disabled'
       Registry 'AllowRspndrOnDomain' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD'
          ValueName    = 'AllowRspndrOnDomain'
          ValueType    = 'DWord'
          ValueData    = '0'
       }

       #  18.5.9.2 (L2) Ensure 'Turn on Responder (RSPNDR) driver' is set to 'Disabled'
       Registry 'AllowRspndrOnPublicNet' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD'
          ValueName    = 'AllowRspndrOnPublicNet'
          ValueType    = 'DWord'
          ValueData    = '0'
       }

       #  18.5.9.2 (L2) Ensure 'Turn on Responder (RSPNDR) driver' is set to 'Disabled'
       Registry 'EnableRspndr' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD'
          ValueName    = 'EnableRspndr'
          ValueType    = 'DWord'
          ValueData    = '0'
       }

       #  18.5.9.2 (L2) Ensure 'Turn on Responder (RSPNDR) driver' is set to 'Disabled'
       Registry 'ProhibitRspndrOnPrivateNet' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD'
          ValueName    = 'ProhibitRspndrOnPrivateNet'
          ValueType    = 'DWord'
          ValueData    = '0'
       }

       #  18.5.10.2 (L2) Ensure 'Turn off Microsoft Peer-to-Peer Networking Services' is set to 'Enabled'
       Registry 'Disabled' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Peernet'
          ValueName    = 'Disabled'
          ValueType    = 'DWord'
          ValueData    = '1'
       }

       #  18.5.11.2 (L1) Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'
       Registry 'NC_AllowNetBridge_NLA' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkConnections'
          ValueName    = 'NC_AllowNetBridge_NLA'
          ValueType    = 'DWord'
          ValueData    = '0'
       }

       #  18.5.11.3 (L1) Ensure 'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled'
       Registry 'NC_ShowSharedAccessUI' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkConnections'
          ValueName    = 'NC_ShowSharedAccessUI'
          ValueType    = 'DWord'
          ValueData    = '0'
       }

       #  18.5.11.4 (L1) Ensure 'Require domain users to elevate when setting a network's location' is set to 'Enabled'
       Registry 'NC_StdDomainUserSetLocation' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkConnections'
          ValueName    = 'NC_StdDomainUserSetLocation'
          ValueType    = 'DWord'
          ValueData    = '1'
       }

       #  18.5.14.1 (L1) Ensure 'Hardened UNC Paths' is set to 'Enabled, with "Require Mutual Authentication" and "Require Integrity" set for all NETLOGON and SYSVOL shares'
       Registry '\\*\NETLOGON' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
          ValueName    = '\\*\NETLOGON'
          ValueType    = 'String'
          ValueData    = 'RequireMutualAuthentication=1, RequireIntegrity=1'
       }

       #  18.5.14.1 (L1) Ensure 'Hardened UNC Paths' is set to 'Enabled, with "Require Mutual Authentication" and "Require Integrity" set for all NETLOGON and SYSVOL shares'
       Registry '\\*\SYSVOL' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
          ValueName    = '\\*\SYSVOL'
          ValueType    = 'String'
          ValueData    = 'RequireMutualAuthentication=1, RequireIntegrity=1'
       }

       #  18.5.19.2.1 (L2) Disable IPv6 (Ensure TCPIP6 Parameter 'DisabledComponents' is set to '0xff (255)')
       Registry 'DisabledComponents' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters'
          ValueName    = 'DisabledComponents'
          ValueType    = 'DWord'
          ValueData    = '255'
       }

       #  18.5.20.1 (L2) Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled'
       Registry 'EnableRegistrars' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars'
          ValueName    = 'EnableRegistrars'
          ValueType    = 'DWord'
          ValueData    = '0'
       }

       #  18.5.20.1 (L2) Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled'
       Registry 'DisableUPnPRegistrar' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars'
          ValueName    = 'DisableUPnPRegistrar'
          ValueType    = 'DWord'
          ValueData    = '0'
       }

       #  18.5.20.1 (L2) Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled'
       Registry 'DisableInBand802DOT11Registrar' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars'
          ValueName    = 'DisableInBand802DOT11Registrar'
          ValueType    = 'DWord'
          ValueData    = '0'
       }

       #  18.5.20.1 (L2) Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled'
       Registry 'DisableFlashConfigRegistrar' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars'
          ValueName    = 'DisableFlashConfigRegistrar'
          ValueType    = 'DWord'
          ValueData    = '0'
       }

       #  18.5.20.1 (L2) Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled'
       Registry 'DisableWPDRegistrar' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars'
          ValueName    = 'DisableWPDRegistrar'
          ValueType    = 'DWord'
          ValueData    = '0'
       }
       
       #  18.5.20.2 (L2) Ensure 'Prohibit access of the Windows Connect Nowwizards' is set to 'Enabled'
       Registry 'DisableWcnUi' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\UI'
          ValueName    = 'DisableWcnUi'
          ValueType    = 'DWord'
          ValueData    = '1'
       }

       #  18.5.21.1 (L1) Ensure 'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled'
       Registry 'fMinimizeConnections' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy'
          ValueName  = 'fMinimizeConnections'
          ValueType  = 'DWord'
          ValueData  = '1'
       }
       
       #  18.5.21.2 (L2) Ensure '..'
       Registry 'fBlockNonDomain' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy'
          ValueName  = 'fBlockNonDomain'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.8.3.1 (L1) Ensure 'Include command line in process creation events' is set to 'Disabled'
       Registry 'ProcessCreationIncludeCmdLine_Enabled' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
          ValueName  = 'ProcessCreationIncludeCmdLine_Enabled'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.8.4.1 (L1) Ensure 'Remote host allows delegation of non-exportable credentials' is set to 'Enabled'
       Registry 'AllowProtectedCreds' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation'
          ValueName  = 'AllowProtectedCreds'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.8.5.1 (NG) Ensure 'Turn On Virtualization Based Security' is set to 'Enabled' (MS Only)
       Registry 'EnableVirtualizationBasedSecurity' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
          ValueName  = 'EnableVirtualizationBasedSecurity'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.8.5.2 (NG) Ensure 'Turn On Virtualization Based Security: Select Platform Security Level' is set to 'Secure Boot and DMA Protection' (MS Only)
       Registry 'RequirePlatformSecurityFeatures' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
          ValueName  = 'RequirePlatformSecurityFeatures'
          ValueType  = 'DWord'
          ValueData  = '3'
       }

       #  18.8.5.3 (NG) Ensure 'Turn On Virtualization Based Security: Virtualization Based Protection of Code Integrity' is set to 'Enabled with UEFI lock' (MS Only)
       Registry 'HypervisorEnforcedCodeIntegrity' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
          ValueName  = 'HypervisorEnforcedCodeIntegrity'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.8.5.4 (NG) Ensure 'Turn On Virtualization Based Security: Require UEFI Memory Attributes Table' is set to 'True (checked)' (MS Only)
       Registry 'HVCIMATRequired' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
          ValueName  = 'HVCIMATRequired'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.8.5.5 (NG) Ensure 'Turn On Virtualization Based Security: Credential Guard Configuration' is set to 'Enabled with UEFI lock' (MS Only)
       Registry 'LsaCfgFlags' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
          ValueName  = 'LsaCfgFlags'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.8.14.1 (L1) Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical'
       Registry 'DriverLoadPolicy' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Policies\EarlyLaunch'
          ValueName  = 'DriverLoadPolicy'
          ValueType  = 'DWord'
          ValueData  = '3'
       }

       #  18.8.21.2 (L1) Ensure 'Configure registry policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE'
       Registry 'NoBackgroundPolicy' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\GroupPolicy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
          ValueName  = 'NoBackgroundPolicy'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.8.21.3 (L1) Ensure 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE'
       Registry 'NoGPOListChanges' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\GroupPolicy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
          ValueName  = 'NoGPOListChanges'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.8.21.4 (L1) Ensure 'Continue experiences on this device' is set to 'Disabled'
       Registry 'EnableCdp' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
          ValueName  = 'EnableCdp'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.8.21.5 (L1) Ensure 'Turn off background refresh of Group Policy' is set to 'Disabled'
       Registry 'DisableBkGndGroupPolicy' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
          ValueName  = 'DisableBkGndGroupPolicy'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.8.22.1.1 (L1) Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
       Registry 'DisableWebPnPDownload' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsNT\Printers'
          ValueName  = 'DisableWebPnPDownload'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.8.22.1.2 (L2) Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'
       Registry 'PreventHandwritingDataSharing' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC'
          ValueName  = 'PreventHandwritingDataSharing'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.8.22.1.3 (L2) Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
       Registry 'PreventHandwritingErrorReports' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports'
          ValueName  = 'PreventHandwritingErrorReports'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.8.22.1.4 (L2) Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
       Registry 'ExitOnMSICW' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard'
          ValueName  = 'ExitOnMSICW'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.8.22.1.5 (L1) Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
       Registry 'NoWebServices' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
          ValueName  = 'NoWebServices'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.8.22.1.6 (L1) Ensure 'Turn off printing over HTTP' is set to 'Enabled'
       Registry 'DisableHTTPPrinting' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsNT\Printers'
          ValueName  = 'DisableHTTPPrinting'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.8.22.1.7 (L2) Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
       Registry 'NoRegistration' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control'
          ValueName  = 'NoRegistration'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.8.22.1.8 (L2) Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
       Registry 'DisableContentFileUpdates' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion'
          ValueName  = 'DisableContentFileUpdates'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.8.22.1.9 (L2) Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
       Registry 'NoOnlinePrintsWizard' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
          ValueName  = 'NoOnlinePrintsWizard'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.8.22.1.10 (L2) Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
       Registry 'NoPublishingWizard' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
          ValueName  = 'NoPublishingWizard'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.8.22.1.11 (L2) Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
       Registry 'CEIP' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client'
          ValueName  = 'CEIP'
          ValueType  = 'DWord'
          ValueData  = '2'
       }

       #  18.8.22.1.12 (L2) Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
       Registry 'CEIPEnable' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows'
          ValueName  = 'CEIPEnable'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.8.22.1.13 (L2) Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
       Registry 'Disabled2' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting'
          ValueName  = 'Disabled'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.8.22.1.13 (L2) Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
       Registry 'DoReport' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting'
          ValueName  = 'DoReport'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.8.25.1 (L2) Ensure 'Support device authentication using certificate' is set to 'Enabled: Automatic'
       Registry 'DevicePKInitBehavior' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters'
          ValueName  = 'DevicePKInitBehavior'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.8.25.1 (L2) Ensure 'Support device authentication using certificate' is set to 'Enabled: Automatic'
       Registry 'DevicePKInitEnabled' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters'
          ValueName  = 'DevicePKInitEnabled'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.8.26.1 (L2) Ensure 'Disallow copying of user input methods to the system account for sign-in' is set to 'Enabled'
       Registry 'BlockUserInputMethodsForSignIn' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\ControlPanel\International'
          ValueName  = 'BlockUserInputMethodsForSignIn'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.8.27.1 (L1) Ensure 'Block user from showing account details on signin' is set to 'Enabled'
       Registry 'BlockUserFromShowingAccountDetailsOnSignin' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
          ValueName  = 'BlockUserFromShowingAccountDetailsOnSignin'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.8.27.2 (L1) Ensure 'Do not display network selection UI' is set to 'Enabled'
       Registry 'DontDisplayNetworkSelectionUI' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
          ValueName  = 'DontDisplayNetworkSelectionUI'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.8.27.3 (L1) Ensure 'Do not enumerate connected users on domainjoined computers' is set to 'Enabled'
       Registry 'DontEnumerateConnectedUsers' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
          ValueName  = 'DontEnumerateConnectedUsers'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.8.27.4 (L1) Ensure 'Enumerate local users on domain-joined computers' is set to 'Disabled' (MS only)
       Registry 'EnumerateLocalUsers' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
          ValueName  = 'EnumerateLocalUsers'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.8.27.5 (L1) Ensure 'Turn off app notifications on the lock screen' is set to 'Enabled'
       Registry 'DisableLockScreenAppNotifications' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
          ValueName  = 'DisableLockScreenAppNotifications'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.8.27.6 (L1) Ensure 'Turn off picture password sign-in' is set to 'Enabled'
       Registry 'BlockDomainPicturePassword' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
          ValueName  = 'BlockDomainPicturePassword'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.8.27.7 (L1) Ensure 'Turn on convenience PIN sign-in' is set to 'Disabled'
       Registry 'AllowDomainPINLogon' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
          ValueName  = 'AllowDomainPINLogon'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.8.28.1 (L1) Ensure 'Untrusted Font Blocking' is set to 'Enabled: Block untrusted fonts and log events'
       Registry 'MitigationOptions_FontBocking' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsNT\MitigationOptions'
          ValueName  = 'MitigationOptions_FontBocking'
          ValueType  = 'String'
          ValueData  = '1000000000000'
       }

       #  18.8.33.6.1 (L2) Ensure 'Allow network connectivity during connectedstandby (on battery)' is set to 'Disabled'
       Registry 'DCSettingIndex' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9'
          ValueName  = 'DCSettingIndex'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.8.33.6.2 (L2) Ensure 'Allow network connectivity during connectedstandby (plugged in)' is set to 'Disabled'
       Registry 'ACSettingIndex' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9'
          ValueName  = 'ACSettingIndex'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.8.33.6.3 (L1) Ensure 'Require a password when a computer wakes (on battery)' is set to 'Enabled'
       Registry 'DCSettingIndex2' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb100d-47d6-a2d5-f7d2daa51f51'
          ValueName  = 'DCSettingIndex'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.8.33.6.4 (L1) Ensure 'Require a password when a computer wakes (plugged in)' is set to 'Enabled'
       Registry 'ACSettingIndex2' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb100d-47d6-a2d5-f7d2daa51f51'
          ValueName  = 'ACSettingIndex'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.8.35.1 (L1) Ensure 'Configure Offer Remote Assistance' is set to 'Disabled'
       Registry 'fAllowUnsolicited' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
          ValueName  = 'fAllowUnsolicited'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.8.35.2 (L1) Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled'
       Registry 'fAllowToGetHelp' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
          ValueName  = 'fAllowToGetHelp'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.8.36.1 (L1) Ensure 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled' (MS only)
       Registry 'EnableAuthEpResolution' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsNT\Rpc'
          ValueName  = 'EnableAuthEpResolution'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.8.36.2 (L2) Ensure 'Restrict Unauthenticated RPC clients' is set to 'Enabled: Authenticated' (MS only)
       Registry 'RestrictRemoteClients' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsNT\Rpc'
          ValueName  = 'RestrictRemoteClients'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.8.44.5.1 (L2) Ensure 'Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider' is set to 'Disabled'
       Registry 'DisableQueryRemoteServer' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy'
          ValueName  = 'DisableQueryRemoteServer'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.8.44.11.1 (L2) Ensure 'Enable/Disable PerfTrack' is set to 'Disabled'
       Registry 'ScenarioExecutionEnabled' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}'
          ValueName  = 'ScenarioExecutionEnabled'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.8.46.1 (L2) Ensure 'Turn off the advertising ID' is set to 'Enabled'
       Registry 'DisabledByGroupPolicy' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\policies\Microsoft\Windows\AdvertisingInfo'
          ValueName  = 'DisabledByGroupPolicy'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.8.49.1.1 (L2) Ensure 'Enable Windows NTP Client' is set to 'Enabled'
       Registry 'EnableNTPClient' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient'
          ValueName  = 'Enabled'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.8.49.1.2 (L2) Ensure 'Enable Windows NTP Server' is set to 'Disabled' (MS only)
       Registry 'EnableNTPServer' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer'
          ValueName  = 'Enabled'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.4.1 (L2) Ensure 'Allow a Windows app to share application data between users' is set to 'Disabled'
       Registry 'AllowSharedLocalAppData' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager'
          ValueName  = 'AllowSharedLocalAppData'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.9.6.1 (L1) Ensure 'Allow Microsoft accounts to be optional' is set to 'Enabled'
       Registry 'MSAOptional' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
          ValueName  = 'MSAOptional'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.8.1 (L1) Ensure 'Disallow Autoplay for non-volume devices' is set to 'Enabled'
       Registry 'NoAutoplayfornonVolume' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer'
          ValueName  = 'NoAutoplayfornonVolume'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.8.2 (L1) Ensure 'Set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands'
       Registry 'NoAutorun' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
          ValueName  = 'NoAutorun'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.8.3 (L1) Ensure 'Turn off Autoplay' is set to 'Enabled: All drives'
       Registry 'NoDriveTypeAutoRun' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
          ValueName  = 'NoDriveTypeAutoRun'
          ValueType  = 'DWord'
          ValueData  = '255'
       }
       
       #  18.9.10.1.1 (L1) Ensure 'Configure enhanced anti-spoofing' is set to 'Enabled'
       Registry 'EnhancedAntiSpoofing' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Biometrics\FacialFeatures'
          ValueName  = 'EnhancedAntiSpoofing'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.12.1 (L2) Ensure 'Allow Use of Camera' is set to 'Disabled'
       Registry 'AllowCamera' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Camera'
          ValueName  = 'AllowCamera'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.9.13.1 (L1) Ensure 'Turn off Microsoft consumer experiences' is set to 'Enabled'
       Registry 'DisableWindowsConsumerFeatures' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
          ValueName  = 'DisableWindowsConsumerFeatures'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.14.1 (L1) Ensure 'Require pin for pairing' is set to 'Enabled'
       Registry 'RequirePinForPairing' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Connect'
          ValueName  = 'RequirePinForPairing'
          ValueType  = 'DWord'
          ValueData  = '1'
       }       
       
       # 18.9.15.1 (L1) Ensure 'Do not display the password reveal button' is set to 'Enabled'
       Registry 'DisablePasswordReveal' {
           Ensure      = 'Present'
           Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CredUI'
           ValueName   = 'DisablePasswordReveal'
           ValueType   = 'DWord'
           ValueData   = '1'
       }

       #  18.9.15.2 (L1) Ensure 'Enumerate administrator accounts on elevation' is set to 'Disabled'
       Registry 'EnumerateAdministrators' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI'
          ValueName  = 'EnumerateAdministrators'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.9.16.1 (L1) Ensure 'Allow Telemetry' is set to 'Enabled: 0 - Security [Enterprise Only]' or 'Enabled: 1 - Basic'
       Registry 'AllowTelemetry' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
          ValueName  = 'AllowTelemetry'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.9.16.2 (L2) Ensure 'Configure Authenticated Proxy usage for the Connected User Experience and Telemetry service' is set to 'Enabled: Disable Authenticated Proxy usage'
       Registry 'DisableEnterpriseAuthProxy' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
          ValueName  = 'DisableEnterpriseAuthProxy'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.9.16.3 (L1) Ensure 'Disable pre-release features or settings' is set to 'Disabled'
       Registry 'EnableConfigFlighting' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds'
          ValueName  = 'EnableConfigFlighting'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.9.16.4 (L1) Ensure 'Do not show feedback notifications' is set to 'Enabled'
       Registry 'DoNotShowFeedbackNotifications' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
          ValueName  = 'DoNotShowFeedbackNotifications'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.16.5 (L1) Ensure 'Toggle user control over Insider builds' is set to 'Disabled'
       Registry 'AllowBuildPreview' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds'
          ValueName  = 'AllowBuildPreview'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.9.26.1.1 (L1) Ensure 'Application: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
       Registry 'RetentionApplicationLog' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'
          ValueName  = 'Retention'
          ValueType  = 'String'
          ValueData  = '0'
       }

       #  18.9.26.1.2 (L1) Ensure 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'
       Registry 'MaxSizeApplicationLog' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'
          ValueName  = 'MaxSize'
          ValueType  = 'DWord'
          ValueData  = '32768'
       }

       #  18.9.26.2.1 (L1) Ensure 'Security: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
       Registry 'RetentionSecurityLog' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'
          ValueName  = 'Retention'
          ValueType  = 'String'
          ValueData  = '0'
       }

       #  18.9.26.2.2 (L1) Ensure 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater'
       Registry 'MaxSizeSecurityLog' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'
          ValueName  = 'MaxSize'
          ValueType  = 'DWord'
          ValueData  = '196608'
       }

       #  18.9.26.3.1 (L1) Ensure 'Setup: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
       Registry 'RetentionSetupLog' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup'
          ValueName  = 'Retention'
          ValueType  = 'String'
          ValueData  = '0'
       }

       #  18.9.26.3.2 (L1) Ensure 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'
       Registry 'MaxSizeSetupLog' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup'
          ValueName  = 'MaxSize'
          ValueType  = 'DWord'
          ValueData  = '32768'
       }

       #  18.9.26.4.1 (L1) Ensure 'System: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
       Registry 'RetentionSystemLog' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System'
          ValueName  = 'Retention'
          ValueType  = 'String'
          ValueData  = '0'
       }

       #  18.9.26.4.2 (L1) Ensure 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'
       Registry 'MaxSizeSystemLog' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System'
          ValueName  = 'MaxSize'
          ValueType  = 'DWord'
          ValueData  = '32768'
       }

       #  18.9.30.2 (L1) Ensure 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled'
       Registry 'NoDataExecutionPrevention' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer'
          ValueName  = 'NoDataExecutionPrevention'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.9.30.3 (L1) Ensure 'Turn off heap termination on corruption' is set to 'Disabled'
       Registry 'NoHeapTerminationOnCorruption' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer'
          ValueName  = 'NoHeapTerminationOnCorruption'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.9.30.4 (L1) Ensure 'Turn off shell protocol protected mode' is set to 'Disabled'
       Registry 'PreXPSP2ShellProtocolBehavior' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
          ValueName  = 'PreXPSP2ShellProtocolBehavior'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.9.39.2 (L2) Ensure 'Turn off location' is set to 'Enabled'
       Registry 'DisableLocation' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors'
          ValueName  = 'DisableLocation'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.43.1 (L2) Ensure 'Allow Message Service Cloud Sync' is set to 'Disabled'
       Registry 'AllowMessageSync' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Messaging'
          ValueName  = 'AllowMessageSync'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.9.44.1 (L1) Ensure 'Block all consumer Microsoft account user authentication' is set to 'Enabled'
       Registry 'DisableUserAuth' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftAccount'
          ValueName  = 'DisableUserAuth'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.52.1 (L1) Ensure 'Prevent the usage of OneDrive for file storage' is set to 'Enabled'
       Registry 'DisableFileSyncNGSC' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OneDrive'
          ValueName  = 'DisableFileSyncNGSC'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.58.2.2 (L1) Ensure 'Do not allow passwords to be saved' is set to 'Enabled'
       Registry 'DisablePasswordSaving' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
          ValueName  = 'DisablePasswordSaving'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.58.3.2.1 (L2) Ensure 'Restrict Remote Desktop Services users to a single Remote Desktop Services session' is set to 'Enabled'
       Registry 'fSingleSessionPerUser' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
          ValueName  = 'fSingleSessionPerUser'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.58.3.3.1 (L2) Ensure 'Do not allow COM port redirection' is set to 'Enabled'
       Registry 'fDisableCcm' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
          ValueName  = 'fDisableCcm'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.58.3.3.2 (L1) Ensure 'Do not allow drive redirection' is set to 'Enabled'
       Registry 'fDisableCdm' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
          ValueName  = 'fDisableCdm'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.58.3.3.3 (L2) Ensure 'Do not allow LPT port redirection' is set to 'Enabled'
       Registry 'fDisableLPT' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
          ValueName  = 'fDisableLPT'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.58.3.3.4 (L2) Ensure 'Do not allow supported Plug and Play device redirection' is set to 'Enabled'
       Registry 'fDisablePNPRedir' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
          ValueName  = 'fDisablePNPRedir'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.58.3.9.1 (L1) Ensure 'Always prompt for password upon connection' is set to 'Enabled'
       Registry 'fPromptForPassword' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
          ValueName  = 'fPromptForPassword'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.58.3.9.2 (L1) Ensure 'Require secure RPC communication' is set to 'Enabled'
       Registry 'fEncryptRPCTraffic' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
          ValueName  = 'fEncryptRPCTraffic'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.58.3.9.3 (L1) Ensure 'Set client connection encryption level' is set to 'Enabled: High Level'
       Registry 'MinEncryptionLevel' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
          ValueName  = 'MinEncryptionLevel'
          ValueType  = 'DWord'
          ValueData  = '3'
       }

       #  18.9.58.3.10.1 (L2) Ensure 'Set time limit for active but idle Remote Desktop Services sessions' is set to 'Enabled: 15 minutes or less'
       Registry 'MaxIdleTime' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
          ValueName  = 'MaxIdleTime'
          ValueType  = 'DWord'
          ValueData  = '900000'
       }

       #  18.9.58.3.10.2 (L2) Ensure 'Set time limit for disconnected sessions' is set to 'Enabled: 1 minute'
       Registry 'MaxDisconnectionTime' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
          ValueName  = 'MaxDisconnectionTime'
          ValueType  = 'DWord'
          ValueData  = '60000'
       }

       #  18.9.58.3.11.1 (L1) Ensure 'Do not delete temp folders upon exit' is set to 'Disabled'
       Registry 'DeleteTempDirsOnExit' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
          ValueName  = 'DeleteTempDirsOnExit'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.58.3.11.2 (L1) Ensure 'Do not use temporary folders per session' is set to 'Disabled'
       Registry 'PerSessionTempDir' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
          ValueName  = 'PerSessionTempDir'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.59.1 (L1) Ensure 'Prevent downloading of enclosures' is set to 'Enabled'
       Registry 'DisableEnclosureDownload' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\InternetExplorer\Feeds'
          ValueName  = 'DisableEnclosureDownload'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.60.2 (L2) Ensure 'Allow Cloud Search' is set to 'Enabled: Disable Cloud Search'
       Registry 'AllowCloudSearch' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsSearch'
          ValueName  = 'AllowCloudSearch'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.60.3 (L1) Ensure 'Allow indexing of encrypted files' is set to 'Disabled'
       Registry 'AllowIndexingEncryptedStoresOrItems' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsSearch'
          ValueName  = 'AllowIndexingEncryptedStoresOrItems'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.9.65.1 (L2) Ensure 'Turn off KMS Client Online AVS Validation' is set to 'Enabled'
       Registry 'NoGenTicket' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform'
          ValueName  = 'NoGenTicket'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.76.3.1 (L1) Ensure 'Configure local setting override for reporting to Microsoft MAPS' is set to 'Disabled'
       Registry 'LocalSettingOverrideSpynetReporting' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsDefender\Spynet'
          ValueName  = 'LocalSettingOverrideSpynetReporting'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.9.76.3.2  (L2) Ensure 'Join Microsoft MAPS' is set to 'Disabled'
       Registry 'SpynetReporting' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsDefender\Spynet'
          ValueName  = 'SpynetReporting'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.9.76.7.1 (L1) Ensure 'Turn on behavior monitoring' is set to 'Enabled'
       Registry 'DisableBehaviorMonitoring' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
          ValueName  = 'DisableBehaviorMonitoring'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.9.76.9.1 (L2) Ensure 'Configure Watson events' is set to 'Disabled'
       Registry 'DisableGenericRePorts' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsDefender\Reporting'
          ValueName  = 'DisableGenericRePorts'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.76.10.1 (L1) Ensure 'Scan removable drives' is set to 'Enabled'
       Registry 'DisableRemovableDriveScanning' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsDefender\Scan'
          ValueName  = 'DisableRemovableDriveScanning'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.9.76.10.2  (L1) Ensure 'Turn on e-mail scanning' is set to 'Enabled'
       Registry 'EnableEmailScanning' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsDefender\Scan'
          ValueName  = 'EnableEmailScanning'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.76.13.1.1 (L1) Ensure 'Configure Attack Surface Reduction rules' is set to 'Enabled'
       Registry 'ExploitGuard_ASR_Rules' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR'
          ValueName  = 'ExploitGuard_ASR_Rules'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.76.13.1.2 (L1) Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is 'configured'
       Registry '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
          ValueName  = '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84'
          ValueType  = 'String'
          ValueData  = '1'
       }

       #  18.9.76.13.1.2 (L1) Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is 'configured'
       Registry '3b576869-a4ec-4529-8536-b80a7769e899' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
          ValueName  = '3b576869-a4ec-4529-8536-b80a7769e899'
          ValueType  = 'String'
          ValueData  = '1'
       }

       #  18.9.76.13.1.2 (L1) Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is 'configured'
       Registry 'd4f940ab-401b-4efc-aadc-ad5f3c50688a' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
          ValueName  = 'd4f940ab-401b-4efc-aadc-ad5f3c50688a'
          ValueType  = 'String'
          ValueData  = '1'
       }

       #  18.9.76.13.1.2 (L1) Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is 'configured'
       Registry '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
          ValueName  = '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b'
          ValueType  = 'String'
          ValueData  = '1'
       }

       #  18.9.76.13.1.2 (L1) Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is 'configured'
       Registry '5beb7efe-fd9a-4556-801d-275e5ffc04cc' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
          ValueName  = '5beb7efe-fd9a-4556-801d-275e5ffc04cc'
          ValueType  = 'String'
          ValueData  = '1'
       }

       #  18.9.76.13.1.2 (L1) Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is 'configured'
       Registry 'd3e037e1-3eb8-44c8-a917-57927947596d' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
          ValueName  = 'd3e037e1-3eb8-44c8-a917-57927947596d'
          ValueType  = 'String'
          ValueData  = '1'
       }

       #  18.9.76.13.1.2 (L1) Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is 'configured'
       Registry 'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
          ValueName  = 'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550'
          ValueType  = 'String'
          ValueData  = '1'
       }

       #  18.9.76.13.3.1 (L1) Ensure 'Prevent users and apps from accessing dangerous websites' is set to 'Enabled: Block'
       Registry 'EnableNetworkProtection' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection'
          ValueName  = 'EnableNetworkProtection'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.76.14 (L1) Ensure 'Turn off Windows Defender AntiVirus' is set to 'Disabled'
       Registry 'DisableAntiSpyware' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsDefender'
          ValueName  = 'DisableAntiSpyware'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.9.79.1.1 (L1) Ensure 'Prevent users from modifying settings' is set to 'Enabled'
       Registry 'DisallowExploitProtectionOverride' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection'
          ValueName  = 'DisallowExploitProtectionOverride'
          ValueType  = 'DWord'
          ValueData  = '1'
       }
       
       #  18.9.80.1.1 (L1) Ensure 'Configure Windows Defender SmartScreen' is set to 'Enabled: Warn and prevent bypass'
       Registry 'EnableSmartScreen' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
          ValueName  = 'EnableSmartScreen'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.80.1.1 (L1) Ensure 'Configure Windows Defender SmartScreen' is set to 'Enabled: Warn and prevent bypass'
       Registry 'ShellSmartScreenLevel' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
          ValueName  = 'ShellSmartScreenLevel'
          ValueType  = 'String'
          ValueData  = 'Block'
       }
       

       #  18.9.84.1 (L2) Ensure 'Allow suggested apps in Windows Ink Workspace' is set to 'Disabled'
       Registry 'AllowSuggestedAppsInWindowsInkWorkspace' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace'
          ValueName  = 'AllowSuggestedAppsInWindowsInkWorkspace'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.9.84.2 (L1) Ensure 'Allow Windows Ink Workspace' is set to 'Enabled: On, but disallow access above lock' OR 'Disabled' but not 'Enabled: On'
       Registry 'AllowWindowsInkWorkspace' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace'
          ValueName  = 'AllowWindowsInkWorkspace'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.85.1 (L1) Ensure 'Allow user control over installs' is set to 'Disabled'
       Registry 'EnableUserControl' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer'
          ValueName  = 'EnableUserControl'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.9.85.2 (L1) Ensure 'Always install with elevated privileges' is set to 'Disabled'
       Registry 'AlwaysInstallElevated' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer'
          ValueName  = 'AlwaysInstallElevated'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.9.85.3 (L2) Ensure 'Prevent Internet Explorer security prompt for Windows Installer scripts' is set to 'Disabled'
       Registry 'SafeForScripting' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer'
          ValueName  = 'SafeForScripting'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.9.86.1 (L1) Ensure 'Sign-in last interactive user automatically after a system-initiated restart' is set to 'Disabled'
       Registry 'DisableAutomaticRestartSignOn' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
          ValueName  = 'DisableAutomaticRestartSignOn'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.95.1 (L1) Ensure 'Turn on PowerShell Script Block Logging' is set to 'Disabled'
       Registry 'EnableScriptBlockLogging' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
          ValueName  = 'EnableScriptBlockLogging'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.9.95.2 (L1) Ensure 'Turn on PowerShell Transcription' is set to 'Disabled'
       Registry 'EnableTranscripting' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
          ValueName  = 'EnableTranscripting'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.9.97.1.1 (L1) Ensure 'Allow Basic authentication' is set to 'Disabled'
       Registry 'AllowBasic' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
          ValueName  = 'AllowBasic'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.9.97.1.2 (L1) Ensure 'Allow unencrypted traffic' is set to 'Disabled'
       Registry 'AllowUnencryptedTraffic' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
          ValueName  = 'AllowUnencryptedTraffic'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.9.97.1.3 (L1) Ensure 'Disallow Digest authentication' is set to 'Enabled'
       Registry 'AllowDigest' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
          ValueName  = 'AllowDigest'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.9.97.2.1 (L1) Ensure 'Allow Basic authentication' is set to 'Disabled'
       Registry 'AllowBasic2' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
          ValueName  = 'AllowBasic'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.9.97.2.2 (L2) Ensure 'Allow remote server management through WinRM' is set to 'Disabled'
       #MODIFY to 1 for testing
      #  Registry 'AllowAutoConfig' {
      #     Ensure     = 'Present'
      #     Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
      #     ValueName  = 'AllowAutoConfig'
      #     ValueType  = 'DWord'
      #     ValueData  = '0'
      #  }

       #  18.9.97.2.3 (L1) Ensure 'Allow unencrypted traffic' is set to 'Disabled'
       Registry 'AllowUnencryptedTraffic2' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
          ValueName  = 'AllowUnencryptedTraffic'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.9.97.2.4 (L1) Ensure 'Disallow WinRM from storing RunAs credentials' is set to 'Enabled'
       Registry 'DisableRunAs' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
          ValueName  = 'DisableRunAs'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.9.98.1 (L2) Ensure 'Allow Remote Shell Access' is set to 'Disabled'
       Registry 'AllowRemoteShellAccess' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS'
          ValueName  = 'AllowRemoteShellAccess'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.9.101.1.1 (L1) Ensure 'Manage preview builds' is set to 'Enabled: Disable preview builds'
       Registry 'ManagePreviewBuilds' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
          ValueName  = 'ManagePreviewBuilds'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.101.1.1 (L1) Ensure 'Manage preview builds' is set to 'Enabled: Disable preview builds'
       Registry 'ManagePreviewBuildsPolicyValue' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
          ValueName  = 'ManagePreviewBuildsPolicyValue'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.9.101.1.2 (L1) Ensure 'Select when Preview Builds and Feature Updates are received' is set to 'Enabled: Semi-Annual Channel, 180 or more days'
       Registry 'DeferFeatureUpdates' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
          ValueName  = 'DeferFeatureUpdates'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.101.1.2 (L1) Ensure 'Select when Preview Builds and Feature Updates are received' is set to 'Enabled: Semi-Annual Channel, 180 or more days'
       Registry 'DeferFeatureUpdatesPeriodInDays' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
          ValueName  = 'DeferFeatureUpdatesPeriodInDays'
          ValueType  = 'DWord'
          ValueData  = '180'
       }

       #  18.9.101.1.2 (L1) Ensure 'Select when Preview Builds and Feature Updates are received' is set to 'Enabled: Semi-Annual Channel, 180 or more days'
       Registry 'BranchReadinessLevel' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
          ValueName  = 'BranchReadinessLevel'
          ValueType  = 'DWord'
          ValueData  = '32'
       }

       #  18.9.101.1.3 (L1) Ensure 'Select when Quality Updates are received' is set to 'Enabled: 0 days'
       Registry 'DeferQualityUpdates' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
          ValueName  = 'DeferQualityUpdates'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.101.1.3 (L1) Ensure 'Select when Quality Updates are received' is set to 'Enabled: 0 days'
       Registry 'DeferQualityUpdatesPeriodInDays' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
          ValueName  = 'DeferQualityUpdatesPeriodInDays'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.9.101.2 (L1) Ensure 'Configure Automatic Updates' is set to 'Enabled'
       Registry 'NoAutoUpdate' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
          ValueName  = 'NoAutoUpdate'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.101.3 (L1) Ensure 'Configure Automatic Updates: Scheduled install day' is set to '0 - Every day'
       Registry 'ScheduledInstallDay' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
          ValueName  = 'ScheduledInstallDay'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.9.101.4 (L1) Ensure 'No auto-restart with logged on users for scheduled automatic updates installations' is set to 'Disabled'
       Registry 'NoAutoRebootWithLoggedOnUsers' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
          ValueName  = 'NoAutoRebootWithLoggedOnUsers'
          ValueType  = 'DWord'
          ValueData  = '0'
       }


       # 19.1.3.1 (L1) Ensure 'Enable screen saver' is set to 'Enabled'
       Registry 'ScreenSaveActive' {
           Ensure      = 'Present'
           Key         = 'HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop'
           ValueName   = 'ScreenSaveActive'
           ValueType   = 'String'
           ValueData   = '1'
       }

       #  19.1.3.2 (L1) Ensure 'Force specific screen saver: Screen saver executable name' is set to 'Enabled: scrnsave.scr'
       Registry 'SCRNSAVE.EXE' {
          Ensure       = 'Present'
          Key          = 'HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop'
          ValueName    = 'SCRNSAVE.EXE'
          ValueType    = 'String'
         ValueData    = 'scrnsave.scr'
       }

       #  19.1.3.3 (L1) Ensure 'Password protect the screen saver' is set to 'Enabled'
       Registry 'ScreenSaverIsSecure' {
          Ensure       = 'Present'
          Key          = 'HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop'
          ValueName    = 'ScreenSaverIsSecure'
          ValueType    = 'String'
          ValueData    = '1'
       }

       #  19.1.3.4 (L1) Ensure 'Screen saver timeout' is set to 'Enabled: 900 seconds or fewer, but not 0'
       Registry 'ScreenSaveTimeOut' {
          Ensure       = 'Present'
          Key          = 'HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop'
          ValueName    = 'ScreenSaveTimeOut'
          ValueType    = 'DWord'
          ValueData    = '900'
       }

       #  19.5.1.1 (L1) Ensure 'Turn off toast notifications on the lock screen' is set to 'Enabled'
       Registry 'NoToastApplicationNotificationOnLockScreen' {
          Ensure       = 'Present'
          Key          = 'HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications'
          ValueName    = 'NoToastApplicationNotificationOnLockScreen'
          ValueType    = 'DWord'
          ValueData    = '1'
       }

       #  19.6.5.1.1 (L2) Ensure 'Turn off Help Experience Improvement Program' is set to 'Enabled'
       Registry 'NoImplicitFeedback' {
          Ensure       = 'Present'
          Key          = 'HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0'
          ValueName    = 'NoImplicitFeedback'
          ValueType    = 'DWord'
          ValueData    = '1'
       }

       #  19.7.4.1 (L1) Ensure 'Do not preserve zone information in file attachments' is set to 'Disabled'
       Registry 'SaveZoneInformation' {
          Ensure       = 'Present'
          Key          = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments'
          ValueName    = 'SaveZoneInformation'
          ValueType    = 'DWord'
          ValueData    = '2'
       }

       #  19.7.4.2 (L1) Ensure 'Notify antivirus programs when opening attachments' is set to 'Enabled'
       Registry 'ScanWithAntiVirus' {
          Ensure       = 'Present'
          Key          = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments'
          ValueName    = 'ScanWithAntiVirus'
          ValueType    = 'DWord'
          ValueData    = '3'
       }

       #  19.7.7.1 (L1) Ensure 'Configure Windows spotlight on lock screen' is set to Disabled'
       Registry 'ConfigureWindowsSpotlight' {
          Ensure       = 'Present'
          Key          = 'HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\CloudContent'
          ValueName    = 'ConfigureWindowsSpotlight'
          ValueType    = 'DWord'
          ValueData    = '2'
       }

       #  19.7.7.2 (L1) Ensure 'Do not suggest third-party content in Windows spotlight' is set to 'Enabled'
       Registry 'DisableThirdPartySuggestions' {
          Ensure       = 'Present'
          Key          = 'HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\CloudContent'
          ValueName    = 'DisableThirdPartySuggestions'
          ValueType    = 'DWord'
          ValueData    = '1'
       }

       #  19.7.7.3 (L2) Ensure 'Do not use diagnostic data for tailored experiences' is set to 'Enabled'
       Registry 'DisableTailoredExperiencesWithDiagnosticData' {
          Ensure       = 'Present'
          Key          = 'HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\CloudContent'
          ValueName    = 'DisableTailoredExperiencesWithDiagnosticData'
          ValueType    = 'DWord'
          ValueData    = '1'
       }

       #  19.7.7.4 (L2) Ensure 'Turn off all Windows spotlight features' is set to 'Enabled'
       Registry 'DisableWindowsSpotlightFeatures' {
          Ensure       = 'Present'
          Key          = 'HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\CloudContent'
          ValueName    = 'DisableWindowsSpotlightFeatures'
          ValueType    = 'DWord'
          ValueData    = '1'
       }

       #  19.7.26.1 (L1) Ensure 'Prevent users from sharing files within their profile.' is set to 'Enabled'
       Registry 'NoInplaceSharing' {
          Ensure       = 'Present'
          Key          = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
          ValueName    = 'NoInplaceSharing'
          ValueType    = 'DWord'
          ValueData    = '1'
       }

       #  19.7.40.1 (L1) Ensure 'Always install with elevated privileges' is set to 'Disabled'
       # WARNING! Duplicate: recommendation 18.9.85.2 => commented out
      #  Registry 'AlwaysInstallElevated2' {
      #     Ensure       = 'Present'
      #     Key          = 'HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Installer'
      #     ValueName    = 'AlwaysInstallElevated'
      #     ValueType    = 'DWord'
      #     ValueData    = '0'
      #  }

       #  19.7.44.2.1 (L2) Ensure 'Prevent Codec Download' is set to 'Enabled'
       Registry 'PreventCodecDownload' {
          Ensure       = 'Present'
          Key          = 'HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer'
          ValueName    = 'PreventCodecDownload'
          ValueType    = 'DWord'
          ValueData    = '1'
       }
   }
}

CIS_WindowsServer2016_v110
