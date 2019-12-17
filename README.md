# posh-dsc-win2016-secureconfig

This repository contains PowerShell DSC code for the secure configuration of Windows Server 2016 according to the following hardening guidelines:

- CIS Microsoft Windows Server 2016 benchmark v1.1.0
- Azure Secure Center Baseline for Windows Server 2016
- Malware Archeology Windows Logging Best Practices

## CIS Microsoft Windows Server 2016 benchmark v1.1.0

The CIS1.1.0_WindowsServer2016.ps1 file contains the Powershell DSC configuration applying the CIS Microsoft Windows Server 2016 benchmark with the recommended controls.

The CIS benchmark is available on the following website:

[CIS Benchmarks - Center for Internet Security](https://www.cisecurity.org/cis-benchmarks/)

Please note the following exceptions:
* For some recommended controls in chapter 2.2 (Local Policies: User Rights Assignment), it is not possible to configure some controls due to duplicates.

* For the recommended control  18.9.97.2.2 (L2) Ensure 'Allow remote server management through WinRM' is set to 'Disabled', modify to 1 for testing.

* For the recommended control 19.7.40.1 (L1) Ensure 'Always install with elevated privileges' is set to 'Disabled', it is commented out because this is a duplicate of the recommendation control 18.9.85.2 (L1) Ensure 'Always install with elevated privileges' is set to 'Disabled'.

## Azure Security Center Baseline for Windows Server 2016

The AzSC_CCEv4_WindowsServer2016.ps1 file contains all controls in the Azure Security Center Baseline for Windows Server 2016.

Azure Security Center Baseline for Windows Server 2016 can be found here:

[TechNet Azure Security Center Common Configuration](https://gallery.technet.microsoft.com/Azure-Security-Center-a789e335)

## Malware Archeology Windows Logging Best Practices

The AuditPolicy_WindowsServer2016.ps1 file contains the Powershell DSC code for applying the Malware Archeology Windows logging best practices.

The logging best practices can be found on the following website:

[Malware Archelogy](https://www.malwarearchaeology.com/logging)

## Usage

To apply the CIS benchmark PowerShell DSC code, follow these steps:

Install the required PowerShell DSC modules:

```
install-module AuditPolicyDSC
install-module ComputerManagementDsc
install-module SecurityPolicyDsc
```

Compile the CIS benchmark PowerShell DSC code:

```
./CIS_WindowsServer2016_v110.ps1
```

A MOF file will be created.

Run the following command to apply the PowerShell DSC configuration:

```
Start-DscConfiguration -Path .\CIS_WindowsServer2016_v110  -Force -Verbose -Wait
```

### OS Platforms

The code in this repository has been tested on the following operating systems:

* Windows Server 2016

## Disclaimer

This code is provided as is. Please test thoroughly before applying it to production systems.
