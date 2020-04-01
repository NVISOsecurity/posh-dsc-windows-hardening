# posh-dsc-windowsserver-hardening

This repository contains PowerShell DSC code for the secure configuration of Windows according to the following hardening guidelines:

- CIS Microsoft Windows 10 Enterprise Release 1909 Benchmark v1.8.1
- CIS Microsoft Windows Server 2019 Release 1809 benchmark v1.1.0
- CIS Microsoft Windows Server 2016 Release 1607 benchmark v1.1.0
- Azure Secure Center Baseline for Windows Server 2016
- Windows Event Log and Audit Policy Best Practices

Read more about it on our [NVISO Blog](https://blog.nviso.eu/2020/03/03/windows-server-hardening-with-powershell-dsc/) 

## CIS Microsoft Windows 10 Enterprise Release 1909 Benchmark v1.8.1

The file CIS_Windows10_v181.ps1 contains the Powershell DSC configuration applying the CIS Microsoft Windows 10 benchmark with the recommended controls.

The CIS benchmark is available on the following website:

[CIS Benchmarks - Center for Internet Security](https://www.cisecurity.org/cis-benchmarks/)

Please note the following exceptions:

* For control  5.39 (L2) Ensure 'Windows Remote Management (WS-Management) (WinRM)' is set to 'Disabled', modify to 2 for testing.

* For control  18.9.97.2.2 (L2) Ensure 'Allow remote server management through WinRM' is set to 'Disabled', modify to 1 for testing.

## CIS Microsoft Windows Server 2019 Release 1809 benchmark v1.1.0

The file CIS_WindowsServer2019_v110.ps1 contains the Powershell DSC configuration applying the CIS Microsoft Windows Server 2019 benchmark with the recommended controls.

The CIS benchmark is available on the following website:

[CIS Benchmarks - Center for Internet Security](https://www.cisecurity.org/cis-benchmarks/)

Please note the following exceptions:
* Some controls in chapter 2.2 (Local Policies: User Rights Assignment) are in comment due to duplicates.

* For control  18.9.97.2.2 (L2) Ensure 'Allow remote server management through WinRM' is set to 'Disabled', modify to 1 for testing.

* For control 19.7.41.1 (L1) Ensure 'Always install with elevated privileges' is set to 'Disabled', it is in comment because this is a duplicate of the control 18.9.85.2 (L1) Ensure 'Always install with elevated privileges' is set to 'Disabled'.

## CIS Microsoft Windows Server 2016 Release 1607 benchmark v1.1.0

The file CIS_WindowsServer2016_v110.ps1 contains the Powershell DSC configuration applying the CIS Microsoft Windows Server 2016 benchmark with the recommended controls.

The CIS benchmark is available on the following website:

[CIS Benchmarks - Center for Internet Security](https://www.cisecurity.org/cis-benchmarks/)

Please note the following exceptions:
* Some controls in chapter 2.2 (Local Policies: User Rights Assignment) are in comment due to duplicates.

* For control  18.9.97.2.2 (L2) Ensure 'Allow remote server management through WinRM' is set to 'Disabled', modify to 1 for testing.

* For control 19.7.40.1 (L1) Ensure 'Always install with elevated privileges' is set to 'Disabled', it is in comment because this is a duplicate of the recommendation control 18.9.85.2 (L1) Ensure 'Always install with elevated privileges' is set to 'Disabled'.

## Azure Security Center Baseline for Windows Server 2016

The file AzSC_CCEv4_WindowsServer2016.ps1 contains all controls in the Azure Security Center Baseline for Windows Server 2016.

Azure Security Center Baseline for Windows Server 2016 can be found here:

[TechNet Azure Security Center Common Configuration](https://gallery.technet.microsoft.com/Azure-Security-Center-a789e335)

## Windows Event Log and Audit Policy Best Practices

The file AuditPolicy_WindowsServer2016.ps1 contains the Powershell DSC code for applying Windows event logging and audit settings best practices.

These best practices are based on guidelines from Malware Archeology:

[Malware Archeology](https://www.malwarearchaeology.com/logging)

## Usage

To apply the CIS benchmark PowerShell DSC code, follow these steps in an elevated PowerShell prompt:

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

Increase the maximum envelope size, by running the following command

```
Set-Item -Path WSMan:\localhost\MaxEnvelopeSizeKb -Value 2048
```

Enable Windows Remote management:

```
winrm quickconfig
```

Run the following command to apply the PowerShell DSC configuration:

```
Start-DscConfiguration -Path .\CIS_WindowsServer2016_v110  -Force -Verbose -Wait
```

### OS Platforms

The relevant baselines have been tested on the following operating systems:

* Windows 10 Release 1909
* Windows Server 2016 Release 1607
* Windows Server 2019 Release 1809

## Disclaimer

This code is provided as is. Please test thoroughly before applying it to production systems.

## License

[GPL-3.0](LICENSE)
