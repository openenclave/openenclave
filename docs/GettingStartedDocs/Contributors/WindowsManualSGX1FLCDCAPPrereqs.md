# SGX1 with Flexible Launch Control (FLC) Prerequisites on Windows

## [Intel Platform Software for Windows (PSW) v2.4](http://registrationcenter-download.intel.com/akdlm/irc_nas/15654/Intel%20SGX%20PSW%20for%20Windows%20v2.4.100.51291.exe)

After unpacking the self-extracting ZIP executable, install the *PSW_EXE_RS2_and_before* version:
```cmd
C:\Intel SGX PSW for Windows v2.4.100.51291\PSW_EXE_RS2_and_before\Intel(R)_SGX_Windows_x64_PSW_2.4.100.51291.exe"
```

## [Azure DCAP client for Windows](https://github.com/Microsoft/Azure-DCAP-Client/tree/master/src/Windows) [optional]

Note that this is optional since you can choose an alternate implementation of the DCAP client or create your own.
The Azure DCAP client for Windows is necessary if you would like to perform enclave attestation on a Azure Confidential Computing VM. It is available from [nuget.org](https://www.nuget.org/packages/Azure.DCAP.Windows/) and can be installed directly via command below.
This example assumes that `C:\oe_prereqs` is where you would like the prerequisites to be installed.

```cmd
nuget.exe install Azure.DCAP.Windows -ExcludeVersion -Version 0.0.2 -OutputDirectory C:\oe_prereqs
```
This example assumes you would like to install the package to `C:\oe_prereqs`.

##### [Intel Data Center Attestation Primitives (DCAP) Libraries v1.2](http://registrationcenter-download.intel.com/akdlm/irc_nas/15650/Intel%20SGX%20DCAP%20for%20Windows%20v1.2.100.49925.exe)
After unpacking the self-extracting ZIP executable, you can refer to the *Intel SGX DCAP Windows SW Installation Guide.pdf*
for more details on how to install the contents of the package.

The following summary will assume that the contents were extracted to `C:\Intel SGX DCAP for Windows v1.2.100.49925`:

1. Unzip the required drivers from the extracted subfolders:
    - `LC_driver_WinServer2016\Signed_1152921504628095185.zip`
    - `DCAP_INF\WinServer2016\Signed_1152921504628099289.zip`

   The following instructions will assume that these have been unzipped into the `LC_driver` and `DCAP_INF` folders respectively.

2. Allow the SGX Launch Configuration driver (LC_driver) to run:
    - From an elevated command prompt:
      ```cmd
      reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sgx_lc_msr\Parameters /v "SGX_Launch_Config_Optin" /t REG_DWORD /d 1
      reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sgx_lc_msr\Parameters /v "SGX_Launch_Config_Optin"
      ```
    - If the driver is already installed and running, the machine will need to be rebooted for the change to take effect.

3. Install the drivers:
    - `devcon.exe` from the [Windows Driver Kit for Windows 10](https://go.microsoft.com/fwlink/?linkid=2026156)
      can be used to install the drivers from an elevated command prompt:
      ```cmd
      devcon.exe install LC_driver\drivers\b361e4d8-bc01-43fc-b8a6-8d101e659ed1\sgx_base_dev.inf root\SgxLCDevice
      devcon.exe install DCAP_INF\drivers\226fdf07-49d3-46aa-a0ce-f21b6d4a05cf\sgx_dcap_dev.inf root\SgxLCDevice_DCAP
      ```
    - Note that `devcon.exe` is usually installed to `C:\Program Files (x86)\Windows Kits\10\tools\x64` which is not in the PATH environment variable by default.
4. Install the DCAP nuget packages:
    - The standalone `nuget.exe` [CLI tool](https://dist.nuget.org/win-x86-commandline/latest/nuget.exe) can be used to do this from the command prompt:
      ```cmd
      nuget.exe install DCAP_Components -ExcludeVersion -Source "C:\Intel SGX DCAP for Windows v1.2.100.49925\nuget" -OutputDirectory c:\oe_prereqs
      nuget.exe install EnclaveCommonAPI -ExcludeVersion -Source "C:\Intel SGX DCAP for Windows v1.2.100.49925\nuget" -OutputDirectory c:\oe_prereqs
      ```
    - *Note:* EnclaveCommonAPI should be installed as the *very last* nuget package as a temporary workaround for a dependency issue. Please see issue #2170, for more details.