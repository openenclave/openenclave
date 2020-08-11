# SGX1 with Flexible Launch Control (FLC) Prerequisites on Windows

## [Intel Platform Software for Windows (PSW) v2.8](http://registrationcenter-download.intel.com/akdlm/irc_nas/16766/Intel%20SGX%20PSW%20for%20Windows%20v2.8.100.2.exe)

The PSW only needs to be manually installed if you are running on Windows Server
2016 or a version of Windows client lower than 1709. It should be installed automatically
with Windows Update on newer versions of Windows client and Windows Server 2019.
You can check your version of Windows by running `winver` on the command line.
Ensure that you have the latest drivers on Windows 10 and Windows Server 2019 by checking for updates and installing all updates.

To install the PSW on Windows Server 2016 and Windows client < 1709, unpack the self-extracting
ZIP executable, and run the installer under `PSW_EXE_RS2_and_before`:

```cmd
"C:\Intel SGX PSW for Windows v2.8.100.2\PSW_EXE_RS2_and_before\Intel(R)_SGX_Windows_x64_PSW_2.8.100.2.exe"
```

If you would like to manually update the PSW on Windows Server 2019 or Windows
clients > 1709 without relying on Windows Update, you can update the PSW components
as follows:

1. Install `devcon.exe`, available as part of the [Windows Driver Kit for Windows 10](https://go.microsoft.com/fwlink/?linkid=2026156).
   -  Note that `devcon.exe` is usually installed to `C:\Program Files (x86)\Windows Kits\10\tools\x64`
   which is not in the `PATH` environment variable by default.

2. In an elevated command prompt, run the following command from the extracted PSW package under the `PSW_INF_RS3_and_above` folder:
  ```cmd
  devcon.exe update sgx_psw.inf "SWC\VEN_INT&DEV_0E0C"
  ```

You can verify that the correct version of Intel SGX PSW is installed by using
Windows Explorer to open `C:\Windows\System32`. You should be able to find
file `sgx_urts.dll` if PSW is installed. Right click on `sgx_urts.dll`,
choose `Properties` and then find `Product version` on the `Details` tab.
The version should be "2.8.xxx.xxx" or above.

## [Azure DCAP client for Windows](https://github.com/Microsoft/Azure-DCAP-Client/tree/master/src/Windows) [optional]

Note that this is optional since you can choose an alternate implementation of the DCAP client or create your own.
The Azure DCAP client for Windows is necessary if you would like to perform enclave attestation on a Azure Confidential Computing VM. It is available from [nuget.org](https://www.nuget.org/packages/Microsoft.Azure.DCAP/) and can be installed directly via command below.

```cmd
nuget.exe install Microsoft.Azure.DCAP -ExcludeVersion -Version 1.6.0 -OutputDirectory C:\oe_prereqs
```

This example assumes you would like to install the package to `C:\oe_prereqs`.

## [Intel Data Center Attestation Primitives (DCAP) Libraries v1.7](http://registrationcenter-download.intel.com/akdlm/irc_nas/16767/Intel%20SGX%20DCAP%20for%20Windows%20v1.7.100.2.exe)

After unpacking the self-extracting ZIP executable, you can refer to the *Intel SGX DCAP Windows SW Installation Guide.pdf*
for more details on how to install the contents of the package.

Note that Windows Server 2019 should have this package installed by default via Windows Update.
In that case, it is only necessary to set the registry key to allow the LC_driver to run.

The following summary will assume that the contents were extracted to `C:\Intel SGX DCAP for Windows v1.7.100.2`:

### Install the Intel DCAP driver

1. Allow the SGX Launch Configuration driver (LC_driver) to run:
    - From an elevated command prompt:

      ```cmd
      reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sgx_lc_msr\Parameters /v "SGX_Launch_Config_Optin" /t REG_DWORD /d 1
      reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sgx_lc_msr\Parameters /v "SGX_Launch_Config_Optin"
      ```

    - If the driver is already installed and running, the machine will need to be rebooted for the change to take effect.

2. Install or update the drivers:
    - Refer to the PSW section above for notes on acquiring and using `devcon.exe`.
    - Please note that the following commands will be ran from the `C:\Intel SGX DCAP for Windows v1.7.100.2` folder.
    - On Windows Server 2016, the drivers can be installed using:

      ```cmd
      devcon.exe install base\WindowsServer2016\sgx_base_dev.inf root\SgxLCDevice
      devcon.exe install dcap\WindowsServer2016\sgx_dcap_dev.inf root\SgxLCDevice_DCAP
      ```

    - On Windows Server 2019, the drivers can be manually updated using:

      ```cmd
      devcon.exe update base\WindowsServer2019_Windows10\sgx_base.inf *INT0E0C
      devcon.exe update dcap\WindowsServer2019_Windows10\sgx_dcap.inf "SWC\VEN_INT&DEV_0E0C_DCAP"
      ```