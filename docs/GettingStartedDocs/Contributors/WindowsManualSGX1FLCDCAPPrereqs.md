# SGX1 with Flexible Launch Control (FLC) Prerequisites on Windows

## [Intel Platform Software for Windows (PSW) v2.7](http://registrationcenter-download.intel.com/akdlm/irc_nas/16607/Intel%20SGX%20PSW%20for%20Windows%20v2.7.101.2.exe)

The PSW only needs to be manually installed if you are running on Windows Server
2016 or a version of Windows client lower than 1709. It should be installed automatically
with Windows Update on newer versions of Windows client and Windows Server 2019.
You can check your version of Windows by running `winver` on the command line.
Ensure that you have the latest drivers on Windows 10 and Windows Server 2019 by checking for updates and installing all updates.

To install the PSW on Windows Server 2016 and Windows client < 1709, unpack the self-extracting
ZIP executable, and run the installer under `PSW_EXE_RS2_and_before`:

```cmd
"C:\Intel SGX PSW for Windows v2.7.101.2\PSW_EXE_RS2_and_before\Intel(R)_SGX_Windows_x64_PSW_2.7.101.2.exe"
```

If you would like to manually update the PSW on Windows Server 2019 or Windows
clients > 1709 without relying on Windows Update, you can do
so as follows:

1. From the extracted PSW package, unzip the `PSW_INF_RS3_and_above\component\Signed_*.zip` file.

   The following instructions will assume that it was unzipped to the `PSW_INF` folder.

2. Install the PSW components:
    - `devcon.exe` from the [Windows Driver Kit for Windows 10](
      https://go.microsoft.com/fwlink/?linkid=2026156) can be used to update
      the drivers from an elevated command prompt:

    - Note that `devcon.exe` is usually installed to `C:\Program Files (x86)\Windows Kits\10\tools\x64`
      which is not in the `PATH` environment variable by default.

    - The hash values in the path may be different from the example command, please update as needed.

    ```cmd
    devcon.exe update PSW_INF\drivers\48e7c1e9-6de8-46ee-8ff9-46aa7b7ee5b9\sgx_psw.inf "SWC\VEN_INT&DEV_0E0C"
    ```

You can verify that the correct version of Intel SGX PSW is installed by using
Windows Explorer to open `C:\Windows\System32`. You should be able to find
file `sgx_urts.dll` if PSW is installed. Right click on `sgx_urts.dll`,
choose `Properties` and then find `Product version` on the `Details` tab.
The version should be "2.7.xxx.xxx" or above.

## [Azure DCAP client for Windows](https://github.com/Microsoft/Azure-DCAP-Client/tree/master/src/Windows) [optional]

Note that this is optional since you can choose an alternate implementation of the DCAP client or create your own.
The Azure DCAP client for Windows is necessary if you would like to perform enclave attestation on a Azure Confidential Computing VM. It is available from [nuget.org](https://www.nuget.org/packages/Microsoft.Azure.DCAP/) and can be installed directly via command below.

```cmd
nuget.exe install Microsoft.Azure.DCAP -ExcludeVersion -Version 1.4.2 -OutputDirectory C:\oe_prereqs
```

This example assumes you would like to install the package to `C:\oe_prereqs`.

## [Intel Data Center Attestation Primitives (DCAP) Libraries v1.6](http://registrationcenter-download.intel.com/akdlm/irc_nas/16620/Intel%20SGX%20DCAP%20for%20Windows%20v1.6.100.2.exe)

After unpacking the self-extracting ZIP executable, you can refer to the *Intel SGX DCAP Windows SW Installation Guide.pdf*
for more details on how to install the contents of the package.

Note that Windows Server 2019 should have this package installed by default via Windows Update.
In that case, it is only necessary to set the registry key to allow the LC_driver to run, and install the
DCAP nuget packages if you want to build the OE SDK.

The following summary will assume that the contents were extracted to `C:\Intel SGX DCAP for Windows v1.6.100.2`:

### Install the Intel DCAP nuget packages

The standalone `nuget.exe` [CLI tool](https://dist.nuget.org/win-x86-commandline/latest/nuget.exe) can be used to do this from the command prompt:

```cmd
nuget.exe install DCAP_Components -ExcludeVersion -Source "C:\Intel SGX DCAP for Windows v1.6.100.2\nuget" -OutputDirectory c:\oe_prereqs
nuget.exe install EnclaveCommonAPI -ExcludeVersion -Source "C:\Intel SGX DCAP for Windows v1.6.100.2\nuget" -OutputDirectory c:\oe_prereqs
```

### Install the Intel DCAP driver

1. Unzip the required drivers from the extracted subfolders:
    - For Windows Server 2016:
      - `LC_driver_WinServer2016\Signed_*.zip`
      - `DCAP_INF\WinServer2016\Signed_*.zip`
    - For Windows Server 2019, only if you want to perform a manual update without Windows Update:
      - `LC_driver_WinServer2019\Signed_*.zip`
      - `DCAP_INF\WinServer2019\Signed_*.zip`

   The following instructions will assume that these have been unzipped into the `LC_driver` and `DCAP_INF` folders respectively.

2. Allow the SGX Launch Configuration driver (LC_driver) to run:
    - From an elevated command prompt:

      ```cmd
      reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sgx_lc_msr\Parameters /v "SGX_Launch_Config_Optin" /t REG_DWORD /d 1
      reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sgx_lc_msr\Parameters /v "SGX_Launch_Config_Optin"
      ```

    - If the driver is already installed and running, the machine will need to be rebooted for the change to take effect.

3. Install or update the drivers:
    - Refer to the PSW section above for notes on acquiring and using `devcon.exe`.
    - The hash values in the paths may be different from the example commands, please update them as needed.
    - On Windows Server 2016, the drivers can be installed using:

      ```cmd
      devcon.exe install LC_driver\drivers\8e78fd6b-efeb-4952-ab0d-945e61c164ba\sgx_base_dev.inf root\SgxLCDevice
      devcon.exe install DCAP_INF\drivers\08cc8440-9f38-4635-9685-cdbf476666fa\sgx_dcap_dev.inf root\SgxLCDevice_DCAP
      ```

    - On Windows Server 2019, the drivers can be manually updated using:

      ```cmd
      devcon.exe update LC_driver\drivers\da362676-240a-4ec6-98cf-4cc4430c84be\sgx_base.inf *INT0E0C
      devcon.exe update DCAP_INF\drivers\4f1f1691-c4b8-422c-9ca9-d22ebee726cc\sgx_dcap.inf "SWC\VEN_INT&DEV_0E0C_DCAP"
      ```

4. Install the DCAP nuget packages:
    - The standalone `nuget.exe` [CLI tool](https://dist.nuget.org/win-x86-commandline/latest/nuget.exe) can be used to do this from the command prompt:

      ```cmd
      nuget.exe install DCAP_Components -ExcludeVersion -Source "C:\Intel SGX DCAP for Windows v1.6.100.2\nuget" -OutputDirectory c:\oe_prereqs
      nuget.exe install EnclaveCommonAPI -ExcludeVersion -Source "C:\Intel SGX DCAP for Windows v1.6.100.2\nuget" -OutputDirectory c:\oe_prereqs
      ```
