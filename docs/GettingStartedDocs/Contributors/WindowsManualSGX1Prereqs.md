# SGX1 Prerequisites on Windows

## [Intel Platform Software for Windows (PSW) v2.8](http://registrationcenter-download.intel.com/akdlm/irc_nas/16766/Intel%20SGX%20PSW%20for%20Windows%20v2.8.100.2.exe)

The PSW only needs to be manually installed if you are running on Windows Server
2016 or a version of Windows client lower than 1709. It should be installed automatically
with Windows Update on newer versions of Windows client and Windows Server 2019.
You can check your version of Windows by running `winver` on the command line.

To install the PSW on Windows Server 2016 and Windows client < 1709, unpack the self-extracting
ZIP executable, and run the installer under `PSW_EXE_RS2_and_before`:

```cmd
"C:\Intel SGX PSW for Windows v2.8.100.2\PSW_EXE_RS2_and_before\Intel(R)_SGX_Windows_x64_PSW_2.8.100.2.exe"
```

On Windows 10 and Windows Server 2019, you should ensure that you have the latest drivers
by checking for updates and installing all necessary updates.

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

To verify that Intel SGX PSW is running, use the following command:

```cmd
sc query aesmservice
```

The state of the service should be "running" (4). Follow Intel's documentation for
troubleshooting. In case the AESM service was stopped for some reasons, restart it
using the following command from Powershell.

```powershell
Start-Service "AESMService"
```

## [Intel Data Center Attestation Primitives (DCAP) Libraries v1.6](http://registrationcenter-download.intel.com/akdlm/irc_nas/16620/Intel%20SGX%20DCAP%20for%20Windows%20v1.6.100.2.exe)

While SGX1 machines without FLC support do not support DCAP quoting and attestation, the DCAP libraries package
contains the **Intel Enclave Common API library** as well. This library is necessary for creating, initializing, and deleting enclaves.

After unpacking the self-extracting ZIP executable, you will need to install the nuget package for the Enclave
Common API library if you want to build OE SDK on the target device. To do so, make sure you have the [nuget CLI tool](https://dist.nuget.org/win-x86-commandline/latest/nuget.exe) installed and its location in your `PATH`.

The following example will assume that the contents were extracted to `C:\Intel SGX DCAP for Windows v1.6.100.2`
and that `C:\oe_prereqs` is where you would like the prerequisites to be installed:

```cmd
nuget.exe install EnclaveCommonAPI -ExcludeVersion -Source "C:\Intel SGX DCAP for Windows v1.6.100.2\nuget" -OutputDirectory c:\oe_prereqs
```

You can verify that the library is installed properly by checking whether `sgx_enclave_common.lib` exists in the folder `C:\oe_prereqs`.
