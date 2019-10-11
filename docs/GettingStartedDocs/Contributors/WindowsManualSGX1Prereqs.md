# SGX1 Prerequisites on Windows

## Intel SGX Platform Software for Windows (PSW) v2.4 or above

The latest PSW should be installed automatically on a Windows machine with Windows
version no lower than 1709. To check your Windows version, run `winver` on the
command line.

Windows Server 2016 image for an Azure Confidential Compute VM has a Windows version
lower than 1709, therefore you need to install PSW v2.4 or above manually.
You can download [PSW v2.4](http://registrationcenter-download.intel.com/akdlm/irc_nas/15654/Intel%20SGX%20PSW%20for%20Windows%20v2.4.100.51291.exe),
extract the zipped files, and run the executable under folder **PSW_EXE_RS2_and_before**
to install PSW 2.4.

You can verify that the correct version of Intel SGX PSW is installed by using
Windows Explorer to open `C:\Windows\System32`. You should be able to find
file `sgx_urts.dll` if PSW is installed. Right click on `sgx_urts.dll`,
choose `Properties` and then find `Product version` on the `Details` tab.
The version should be "2.4.xxx.xxx" or above.

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

## Intel Enclave Common API library

The Intel Enclave Common API library is necessary for creating, initializing, and deleting enclaves.
It does not supporting quoting, and consequentially, attestation which is based on quoting. The lack
of quoting capability is a limitation of SGX1 machines which don't have FLC support.

Firstly we download Intel SGX and DCAP library from [here](http://registrationcenter-download.intel.com/akdlm/irc_nas/15650/Intel%20SGX%20DCAP%20for%20Windows%20v1.2.100.49925.exe). Run the executable to unzip files to a specified location.

Make sure you have [nuget cli tool](https://dist.nuget.org/win-x86-commandline/latest/nuget.exe) installed,
run the following command from a Windows prompt:
```cmd
nuget install EnclaveCommonAPI -Source C:\path\to\the\unzipped\sgx\and\dcap\files\nuget -OutputDirectory C:\path\to\where\you\would\like\to\install\intel_and_dcap_nuget_packages  -ExcludeVersion
```

You can verify that the library is installed properly by checking whether `sgx_enclave_coomon.lib` exists in the folder `C:\path\to\where\you\would\like\to\install\intel_and_dcap_nuget_packages\nuget\EnclaveCommonAPI\lib\native\x64-Release`.
