# SGX1 Prerequisites on Windows

## Intel SGX Platform Software for Windows (PSW) v2.4 or above

The latest PSW should be installed automatically on a Windows machine with Windows
version no lower than 1709. To check your Windows version, run `winver` on the
command line.

Windows Server 2016 image for an Azure Confidential Compute VM has a Windows version
lower than 1709, and therefore you need to install PSW v2.4 or above manually.
You can download [PSW v2.7](http://registrationcenter-download.intel.com/akdlm/irc_nas/16115/Intel%20SGX%20PSW%20for%20Windows%20v2.7.100.2.exe),
extract the zipped files, and run the executable under folder **PSW_EXE_RS2_and_before**
to install PSW 2.7.

You can verify that the correct version of Intel SGX PSW is installed by using
Windows Explorer to open `C:\Windows\System32`. You should be able to find
file `sgx_urts.dll` if PSW is installed. Right click on `sgx_urts.dll`,
choose `Properties` and then find `Product version` on the `Details` tab.
The version should be "2.7.xxx.xxx" or above.

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

Firstly we download the Intel SGX DCAP self-extracting executable from [here](http://registrationcenter-download.intel.com/akdlm/irc_nas/16014/Intel%20SGX%20DCAP%20for%20Windows%20v1.5.100.2.exe). Run the executable to unzip files to a specified location.
The following summary will assume that the contents were extracted to `C:\Intel SGX DCAP for Windows v1.5.100.2`:

Make sure you have [nuget cli tool](https://dist.nuget.org/win-x86-commandline/latest/nuget.exe) installed and in your path,
run the following command from a command prompt (assuming you would like the package to be installed to `C:\oe_prereqs`):
```cmd

nuget.exe install EnclaveCommonAPI -ExcludeVersion -Source "C:\Intel SGX DCAP for Windows v1.5.100.2\nuget" -OutputDirectory C:\path\to\where\you\would\like\to\install\intel_nuget_packages

```

You can verify that the library is installed properly by checking whether `sgx_enclave_common.lib` exists in the folder `C:\oe_prereqs`.
