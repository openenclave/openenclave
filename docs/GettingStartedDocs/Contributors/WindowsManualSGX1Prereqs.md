# SGX1 Prerequisites on Windows

## Intel Platform Software for Windows (PSW)

Intel PSW only needs to be manually installed if you are running on version of Windows client lower than 1709. It should be installed automatically with Windows Update on newer versions of Windows client and Windows Server 2019. You can check your version of Windows by running `winver` on the command line.

Ensure that you have the latest drivers on Windows 10 and Windows Server 2019 by checking for updates and installing all updates.

### Manual installation for client versions lower than 1709
To manually install Intel SGX PSW on Windows for client versions lower than 1709:

1. Download Intel SGX PSW from [Windows Open Enclave SDK Prerequisites](WindowsPrerequisites.md). For this example we will use Intel SGX PSW for Windows v2.12.100.4, but your commands should substitute the version with the version downloaded.

2. Unpack the self-extracting ZIP executable, and run the installer under `PSW_EXE_RS2_and_before`:

```cmd
"C:\Intel SGX PSW for Windows v2.12.100.4\PSW_EXE_RS2_and_before\Intel(R)_SGX_Windows_x64_PSW_2.12.100.4.exe"
```

### Manual installation for client versions 1709 and above
If you would like to manually update Intel PSW on Windows Server 2019 or Windows clients >= 1709 without relying on Windows Update, you can update the PSW components as follows:

1. Download devcon from [Windows Open Enclave SDK Prerequisites](WindowsPrerequisites.md) and install. Alternatively it is available as part of the [Windows Driver Kit for Windows 10](https://go.microsoft.com/fwlink/?linkid=2026156).
   -  Note that `devcon.exe` is usually installed to `C:\Program Files (x86)\Windows Kits\10\tools\x64`
   which is not in the `PATH` environment variable by default.

2. Download the Intel SGX PSW from [Windows Open Enclave SDK Prerequisites](WindowsPrerequisites.md).

3. Unpack the self-extracting ZIP executable. In an elevated command prompt, run the following command from the extracted PSW package under the `PSW_INF_RS3_and_above` folder:
  ```cmd
  devcon.exe update sgx_psw.inf "SWC\VEN_INT&DEV_0E0C"
  ```

### Verifying PSW installation
You can verify that the correct version of Intel SGX PSW is installed by using
Windows Explorer to open `C:\Windows\System32`. You should be able to find
file `sgx_urts.dll` if PSW is installed. Right click on `sgx_urts.dll`,
choose `Properties` and then find `Product version` on the `Details` tab.
The version should be `2.12.xxx.xxx` or above.

To verify that Intel SGX PSW is running, use the following command:

```cmd
sc query aesmservice
```

The state of the service should be "running" (4). If there are any errors, follow `Intel SGX Installation Guide for Windows OS.pdf` for troubleshooting. The document can be located under the `Documentation` folder where the Intel SGX PSW ZIP content was extracted.

If the AESM Service is stopped for any reason, it can be started by using the following command from Powershell.
```powershell
Start-Service "AESMService"
```

To restart the AESM Service, use the following Powershell command:
```powershell
Restart-Service "AESMService"
```
