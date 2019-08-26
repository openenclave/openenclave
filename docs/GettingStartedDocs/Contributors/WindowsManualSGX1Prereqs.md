# SGX1 Prerequisites on Windows

## Intel SGX Platform Software for Windows (PSW) v2.2

The PSW should be installed automatically on Windows 10 version 1709 or newer, or on a Windows Server 2016 image for an Azure ConfidentialCompute VM. You can verify that is the case on the command line as follows:

```cmd
sc query aesmservice
```

The state of the service should be "running" (4). Follow Intel's documentation for troubleshooting.

If you have a Windows Server 2016 image that does not have Intel PSW 2.2, please get the PSW 2.2 [zipped executable](https://oejenkins.blob.core.windows.net/oejenkins/intel_sgx_win_2.2.100.47975_PV.zip).

After downloading  and extracting the zipped executable, run the executable to install PSW 2.2.

```cmd
C:\Intel SGX PSW for Windows v2.2.100.48339.exe\PSW_EXE_RS2_and_before\Intel(R)Intel(R)_SGX_Windows_x64_PSW_2.2.100.48339.exe
```

Start the AESM service by running the following command from Powershell.

```powershell
Start-Service "AESMService"
```