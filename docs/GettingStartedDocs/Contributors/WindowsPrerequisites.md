# Windows Open Enclave SDK Prerequisites
- [Git for Windows](https://github.com/git-for-windows/git/releases/)
- [OpenSSL 1.1.1](https://openenclavepublicstorage.blob.core.windows.net/openenclavedependencies/openssl.1.1.1579.74.nupkg)
- [Visual Studio Build Tools](https://aka.ms/vs/16/release/vs_buildtools.exe)
- [Clang 11.1.0](https://github.com/llvm/llvm-project/releases/download/llvmorg-11.1.0/LLVM-11.1.0-win64.exe)
- [ShellCheck v0.7.0](https://openenclavepublicstorage.blob.core.windows.net/openenclavedependencies/shellcheck-v0.7.0.zip)
- [Nuget 3.4.3](https://www.nuget.org/api/v2/package/NuGet.exe/3.4.3)
- [Python 3](https://www.python.org/downloads/windows/)
- [Python pip](https://pip.pypa.io/en/stable/installation/)
- [Intel SGX PSW 2.22.100.2](https://registrationcenter-download.intel.com/akdlm/IRC_NAS/f9a43559-9da1-4cb6-840e-9fc670b11a5a/Intel_SGX_DCAP_for_Windows_v1.20.100.2.zip) (note: this is bundled with Intel SGX DCAP)


## Additional Windows Open Enclave SDK Prerequisites for SGX1 with Flexible Launch Control (FLC)
- [Devcon](https://download.microsoft.com/download/7/D/D/7DD48DE6-8BDA-47C0-854A-539A800FAA90/wdk/Installers/787bee96dbd26371076b37b13c405890.cab)
- [Intel SGX DCAP v1.20.100.2](https://registrationcenter-download.intel.com/akdlm/IRC_NAS/f9a43559-9da1-4cb6-840e-9fc670b11a5a/Intel_SGX_DCAP_for_Windows_v1.20.100.2.zip)
- [Azure DCAP 1.10.0](https://www.nuget.org/api/v2/package/Microsoft.Azure.DCAP/1.10.0)

Note: while this list is maintained with best effort, the links here may be outdated. If you encounter a broken link or an outdated version, see the latest used by Open Enclave SDK install scripts here: [install-windows-prereqs.ps1](../../../scripts/install-windows-prereqs.ps1). Use of this script to set up prerequisites is encouraged as well.
