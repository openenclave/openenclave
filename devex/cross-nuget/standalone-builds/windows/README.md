# Standalone Windows Build

Assuming the path of an existing Open Enclave SDK repository is given (via the `-SDK_PATH` argument), the standalone build script allows the user to build from an existing Open Enclave SDK repository without having to re-clone the Open Enclave SDK repository. To execute the standalone Windows build script:

1. Install the Windows prerequisites, if the prerequisites are already installed in the system skip this step, and proceed to step 3. Execute the Windows prerequisites installation script in `openenclave/scripts/install-windows-prereqs.ps1`:
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
   .\install-windows-prereqs.ps1 -InstallPath C:/oe_prereqs -LaunchConfiguration SGX1FLC-NoIntelDrivers -DCAPClientType None
   ```
2. When prompted, reboot the system.
3. Run the standalone build script:
    ```
    vcvars64.bat && powershell -c "Set-ExecutionPolicy Bypass -Scope Process; .\build.ps1 -SDK_PATH <path to the OE SDK repository> -SDK_BUILD_PATH <path to the build folder>
    ```
    Note 1: If the `SDK_PATH` is not given, a new Open Enclave SDK repository will be cloned. To specify the branch that will be cloned, use the `SDK_TAG` argument.
    Note 2: If the build folder given does not exist, it will be created.

4. Run the standalone pack script:
    ```
    vcvars64.bat && powershell -c "Set-ExecutionPolicy Bypass -Scope Process; .\pack.ps1 -SDK_BUILD_PATH <path to the build folder> -SDK_PACK_PATH <path to the pack folder, shared with the Ubuntu bits>
    ```
