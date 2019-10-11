# Building And Debugging Using Visual Studio Code

This document provides a brief overview of how to build and debug Open Enclave applications using VS Code.

## Install VS Code

The latest version of Visual Studio Code can be installed from [https://code.visualstudio.com/](https://code.visualstudio.com/)


## Install VS Code Extensions

Install the following VS Code extensions. Click on an image to navigate to the Visual Studio Code Marketplace page for the extension.

[![C/C++ Extension](images/VSCodeCppExtension.png)](https://marketplace.visualstudio.com/items?itemName=ms-vscode.cpptools)

[![CMake Tools Extension](images/VSCodeCMakeToolsExtension.png)](https://marketplace.visualstudio.com/items?itemName=vector-of-bool.cmake-tools)

[![CDB Extension](images/VSCodeCDBExtension.png)](https://marketplace.visualstudio.com/items?itemName=MicrosoftDebuggingPlatform.vscode-cdb)

## Launch Visual Studio Code
Open an instance of x64 Native Tools Command Prompt. This ensures that cmake is available in the path.

![x64 Native Tools Command Prompt](images/VSCodeNativeToolsPrompt.png)

Change to the directory containing your Open Enclave Application and launch VS Code in the current folder.

```cmd
cd YourApplicationFolder
code .
```

![Launch VS Code](images/VSCodeLaunch.png)

## Configure Your Workspace

Open Workspace Settings by pressing Ctrl+Shift+P and typing "Open Workspace Settings" in the command palette.

![Open Workspace Settings](images/VSCodeOpenWorkspaceSettings.png)

Search for the setting "CMake Configure Args" and add an item `-DNUGET_PACKAGE_PATH=path-to-openenclave-nuget-packages\prereqs\nuget`.
Add another item `-DOpenEnclave_DIR=YourOpenEnclaveInstallFolder\lib\openenclave\cmake`


![CMake Configure Args](images/VSCodeCMakeConfigureArgs.png)

Configure your workspace by typing "cmake configure" in the command palette

![CMake Configure](images/VSCodeCMakeConfigure.png)

Configuration should successfully complete.

![CMake Configure Output](images/VSCodeCMakeConfigureOutput.png)

## Build And Run Your Open Enclave Application

Build the application by pressing Shift+F7 or typing "CMake Build a target" in the command palette, and selecting the "all META" target.

![Build](images/VSCodeBuild.png)

Run your application by pressing Shift+F7 or typing "CMake Build a target" in the command palette, and selecting the "run UTILITY" target.

![Run](images/VSCodeRun.png)

## Configuring Intellisense

Intellisense should work out of the box for files within your workspace. However, Intellisense may not be aware of where to locate the Open Enclave SDK headers.
Open settings.json (or create one) under the .vscode folder and add entries for "C_Cpp.default.includePath" and "C_Cpp.default.systemIncludePath".

```json
{
    "cmake.configureArgs": [
        "-DNUGET_PACKAGE_PATH=C:\\OpenEnclaveNugetPackages"
    ],
    "C_Cpp.default.includePath": ["your-openenclave-sdk-install-path\\include"],
    "C_Cpp.default.systemIncludePath": [
        "your-openenclave-sdk-install-path\\include\\openenclave\\3rdparty\\libc",
        "your-openenclave-sdk-install-path\\include\\openenclave\\3rdparty\\libcxx"
    ]
}
```

## Debug Your Open Enclave Application

Add a CDB Debug Configuration as shown below.

![CDB Debug Configuration](images/VSCodeDebugConfiguration.png)

Fill in program path, parameters and other values in the configuration.

![Edit CDB Debug Configuration](images/VSCodeEditDebugConfiguration.png)

Open host.c and add a breakpoint. Start debugging.

![Host Breakpoint](images/VSCodeHostBreakpoint.png)

Step over the line that creates the enclave. The Console pane should show that the enclave has been loaded.

![Stop After Enclave Creation](images/VSCodeStopAfterEnclaveCreation.png)

Note: CDB commands can be executed in the Console Prompt.

![Debug Console](images/VSCodeDebugConsole.png)

Open enc.c and put a breakpoint and continue execution.

![Enclave Breakpoint](images/VSCodeEnclaveBreakpoint.png)


## Known Issues

The VS Code Debugger extension is currently released as an early preview.
These issues are being worked on and will be fixed in an upcoming update.

- Breakpoints aren't yet completely persisted and restored correctly.
Therefore it is recommended that you clear all breakpoints and set them again every time the program is launched for debugging.
- Debugging session is not terminated when the program runs to completion.
Therefore it is recommended that you stop and start a new debugging session each time.
- The debug cursor often jumps to the start of the file while debugging within an enclave.
Stepping again should take the cursor to the correct location.
