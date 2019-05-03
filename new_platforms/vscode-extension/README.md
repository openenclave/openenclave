# Open Enclave extension for Visual Studio Code

A [Visual Studio Code](https://code.visualstudio.com/) [extension](https://marketplace.visualstudio.com/VSCode) supporting [Open Enclave](https://openenclave.io/sdk/), including development, debugging, emulators, and deployment!

For more information on the technology, [see here](https://github.com/Microsoft/openenclave/blob/feature.new_platforms/new_platforms/README.md).

## Getting started

Ensure that the [requirements](#Requirements) are met.

You can directly install the [Microsoft Open Enclave extension](https://marketplace.visualstudio.com/items?itemName=ms-iot.msiot-vscode-openenclave).

Alternatively, you can run the extension from this repository by following these instructions:

1. Clone this repository `git clone --recursive https://github.com/microsoft/openenclave --branch feature.new_platforms`.
1. Navigate to `new_platforms\vscode-extension` in the cloned folder.
1. Run npm to install the dependencies: `npm install` (see the [requirements](#Requirements) section for npm installation link).
1. Start VSCode: `code .`.
1. Start the extension using `F5`.

## Features

### Create a new Open Enclave solution.

You can use the `Microsoft Open Enclave: New Open Enclave Solution` command (commands can be found using **F1** or **CTRL-Shift-P**) 
to create a new Open Enclave solution.  

You will be prompted to:

1. Select a folder for your solution.  
1. On Linux, you will have the option to create a standalone project or an Azure IoT Edge container 
    project.  Otherwise, you will only have the option to create an Azure IoT Edge container project.
1. If you choose a container project, you will be prompted to provide your container repository.
1. You will be prompted to provide a name for your host/enclave.

A new solution will be created in the folder you've selected.  That solution will contain both the host
and enclave as well as the required EDL file.  If you've chosen to build a container, the host will include
some code that implements the required Azure IoT Hub communication.

### Build your Open Enclave solution.

There are build tasks for both standalone and Azure IoT Edge container projects.  The underlying system used 
to build is CMake.  

For a standalone project, there will be configure and build tasks for each target (ARMv7-A and AArch64/ARMv8-A).  The 
configure task will invoke CMake to create the required build files.  This is only required to be run once.  
The build task will do the actual compiling and linking.

1. **F1** or **CTRL-Shift-P**
1. Select `Tasks: Run Task`
1. Select `Configure for QEMU (ARMv7-A | AArch64/ARMv8-A)`
1. Select `Build for QEMU (ARMv7-A | AArch64/ARMv8-A)`

For an Azure IoT Edge container project, containers are used to configure and build.  The build task in a
container project will invoke docker and leverage project dockerfiles.  The container can be built by:

1. Right click on `modules/<solution-name>/module.json`
1. Select `Build IoT Edge Module Image`
1. Select desired architecture and configuration from picker

### Deploy your Open Enclave solution.

Deploying an Azure IoT Edge container project is fairly simple:

1. Select the desired platform:
    1. **F1** or **CTRL-Shift-P**
    1. Select `Azure IoT Edge: Set Default Target Platform for Edge Solution`
    1. Choose from `arm32v7` or `aarch64`
1. Right click on `modules/<solution-name>/module.json`
1. Select `Build and Push IoT Edge Module Image`
1. Select desired architecture and configuration from picker

Azure IoT Edge deployment template files have been provided.  To create
a new deployment configuration based on the current settings in `module.json`:

1. Right click on `deployment.template.json` (or `deployment.debug.template.json`)
1. Select `Generate IoT Edge Deployment Manifest`.  This will generate or replace the apppropriate deployment json file in the `config` folder.

Once your deployment json has been created in the `config` folder, you can deploy
to an Azure Edge device by:

1. Navigate to the `config` folder and right click on `deployment.*.json`
1. Select `Create Deployment for Single Device` or `Create Deployment at Scale`.

### Debug your Open Enclave solution.

Debugging your standalone project's enclave is easy.  

1. Set breakpoints in the files you wish to debug.  Breakpoints in the enclave may only be added before
the emulator (QEMU) starts or when the debugger is already broken inside the enclave.
1. Choose the architecture you are interested in debugging by navigating to the Visual 
Studio `Debug` view (**CTRL-Shift-D**) and selecting either `(gdb) Launch QEMU (ARMv7-A)` or 
`(gdb) Launch QEMU (AArch64/ARMv8-A)` from the debug configuration dropdown.
1. You can simply hit `F5`.  This will run cmake configuration, run the build, start QEMU, and load 
the host and enclave symbols into an instance of the debugger.
1. Open the **Terminal** view
1. Log into QEMU using `root` (no password is required)
1. Start the host process by entering `/mnt/host/bin/<solution-name>`

        Note: The debugger has been configured to break at TA_InvokeCommandEntryPoint.  This will happen once when the enclave starts and once for each ECALL.

## Requirements

* Install [Visual Studio Code](https://code.visualstudio.com/)
* Install required compilers

      sudo apt update && sudo apt install -y build-essential cmake gcc-arm-linux-gnueabihf gcc-aarch64-linux-gnu g++-arm-linux-gnueabihf g++-aarch64-linux-gnu gdb-multiarch

* Make sure that the [Native Debug extension](https://marketplace.visualstudio.com/items?itemName=webfreak.debug) is installed.
* Ensure that the requirements are met for the [Azure IoT Edge extension](https://marketplace.visualstudio.com/items?itemName=vsciot-vscode.azure-iot-edge):
    * Ensure that [Docker is installed and running: https://docs.docker.com/get-started/](https://docs.docker.com/get-started/).
    * Ensure that the [iotedgehubdev](https://pypi.org/project/iotedgehubdev/) tool is installed

          pip install --upgrade iotedgehubdev

    * Create a container repository, like [Azure Container Registry](https://azure.microsoft.com/en-us/services/container-registry/)
        * To push Edge containers to the container registry, find the username and password for your container registry and use them to log into docker: `docker login -u <username> -p <password> <container-url>`
    * Make sure that the [Azure Account extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode.azure-account) is installed and utilized:
        1. **F1** or **CTRL-Shift-P**
        1. `Azure: Sign In`
    * Make sure that the [Azure IoT Hub Toolkit](https://marketplace.visualstudio.com/items?itemName=vsciot-vscode.azure-iot-toolkit) extension is installed and utilized:
        1. **F1** or **CTRL-Shift-P**
        1. `Azure IoT Hub: Select IoT Hub`

### For development of this extension, or running from source code directly

* Install [node](https://nodejs.org/en/)
* Install [npm](https://www.npmjs.com/get-npm)

## Data/Telemetry

This project collects usage data and sends it to Microsoft to help improve our products and services.  Read our 
[privacy statement](http://go.microsoft.com/fwlink/?LinkId=521839) to learn more.  If you don't wish to send usage 
data to Microsoft, you can set the `telemetry.enableTelemetry` setting to `false`.  Learn more in the 
[Visual Studio Code FAQ](https://code.visualstudio.com/docs/supporting/faq#_how-to-disable-telemetry-reporting).

## Known Issues

* Building SGX enclaves is not currently supported.

## Release Notes

### 1.0.3

GA

### 1.0.1

Prototyping and developing :)

