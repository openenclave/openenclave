# Open Enclave extension for Visual Studio Code

A [Visual Studio Code](https://code.visualstudio.com/) [extension](https://marketplace.visualstudio.com/VSCode) supporting [Open Enclave](https://github.com/Microsoft/openenclave), including development, debugging, emulators, and deployment!

## Getting started

You can install the Open Enclave extension into Visual Studio Code directly via the Visual Studio Gallery [TBD](TBD).

Alternatively, you can run the extension from this repository by following these instructions:

1. Clone this repository `git clone --recursive https://github.com/microsoft/openenclave`
2. Navigate to `new_platforms\vscode-extension` in the cloned folder.
3. Run npm to install the dependencies: `npm install` (see Requirements section for npm installation link)
4. Start VSCode: `code .`
5. Start the extension using F5

## Features

### Create a new Open Enclave solution.

You can use the **Microsoft Open Enclave: New Open Enclave Solution** command (commands can be found using **CTRL-Shift-P**) 
to create a new Open Enclave solution.  

You will be prompted to:

1. Select a folder for your solution.  
1. On Linux, you will have the option to create a standalone project or an Azure IoT Edge container 
    project.  Otherwise, you will only have the option to create an Azure IoT Edge container project.
1. If you choose a container project, you will be prompted to provide your container repository.
1. You will be prompted to provide a name for your host/enclave.

A new solution will be created in the folder you've selected.  That solution will contain both the host
and enclave as well as the required edl.  If you've chosen to build a container, the host will include
some code that implements the required Azure IoT Hub communication.

### Build your Open Enclave solution.

There are build tasks for both standalone and Azure IoT Edge container projects.  The underlying system used 
to build is CMake.  

For a standalone project, there will be configure and build tasks for each target (arm32v7 and aarch64).  The 
configure task will invoke CMake to create the required build files.  This is only required to be run once.  
The build task will do the actual compiling and linking.

1. **CTRL-Shift-P**
1. Select `Tasks: Run Task`
1. Select `Configure for QEMU (ARM | AARCH64)`
1. Select `Build for QEMU (ARM | AARCH64)`

For an Azure IoT Edge container project, containers are used to configure and build.  The build task in a
container project will invoke docker and leverage project dockerfiles.  The container can be built by:

1. Right click on `modules/<solution-name>/module.json`
1. Select `Build IoT Edge Module Image`
1. Select desired architecture and configuration from picker

### Deploy your Open Enclave solution.

Deploying an Azure IoT Edge container project is fairly simple:

1. Select the desired platform:
    1. **CTRL-Shift-P**
    1. Select `Azure IoT Edge: Set Default Target Platform for Edge Solution`
    1. Choose from **arm32v7** or **aarch64**
1. Right click on `modules/<solution-name>/module.json`
1. Select `Build and Push IoT Edge Module Image`
1. Select desired architecture and configuration from picker

Azure IoT Edge deployment template files have been provided.  To create
a new deployment configuration based on the current settings in module.json:

1. Right click on `deployment.template.json` (or `deployment.debug.template.json`)
1. Select `Generate IoT Edge Deployment Manifest`.  This will generate or replace the apppropriate deployment json file in the `config` folder.

Once your deployment json has been created in the config folder, you can deploy
to an Azure Edge device by:

1. Right click on `deployment.*.json` (or `deployment.debug.*.json`)
1. Select `Create Deployment for Single Device` or `Create Deployment at Scale`.

## Requirements

Install [Visual Studio Code](https://code.visualstudio.com/)

Install [npm](https://www.npmjs.com/get-npm)

On Linux, for standalone projects:

* Run `sudo apt update && sudo apt install -y build-essential cmake gcc-arm-linux-gnueabi gcc-aarch64-linux-gnu g++-aarch64-linux-gnu`

For Azure IoT Edge projects:

* Ensure that [Docker is installed and running: https://docs.docker.com/get-started/](https://docs.docker.com/get-started/).
* Create a container repository, like [Azure Container Registry](https://azure.microsoft.com/en-us/services/container-registry/)

For better Azure integration:

* Make sure that the VS Code Azure Account extension is installed and utilized:
    1. CTRL-Shift-P
    1. Azure: Sign In

* Make sure that the VS Code Azure IoT Hub Toolkit extension is installed and utilized:
    1. CTRL-Shift-P
    1. Azure IoT Hub: Select IoT Hub

## Known Issues

* SGX is not currently supported

## Release Notes

### 1.0.1

Prototyping and developing :)

