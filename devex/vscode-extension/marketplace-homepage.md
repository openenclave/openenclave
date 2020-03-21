# Open Enclave extension for Visual Studio Code

A
[Visual Studio Code](https://code.visualstudio.com/)
[extension](https://marketplace.visualstudio.com/VSCode)
supporting the
[Open Enclave SDK](https://openenclave.io/sdk/),
including development, debugging, emulators, and deployment!

For more information on the technology, see the
[SDK's documentation](https://github.com/openenclave/openenclave).

Currently, this extension supports the following combinations of project types,
and operating system and trusted execution environments:

1. Linux Development Machine:
   1. Standalone Project Targets:
      1. Linux Host with Intel SGX Enclave
      1. Linux Host with OP-TEE on ARM TrustZone Enclave
         1. [Scalys Grapeboard](https://www.grapeboard.com/)
         1. Emulated QEMU ARMv8
   1. Azure IoT Edge Project Targets:
      1. Linux Host with OP-TEE on ARM TrustZone Enclave
         1. [Scalys Grapeboard](https://www.grapeboard.com/)
         1. Emulated QEMU ARMv8
1. Windows Development Machine
   1. Azure IoT Edge Project Targets:
      1. Linux Host with OP-TEE on ARM TrustZone Enclave
         1. [Scalys Grapeboard](https://www.grapeboard.com/)
         1. Emulated QEMU ARMv8

## Getting started

Ensure that the [requirements](#Requirements) are met.

If you are reading this document on GitHub, install the
[Open Enclave extension](https://marketplace.visualstudio.com/items?itemName=ms-iot.msiot-vscode-openenclave)
from the Visual Studio Code marketplace.

To deploy hosts and enclaves to a Scalys Grapeboard regardless of the type of
project (Standalone or Azure IoT Edge) that you choose, follow the
[Getting Started with Open Enclave for the Scalys TrustBox](https://github.com/openenclave/openenclave/blob/master/docs/GettingStartedDocs/OP-TEE/Hardware/ScalysTrustBox.md)
guide to set up your board.

## Create a new Open Enclave solution

You can use the `Open Enclave: New Open Enclave Solution` command (commands can
be found using **F1** or **CTRL-Shift-P**) to create a new Open Enclave
solution.

You will be prompted to:

1. Select a folder for your solution.
1. On Linux, you will have the option to create a
    [Standalone](#Standalone%20projects) project or an [Azure IoT Edge
    Module](#Azure%20IoT%20Edge%20projects) project.  Otherwise, you will only
    have the option to create an [Azure IoT Edge
    Module](#Azure%20IoT%20Edge%20projects) project.
1. If you choose an Azure IoT Edge Module project, you will be prompted to
   provide your container repository.
1. You will be prompted to provide a name for your host/enclave.

A new solution will be created in the folder you've selected.  That solution
will contain both the host and enclave as well as the required EDL file.  If
you've chosen to build an Azure IoT Edge Module, the host will include some code
that implements the required Azure IoT Hub communication.

**Note:** On Windows, you can use the [Windows Subsystem for
Linux](https://docs.microsoft.com/en-us/windows/wsl/install-win10) and the
Visual Studio Code [Remote Development
extension](https://code.visualstudio.com/docs/remote/remote-overview) to utilize
[Standalone](#Standalone%20projects) projects on a Windows desktop.  In this
case, you will need to install the [requirements](#Requirements) in the
subsystem.

## Standalone projects

### Build your Open Enclave solution

The underlying system used to build is CMake.

There will be configure and build tasks for each target (Intel SGX,
AArch64/ARMv8-A, and LS1012).  The configure task will invoke CMake to create
the required build files. The build task will do the actual compiling and
linking.

1. **F1** or **CTRL-Shift-P**
1. Select `Tasks: Run Task`
1. Select `Build for QEMU (Intel SGX | AArch64/ARMv8-A | LS1012)`

### Debug your Open Enclave solution

Debugging your standalone project's enclave is easy.  Please ensure that all of
the [QEMU dependencies](#Requirements) are installed in your development
environment.

1. Set breakpoints in the files you wish to debug:
   1. When debugging enclaves for OP-TEE on ARM TrustZone with QEMU, breakpoints
      in the enclave may only be added before the emulator (QEMU) starts or when
      the debugger is already broken inside the enclave.
1. Choose the architecture you are interested in debugging by navigating to the
   Visual Studio Code `Debug` view (**CTRL-Shift-D**) and selecting either
   `(gdb) Launch Intel SGX (Hardware)`,
   `(gdb) Launch Intel SGX (Simulation)`, or
   `(gdb) Launch QEMU (AArch64/ARMv8-A)`
   from the debug configuration dropdown.
1. You can simply hit `F5`.  This will run CMake configuration, run the build,
   start QEMU if necessary, and load the host and enclave symbols into an
   instance of the debugger.
1. If debugging using QEMU:
   1. Open the **Terminal** view
   1. Log into QEMU using `root` (no password is required)
   1. Start the host process by entering `/mnt/host/bin/<solution-name> <TA UUID>`
   1. The debugger has been configured to break at `ecall_handle_message`.

## Azure IoT Edge projects

### Build your Open Enclave solution

Ubuntu containers are used to configure and build.  The build task will invoke
Docker and leverage project dockerfiles.  To build the Azure IoT Edge Module:

1. Right click on `modules/<solution-name>/module.json`
1. Select `Build IoT Edge Module Image`
1. Select `ls1012` or `aarch64-qemu` from the Platform picker

### Deploy your Open Enclave solution

Deploying your Azure IoT Edge Module project is fairly simple:

1. Right click on `modules/<solution-name>/module.json`
1. Select `Build and Push IoT Edge Module Image`
1. Select `ls1012` or `aarch64-qemu` from the Platform picker

Azure IoT Edge deployment template files have been provided.  To create a new
deployment configuration based on the current settings in `module.json`:

1. Select the desired platform:
    1. **F1** or **CTRL-Shift-P**
    1. Select `Azure IoT Edge: Set Default Target Platform for Edge Solution`
    1. Choose from `ls1012` or `aarch64-qemu`
1. Right click on `deployment.template.json` (or
   `deployment.debug.template.json`)
1. Select `Generate IoT Edge Deployment Manifest`.  This will generate or
   replace the appropriate deployment JSON file in the `config` folder.

Once your deployment JSON has been created in the `config` folder, you can
deploy to an Azure Edge device by:

1. Navigating to the `config` folder
1. Right clicking on `deployment.*.json`
1. Selecting `Create Deployment for Single Device` or `Create Deployment at
   Scale`.

To set up an actual device to receive a deployment, you can follow
[these](./SetUpDevice.md) instructions.

## Check your system for Open Enclave requirements

You can use the `Open Enclave: Check System Requirements` command (commands can
be found using **F1** or **CTRL-Shift-P**) to validate your system.

The command will query whether the
[required tools and the required versions](#Requirements)
are present on your system.  Any unmet requirements will be presented in a
Visual Studio Code warning window.

**Note:** as long as unmet requirements are found, this requirements check will
run whenever the extension is activated automatically.

## Requirements

This section describes the system requirements depending on which operating
system you run the extension on.

### All OSes

* Install [Visual Studio Code](https://code.visualstudio.com/)
* Install [git](https://git-scm.com/downloads)

* Create a container repository, like
  [Azure Container Registry](https://azure.microsoft.com/en-us/services/container-registry/)
  * To push Edge containers to the container registry, find the username
    and password for your container registry and use them to log into
    docker (the --pasword-stdin option will prevent your password from
    appearing in the command line history):
    `docker login --password-stdin -u <username> <container-url>`
  * Once you've logged into docker, you can log out (ane remove your
    credentials from the system) by: `docker logout <container-url>`
  * Make sure that the
    [Azure Account extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode.azure-account)
    is installed and configured:
    1. **F1** or **CTRL-Shift-P**
    1. `Azure: Sign In`
  * Make sure that the
    [Azure IoT Hub Toolkit](https://marketplace.visualstudio.com/items?itemName=vsciot-vscode.azure-iot-toolkit)
    extension is installed and utilized:
    1. **F1** or **CTRL-Shift-P**
    1. `Azure IoT Hub: Select IoT Hub`

### Linux

* Install the
  [C/C++](https://marketplace.visualstudio.com/items?itemName=ms-vscode.cpptools)
  extension.

* Install the
  [Native Debug extension](https://marketplace.visualstudio.com/items?itemName=webfreak.debug)
  extension.

* Install [CMake 3.12 or higher](https://cmake.org/download/). On Ubuntu 18.04:
  ```bash
  # Remove CMake if already installed.
  sudo apt remove cmake --purge

  # Download the CMake tarball for Linux.
  wget https://cmake.org/files/v3.13/cmake-3.13.1-Linux-x86_64.tar.gz

  # Extract it.
  sudo tar xf cmake-3.13.1-Linux-x86_64.tar.gz -C /usr/local

  # Install CMake and its tools to the right directories.
  sudo ln -s /usr/local/cmake-3.13.1-Linux-x86_64/bin/ccmake /usr/local/bin/ccmake
  sudo ln -s /usr/local/cmake-3.13.1-Linux-x86_64/bin/cmake /usr/local/bin/cmake
  sudo ln -s /usr/local/cmake-3.13.1-Linux-x86_64/bin/cpack /usr/local/bin/cpack
  sudo ln -s /usr/local/cmake-3.13.1-Linux-x86_64/bin/ctest /usr/local/bin/ctest
  ```

* Install the required build components. On Ubuntu 18.04:
  ```bash
  # Flag all current directories as AMD64-only.
  sudo sed -i 's/^deb h/deb [arch=amd64,i386] h/g' /etc/apt/sources.list

  # Enable the ARM64 architecture.
  sudo dpkg --add-architecture arm64

  # Add the Intel SGX repository and key.
  echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list
  wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add -

  # Add the LLVM repository and key.
  echo "deb [arch=amd64] http://apt.llvm.org/bionic/ llvm-toolchain-bionic-7 main" | sudo tee /etc/apt/sources.list.d/llvm-toolchain-bionic-7.list
  wget -qO - https://apt.llvm.org/llvm-snapshot.gpg.key | sudo apt-key add -

  # Add the Microsoft repository and key.
  echo "deb [arch=amd64] https://packages.microsoft.com/ubuntu/18.04/prod bionic main" | sudo tee /etc/apt/sources.list.d/msprod.list
  wget -qO - https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -

  # Add the Ubuntu ARM64 ports repository.
  echo 'deb [arch=arm64] http://ports.ubuntu.com/ubuntu-ports bionic main restricted universe multiverse' | sudo tee -a /etc/apt/sources.list
  echo 'deb [arch=arm64] http://ports.ubuntu.com/ubuntu-ports bionic-updates main restricted universe multiverse' | sudo tee -a /etc/apt/sources.list
  echo 'deb [arch=arm64] http://ports.ubuntu.com/ubuntu-ports bionic-backports main restricted universe multiverse' | sudo tee -a /etc/apt/sources.list

  # Update the repositories.
  sudo apt update

  # Install all prerequisites.
  sudo apt install -y apt-transport-https az-dcap-client binfmt-support      \
    build-essential clang-7 docker.io g++-aarch64-linux-gnu                  \
    gcc-aarch64-linux-gnu gdb gdb-multiarch libc6 libc6-dev:arm64 libfdt1    \
    libglib2.0-0 libpcre3 libpixman-1-0 libprotobuf10 libsgx-dcap-ql         \
    libsgx-dcap-ql-dev libsgx-enclave-common libsgx-enclave-common-dev       \
    libssl-dev libssl-dev:arm64 libstdc++6 open-enclave python python-crypto \
    python-pip qemu-user-static zlib1g
  ```

* [Determine the level of SGX support of your hardware](https://github.com/openenclave/openenclave/blob/master/docs/GettingStartedDocs/Contributors/building_oe_sdk.md#1-determine-the-sgx-support-level-on-your-developmenttarget-system).

* If you have Intel SGX-capable hardware without Flexible Launch Control (FLC),
  install the Legacy SGX driver:

  On Ubuntu 16.04, run:
  ```bash
  sudo apt update
  wget https://download.01.org/intel-sgx/sgx-linux/2.8/distro/ubuntu16.04-server/sgx_linux_x64_driver_2.6.0_51c4821.bin
  chmod +x sgx_linux_x64_driver_2.6.0_51c4821.bin
  sudo ./sgx_linux_x64_driver_2.6.0_51c4821.bin
  ```

  On Ubuntu 18.04, run:
  ```bash
  sudo apt update
  wget https://download.01.org/intel-sgx/sgx-linux/2.8/distro/ubuntu18.04-server/sgx_linux_x64_driver_2.6.0_51c4821.bin
  chmod +x sgx_linux_x64_driver_2.6.0_51c4821.bin
  sudo ./sgx_linux_x64_driver_2.6.0_51c4821.bin
  ```

* If you have Intel SGX-capable hardware with FLC support, install the Intel SGX
  DCAP driver:

  On Ubuntu 16.04, run:
  ```bash
  sudo apt update
  sudo apt -y install dkms
  wget https://download.01.org/intel-sgx/sgx-dcap/1.4/linux/distro/ubuntuServer16.04/sgx_linux_x64_driver_1.21.bin -O sgx_linux_x64_driver.bin
  chmod +x sgx_linux_x64_driver.bin
  sudo ./sgx_linux_x64_driver.bin
  ```

  On Ubuntu 18.04, run:
  ```bash
  sudo apt update
  sudo apt -y install dkms
  wget https://download.01.org/intel-sgx/sgx-dcap/1.4/linux/distro/ubuntuServer18.04/sgx_linux_x64_driver_1.21.bin -O sgx_linux_x64_driver.bin
  chmod +x sgx_linux_x64_driver.bin
  sudo ./sgx_linux_x64_driver.bin
  ```

  **Note:** A new version of either driver may have been released since this
            documentation was written. Check on
            [Intel's Open Source site](https://01.org/intel-software-guard-extensions/downloads)
            if a more recent SGX Legacy or DCAP driver exists. The former is
            referred to as "Intel SGX Linux X.Y Release" while the latter, as
            "Intel SGX DCAP Linux A.B Release".

* Ensure that the requirements are met for the
  [Azure IoT Edge extension](https://marketplace.visualstudio.com/items?itemName=vsciot-vscode.azure-iot-edge).

* For Azure IoT Edge projects, enable cross-building:

  * On Ubuntu 19.04 and 18.10, this should already be enabled by having
    installed the prerequisites listed previously.

  * On Ubuntu 18.04 and 16.04 by:
    ```bash
    sudo mkdir -p /lib/binfmt.d
    sudo sh -c 'echo :qemu-arm:M::\\x7fELF\\x01\\x01\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x02\\x00\\x28\\x00:\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\xfe\\xff\\xff\\xff:/usr/bin/qemu-arm-static:F > /lib/binfmt.d/qemu-arm-static.conf'
    sudo sh -c 'echo :qemu-aarch64:M::\\x7fELF\\x02\\x01\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x02\\x00\\xb7\\x00:\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\xfe\\xff\\xff\\xff:/usr/bin/qemu-aarch64-static:F > /lib/binfmt.d/qemu-aarch64-static.conf'
    sudo systemctl restart systemd-binfmt.service
    ```

  * To validate that your system is configured for cross-building, you can
    try testing the docker containers that will be needed in the build:
    ```bash
    docker run arm32v7/ubuntu:xenial
    docker run aarch64/ubuntu:xenial
    docker run amd64/ubuntu:xenial
    ```

  * Install the [iotedgehubdev](https://pypi.org/project/iotedgehubdev/) tool:
    ```bash
    pip install --upgrade iotedgehubdev
    ```

* If you are seeing permission issues related to connecting to the Docker
  daemon, add your Linux user to the docker group. This will allow your user
  to connect and issue commands to the Docker daemon:
  ```bash
  sudo usermod -a -G docker $USER
  ```
  Log out and log back in.

### Windows

* [Install Docker](https://docs.docker.com/install/)

* Ensure sure that Git long paths are enabled:
  `git config --global core.longpaths true`

* Ensure Docker is configured to use Linux containers.  See Docker's help
  on how to **Switch between Windows and Linux containers** on the
  [Get started with Docker for Windows](https://docs.docker.com/docker-for-windows/)
  page.
  

## Build and run extension from source code

For development of this extension, or running from source code directly

* Install [node](https://nodejs.org/en/)
* Install [npm](https://www.npmjs.com/get-npm)

To run the extension from this repository, following these instructions:

1. Clone this repository
   `git clone --recursive https://github.com/openenclave/openenclave --branch feature.new_platforms`.
1. Navigate to `new_platforms\vscode-extension` in the cloned folder.
1. Run npm to install the dependencies: `npm install` (see the
   [requirements section](#Requirements) for npm installation link).
1. Start VSCode: `code .`.
1. Start the extension using `F5`.

## Data/Telemetry

This project collects usage data and sends it to Microsoft to help improve our
products and services.  Read our [privacy
statement](http://go.microsoft.com/fwlink/?LinkId=521839) to learn more.  If you
don't wish to send usage data to Microsoft, you can set the
`telemetry.enableTelemetry` setting to `false`.  Learn more in the [Visual
Studio Code
FAQ](https://code.visualstudio.com/docs/supporting/faq#_how-to-disable-telemetry-reporting).

## Known Issues

1. Debugging the host application under QEMU does not work.

2. If while configuring a Standalone project, VS Code emits the error "The
   terminal shell path "cmake" is a directory", try changing `"type": "process"`
   into `"type": "shell"` in the corresponding tasks under `.vscode/tasks.json`
   in the generated project. Whether this happens appears to depend on how CMake
   was installed on the system.

## Release Notes

### 2.0.0

Support for the Open Enclave SDK master branch and Intel SGX on Linux.

### 1.1.0

Public Preview

### 1.0.1

Prototyping and developing :)
