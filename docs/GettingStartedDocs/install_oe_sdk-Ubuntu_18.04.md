# Install the Open Enclave SDK (Ubuntu 18.04)

## Platform requirements

- Ubuntu 18.04-LTS 64-bit.
    - Instructions are also available for [Ubuntu 16.04-LTS 64-bit](/docs/GettingStartedDocs/install_oe_sdk-Ubuntu_16.04.md).
- SGX1-capable system with support for Flexible Launch Control (FLC).
    - You can acquire a VM with the required features from [Azure Confidential Compute](https://azure.microsoft.com/en-us/solutions/confidential-compute/).
    - If you are setting up your own device, [check if your existing device supports SGX with FLC](/docs/GettingStartedDocs/Contributors/building_oe_sdk.md#1-determine-the-sgx-support-level-on-your-developmenttarget-system).
        - If your device only supports SGX without FLC, you will need to [clone and build OE SDK](/docs/GettingStartedDocs/Contributors/SGX1GettingStarted.md) for that configuration.
        - If your device does not support SGX, follow the [instructions for simulation mode](/docs/GettingStartedDocs/install_oe_sdk-Simulation.md). Please see [instructions for determining SGX support](/docs/GettingStartedDocs/SGXSupportLevel.md) on the machine you are using.

### 1. Configure the Intel and Microsoft APT Repositories
```bash
echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list
wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add -

echo "deb http://apt.llvm.org/bionic/ llvm-toolchain-bionic-7 main" | sudo tee /etc/apt/sources.list.d/llvm-toolchain-bionic-7.list
wget -qO - https://apt.llvm.org/llvm-snapshot.gpg.key | sudo apt-key add -

echo "deb [arch=amd64] https://packages.microsoft.com/ubuntu/18.04/prod bionic main" | sudo tee /etc/apt/sources.list.d/msprod.list
wget -qO - https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -
```

### 2. Install the Intel SGX DCAP Driver
Some versions of Ubuntu come with the SGX driver already installed. You can check
by running with the following:

```
$ dmesg | grep -i sgx
[  106.775199] sgx: intel_sgx: Intel SGX DCAP Driver {version}
```

If the output of the above is blank, you should proceed with installing the driver:

```bash
sudo apt update
sudo apt -y install dkms
wget https://download.01.org/intel-sgx/sgx-dcap/1.7/linux/distro/ubuntu18.04-server/sgx_linux_x64_driver_1.35.bin -O sgx_linux_x64_driver.bin
chmod +x sgx_linux_x64_driver.bin
sudo ./sgx_linux_x64_driver.bin
```

> This may not be the latest Intel SGX DCAP driver.
> Please check with [Intel's SGX site](https://01.org/intel-software-guard-extensions/downloads)
> if a more recent SGX DCAP driver exists.

### 3. Install the Intel and Open Enclave packages and dependencies
```bash
sudo apt -y install clang-7 libssl-dev gdb libsgx-enclave-common libsgx-enclave-common-dev libprotobuf10 libsgx-dcap-ql libsgx-dcap-ql-dev az-dcap-client open-enclave
```

> This step also installs the [az-dcap-client](https://github.com/microsoft/azure-dcap-client)
> package which is necessary for performing remote attestation in Azure. A general
> implementation for using Intel DCAP outside the Azure environment is coming soon.

If you wish to use the Ninja build system rather than make, also install
```bash
sudo apt -y install ninja-build
```

If you wish to make use of the Open Enclave CMake package, please install CMake and [follow the instructions here](/cmake/sdk_cmake_targets_readme.md).

### 4. Verify the Open Enclave SDK install

See [Using the Open Enclave SDK](Linux_using_oe_sdk.md) for verifying and using the installed SDK.
