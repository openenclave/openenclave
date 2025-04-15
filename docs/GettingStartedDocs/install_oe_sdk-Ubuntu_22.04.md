# Install the Open Enclave SDK (Ubuntu 22.04)

## Platform requirements

- Ubuntu 22.04-LTS 64-bit.
- SGX1-capable system with support for Flexible Launch Control (FLC).
    - You can acquire a VM with the required features from [Azure Confidential Compute](https://azure.microsoft.com/en-us/solutions/confidential-compute/).
    - If you are setting up your own device, [check if your existing device supports SGX with FLC](/docs/GettingStartedDocs/Contributors/building_oe_sdk.md#1-determine-the-sgx-support-level-on-your-developmenttarget-system).
        - If your device only supports SGX without FLC, you will need to [clone and build OE SDK](/docs/GettingStartedDocs/Contributors/SGX1GettingStarted.md) for that configuration.
        - If your device does not support SGX, follow the [instructions for simulation mode](/docs/GettingStartedDocs/install_oe_sdk-Simulation.md). Please see [instructions for determining SGX support](/docs/GettingStartedDocs/SGXSupportLevel.md) on the machine you are using.

### 1. Configure the Intel and Microsoft APT Repositories
```bash
echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu jammy main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list
wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add -

echo "deb [arch=amd64] https://packages.microsoft.com/ubuntu/22.04/prod jammy main" | sudo tee /etc/apt/sources.list.d/msprod.list
wget -qO - https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -

sudo apt update
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
wget https://download.01.org/intel-sgx/sgx-linux/2.25/distro/ubuntu22.04-server/sgx_linux_x64_driver_1.41.bin -O sgx_linux_x64_driver.bin
chmod +x sgx_linux_x64_driver.bin
sudo ./sgx_linux_x64_driver.bin
```

> This may not be the latest Intel SGX DCAP driver.
> Please check with [Intel's SGX site](https://01.org/intel-software-guard-extensions/downloads)
> if a more recent SGX DCAP driver exists.

### 3. Install the Intel and Open Enclave packages and dependencies
#### 3.1 Install required dependencies
```bash
sudo apt -y install llvm-11 libssl-dev gdb libsgx-enclave-common libsgx-quote-ex libprotobuf23 libsgx-dcap-ql libsgx-dcap-ql-dev az-dcap-client
```

> This step also installs the [az-dcap-client](https://github.com/microsoft/azure-dcap-client)
> package which is necessary for performing remote attestation in Azure. For a general
> implementation outside the Azure environment, please use [Intel QPL](https://github.com/intel/qpl) and
> see [Open Enclave's guide on using non-ACC Linux machines](Contributors\NonAccMachineSGXLinuxGettingStarted.md).

#### 3.2 Install a build system
If you wish to use the Ninja build system rather than make, also install:
```bash
sudo apt -y install ninja-build
```

If you wish to make use of the Open Enclave CMake package, please install CMake:

```
sudo apt-get install python3-pip
sudo pip3 install cmake
```

and [follow the instructions here](/cmake/sdk_cmake_targets_readme.md).

#### 3.3 Install Open Enclave
Download Open Enclave SDK binary packages [from GitHub](https://github.com/openenclave/openenclave/releases)

```bash
wget https://github.com/openenclave/openenclave/releases/download/v0.19.9/Ubuntu_2204_open-enclave_0.19.9_amd64.deb
sudo dpkg -i Ubuntu_2204_open-enclave_0.19.9_amd64.deb
```

### 4. Verify the Open Enclave SDK install

See [Using the Open Enclave SDK](Linux_using_oe_sdk.md) for verifying and using the installed SDK.

### 5. Determine call path for SGX quote generation in attestation sample

In the attestation sample, you can either take the in-process call path or out-of-process call path to generate evidence of format `OE_FORMAT_UUID_SGX_ECDSA`. Please refer to the following README file for more information:

 - [The Attestation Sample](/samples/attestation/README.md#determining-call-path-for-sgx-quote-generation)
