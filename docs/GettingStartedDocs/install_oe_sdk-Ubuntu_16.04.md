# Install the Open Enclave SDK (Ubuntu 16.04)

## Platform requirements

- Ubuntu 16.04-LTS 64-bits
- SGX1-capable system with support for Flexible Launch Control (FLC).
    - You can acquire a VM with the required features from [Azure Confidential Compute](https://azure.microsoft.com/en-us/solutions/confidential-compute/).
    - Alternatively, you can [check if your existing device supports SGX with FLC](/docs/GettingStartedDocs/GettingStarted.md#1-determine-the-sgx-support-level-on-your-developmenttarget-system).

### 1. Configure the Intel and Microsoft APT Repositories
```bash
echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu xenial main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list
wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add -

echo "deb http://apt.llvm.org/xenial/ llvm-toolchain-xenial-7 main" | sudo tee /etc/apt/sources.list.d/llvm-toolchain-xenial-7.list
wget -qO - https://apt.llvm.org/llvm-snapshot.gpg.key | sudo apt-key add -

echo "deb [arch=amd64] https://packages.microsoft.com/ubuntu/16.04/prod xenial main" | sudo tee /etc/apt/sources.list.d/msprod.list
wget -qO - https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -
```

### 2. Install the Intel SGX DCAP Driver
```bash
sudo apt -y install dkms
wget https://download.01.org/intel-sgx/dcap-1.0.1/dcap_installer/ubuntuServer1604/sgx_linux_x64_driver_dcap_4f32b98.bin -O sgx_linux_x64_driver.bin
chmod +x sgx_linux_x64_driver.bin
sudo ./sgx_linux_x64_driver.bin
```

Note: This may not be the latest Intel SGX DCAP driver. Please check with [Intel's SGX site](https://01.org/intel-software-guard-extensions/downloads) if a more recent SGX DCAP driver exists.

### 3. Install the Intel and Open Enclave packages and dependencies
```bash
sudo apt -y install clang-7 libssl-dev gdb libsgx-enclave-common libsgx-enclave-common-dev libsgx-dcap-ql libsgx-dcap-ql-dev az-dcap-client open-enclave
```

> This step also installs the [az-dcap-client](https://github.com/microsoft/azure-dcap-client)
> package which is necessary for performing remote attestation in Azure. A general
> implementation for using Intel DCAP outside the Azure environment is coming soon.

Note: If you wish to make use of the Open Enclave CMake package, please install cmake and [follow the instructions here](cmake/sdk_cmake_targets_readme.md).

### 4. Verify the Open Enclave SDK install

See [Using the Open Enclave SDK](using_oe_sdk.md) for verifying and using the installed SDK.
