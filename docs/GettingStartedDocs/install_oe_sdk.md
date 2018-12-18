# Install the Open Enclave SDK

## Platform requirements

- Ubuntu 16.04-LTS 64-bits
- SGX1-capable system with support for Flexible Launch Control (FLC).
    - You can acquire a VM with the required features from [Azure Confidential Compute](https://azure.microsoft.com/en-us/solutions/confidential-compute/).
    - Alternatively, you can [check if your existing device supports SGX with FLC](/docs/GettingStartedDocs/GettingStarted.md#1-determine-the-sgx-support-level-on-your-developmenttarget-system).

#### 1. Configure the Intel and Microsoft APT Repositories
```bash
echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu xenial main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list
wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add -

echo "deb http://apt.llvm.org/xenial/ llvm-toolchain-xenial-7 main" | sudo tee /etc/apt/sources.list.d/llvm-toolchain-xenial-7.list
wget -qO - https://apt.llvm.org/llvm-snapshot.gpg.key | sudo apt-key add -

echo "deb [arch=amd64] https://packages.microsoft.com/ubuntu/16.04/prod xenial main" | sudo tee /etc/apt/sources.list.d/msprod.list
wget -qO - https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -
```

#### 2. Install the prerequisite packages
```bash
sudo apt-get update
sudo apt-get -y install clang-7 libssl-dev make gcc gdb g++ pkg-config
```

#### 3. Install the Intel SGX DCAP Driver
```bash
wget https://download.01.org/intel-sgx/dcap-1.0/sgx_linux_x64_driver_dcap_36594a7.bin -O sgx_linux_x64_driver.bin
chmod +x sgx_linux_x64_driver.bin
sudo ./sgx_linux_x64_driver.bin
```

> The Intel SGX DCAP driver currently needs to be re-installed when the Ubuntu kernel is updated.

#### 4. Install the Intel and Open Enclave packages
```bash
sudo apt-get -y install libsgx-enclave-common libsgx-enclave-common-dev libsgx-dcap-ql libsgx-dcap-ql-dev az-dcap-client open-enclave
```

> This step also installs the [az-dcap-client](https://github.com/microsoft/azure-dcap-client)
> package which is necessary for performing remote attestation in Azure. A general
> implementation for using Intel DCAP outside the Azure environment is coming soon.

As a convenience, you can download and run the [install-open-enclave-stack](/scripts/install-open-enclave-stack) on your target device, which executes all of the above steps.

The packages are also available for download directly:
- [libsgx-enclave-common_2.3.100.46354-1_amd64.deb](https://download.01.org/intel-sgx/dcap-1.0/SGX_installers/ubuntu16.04/libsgx-enclave-common_2.3.100.46354-1_amd64.deb)
- [libsgx-enclave-common-dev_2.3.100.0-1_amd64.deb](https://download.01.org/intel-sgx/sgx_repo/ubuntu/pool/main/libs/libsgx-enclave-common-dev/libsgx-enclave-common-dev_2.3.100.0-1_amd64.deb)
- [libsgx-dcap-ql_1.0.100.46460-1.0_amd64.deb](https://download.01.org/intel-sgx/dcap-1.0/DCAP_installers/ubuntu16.04/libsgx-dcap-ql_1.0.100.46460-1.0_amd64.deb)
- [libsgx-dcap-ql-dev_1.0.100.46460-1.0_amd64.deb](https://download.01.org/intel-sgx/dcap-1.0/DCAP_installers/ubuntu16.04/libsgx-dcap-ql-dev_1.0.100.46460-1.0_amd64.deb)
- [az-dcap-client_1.0_amd64.deb](https://packages.microsoft.com/repos/microsoft-ubuntu-xenial-prod/pool/main/a/az-dcap-client/az-dcap-client_1.0_amd64.deb)
- [open-enclave_0.4.0_amd64.deb](https://packages.microsoft.com/repos/microsoft-ubuntu-xenial-prod/pool/main/o/open-enclave/open-enclave-0.4.0-Linux.deb)

#### 5. Verify the Open Enclave SDK install

See [Using the Open Enclave SDK](using_oe_sdk.md) for verifying and using the installed SDK.
