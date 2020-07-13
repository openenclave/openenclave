# Install the Open Enclave Host-Verify SDK (Ubuntu 18.04)

## Platform requirements

- Ubuntu 18.04-LTS 64-bit.
    - Instructions are also available for [Ubuntu 16.04-LTS 64-bit](/docs/GettingStartedDocs/install_host_verify-Ubuntu_16.04.md).

### 1. Configure the Intel and Microsoft APT Repositories
```bash
echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list
wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add -

echo "deb http://apt.llvm.org/bionic/ llvm-toolchain-bionic-7 main" | sudo tee /etc/apt/sources.list.d/llvm-toolchain-bionic-7.list
wget -qO - https://apt.llvm.org/llvm-snapshot.gpg.key | sudo apt-key add -

echo "deb [arch=amd64] https://packages.microsoft.com/ubuntu/18.04/prod bionic main" | sudo tee /etc/apt/sources.list.d/msprod.list
wget -qO - https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -
```

### 2. Install the Intel and Open Enclave Host-Verify packages and dependencies
```bash
sudo apt update
sudo apt -y install clang-7 libssl-dev gdb libprotobuf10 libsgx-dcap-ql libsgx-dcap-ql-dev az-dcap-client open-enclave-hostverify
```

> This step also installs the [az-dcap-client](https://github.com/microsoft/azure-dcap-client)
> package which is necessary for performing remote attestation in Azure. A general
> implementation for using Intel DCAP outside the Azure environment is coming soon.

If you wish to use the Ninja build system rather than make, also install
```bash
sudo apt -y install ninja-build
```

If you wish to make use of the Open Enclave Host-Verify CMake package, please install CMake and [follow the instructions here](/cmake/sdk_cmake_targets_readme.md).

### 3. Verify the Open Enclave Host-Verify SDK install

See [Using the Open Enclave Host-Verify SDK](Linux_using_host_verify.md) for verifying and using the installed SDK.
