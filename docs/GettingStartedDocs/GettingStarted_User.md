Getting Started for Open Enclave (OE) application developers
========================================================

Acquire Intel SGX DCAP Hardware
----------------------------------------------

 - Azure currently offers an Ubuntu 16.04 ACC VM which supports Intel SGX DCAP. More information can be found here: https://azure.microsoft.com/en-us/solutions/confidential-compute/

Install Open Enclave SDK
----------------------------------------------

1. Configure APT Repos
```bash
echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu xenial main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list
wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add -

echo "deb http://apt.llvm.org/xenial/ llvm-toolchain-xenial-7 main" | sudo tee /etc/apt/sources.list.d/llvm-toolchain-xenial-7.list
wget -qO - https://apt.llvm.org/llvm-snapshot.gpg.key | sudo apt-key add -

echo "deb [arch=amd64] https://packages.microsoft.com/ubuntu/16.04/prod xenial main" | sudo tee /etc/apt/sources.list.d/msprod.list
wget -qO - https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -
```

2. Install the base packages
```bash
sudo apt-get update
sudo apt-get -y install clang-7 libssl-dev make gcc gdb g++ pkg-config
```

3. Install the Intel SGX DCAP Driver
```bash
wget https://download.01.org/intel-sgx/dcap-1.0/sgx_linux_x64_driver_dcap_36594a7.bin -O sgx_linux_x64_driver.bin
chmod +x sgx_linux_x64_driver.bin
sudo ./sgx_linux_x64_driver.bin
```

4. Install the Intel and Open Enclave packages
```bash
sudo apt-get -y install libsgx-enclave-common libsgx-enclave-common-dev libsgx-dcap-ql libsgx-dcap-ql-dev az-dcap-client open-enclave
```
  
 - As an alternative to all steps above, one can run the [install-open-enclave-stack](/scripts/install-open-enclave-stack) script.

OE Samples
-------------------------------

   The default install directory for an Open Enclave SDK installationis /opt/openenclave. On a successful installation, you can find all the samples under 
   
       /opt/openenclave/share/openenclave/samples
  
See [Open Enclave samples](/samples/README.md) for details
    
SDK API Reference
-------------------------------

  [SDK API Reference](APIsAvailableToEnclave.md)


