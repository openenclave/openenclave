Microsoft(R) OpenEnclave SDK
============================

# OpenEnclave

Introduction
------------

OpenEnclave is an SDK for builiding enclave applications in C and C++. An
enclave application partitions itself into a trusted component (called the
host) and an untrusted compoment (called the enclave). An enclave is a secure
container whose memory is protected from outsiders. These protections allow 
enclaves to perform secure computations with assurances that secrets will not 
be leaked to unauthorized entities.

OpenEnclave aims to support building of enclave applications without concern 
for the underlying memory protection architecture. OpenEnclave currently 
supports Intel(R) Software Guard Extensions (SGX) but will later provide 
support Microsoft(R) Virtual Secure Mode (VSM) as well and possibly others.

Building
--------

### Prerequisites:

- Install Ubuntu Desktop (ubuntu-16.04.2-desktop-amd64.iso)

- Install the Intel(R) SGX driver ([here](https://github.com/01org/linux-sgx-driver))

- Install the Intel(R) AESM service ([here](https://github.com/01org/linux-sgx))

- Install GNU make

- Install the GCC C++ compiler

Contributing
------------

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
