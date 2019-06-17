# Getting Started with building Open Enclave in a Docker Container

## Platform requirements

- Linux distribution capable of running Docker containers.

## Steps to building Open Enclave inside of a Docker container

1. Install Docker CE by following these instructions: https://docs.docker.com/install/linux/docker-ce/ubuntu/#install-docker-ce

2. Install the appropriate Intel SGX Driver for your platform. For example, if you're running on an SGX1 with FLC system, you'll probably want to install the Intel SGX DCAP Driver for your platfrom: https://01.org/intel-software-guard-extensions/downloads
    - If you're running on an SGX with FLC system, you'll probably want to install the Intel SGX DCAP Driver for your platfrom: https://01.org/intel-softwareguard-extensions/downloads/intel-sgx-dcap-linux-1.1-release
    - If you're running on an SGX without FLC system, you'll want to install the Intel SGX Driver for your platform: https://01.org/intel-softwareguard-extensions/downloads/intel-sgx-linux-2.5-release
    - The driver you're looking for is a ".bin" file, for either Ubuntu 16.04 or 18.04 releases. It will be named something like: `sgx_linux_x64_driver_dcap_1.1.100.2786ad8.bin`
    - To install this driver, simply run it as root like this:
        - `sudo bash ./sgx_linux_x64_driver_dcap_1.1.100.2786ad8.bin`

3. Pull the latest oetools-full image for Open Enclave from *either* of these two distributions:
    - https://hub.docker.com/r/oeciteam/oetools-full-16.04
    - https://hub.docker.com/r/oeciteam/oetools-full-18.04

4. Run an interactive container of one of these images. If you're using the Intel SGX DCAP driver, for example, you'll want to expose the /dev/sgx device to the container:
```bash
sudo docker run --device /dev/sgx:/dev/sgx -i -t oeciteam/oetools-full-18.04 bash
```

5. Clone the Open Enclave repository from within this container and run the build and tests. For example, if your system has the SGX DCAP driver installed and it has been made available to the container:
```bash
cd ~
git clone https://github.com/Microsoft/openenclave.git
cd openenclave
mkdir build
cd build
cmake .. -GNinja
ninja
ctest
```
