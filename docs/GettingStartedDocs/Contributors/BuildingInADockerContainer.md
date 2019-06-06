# Getting Started with building Open Enclave in a Docker Container

## Platform requirements

- Linux distribution capable of running Docker containers.

## Steps to building Open Enclave inside of a Docker container

1. Install Docker CE by following these instructions: https://docs.docker.com/install/linux/docker-ce/ubuntu/#install-docker-ce-1

2. Install the appropriate Intel SGX Driver for your platform. For example, if you're running on an SGX1 with FLC system, you'll probably want to install the Intel SGX DCAP Driver for your platfrom: https://01.org/intel-software-guard-extensions/downloads

3. Pull the latest oetools-full image for Open Enclave from either of these two distributions:
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
