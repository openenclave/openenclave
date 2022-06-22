# Getting Started with building Open Enclave in a Docker Container

## Platform requirements

- Linux distribution capable of running Docker containers.

## Steps to building Open Enclave inside of a Docker container

1. Install Docker CE by following these instructions: https://docs.docker.com/install/linux/docker-ce/ubuntu/#install-docker-ce

2. Install the appropriate Intel SGX Driver for your platform from https://01.org/intel-software-guard-extensions/downloads
    - For a SGX with FLC system, choose Intel SGX DCAP Driver for your platform, such as [intel-sgx-dcap-1.10.3-release](https://01.org/intel-softwareguard-extensions/downloads/intel-sgx-dcap-1.10.3-release).
    - For a SGX without FLC system, choose the Intel SGX Driver for your platform, such as [intel-sgx-linux-2.13.3-release](https://01.org/intel-softwareguard-extensions/downloads/intel-sgx-linux-2.13.3-release).
    - Once you select the correct version and platform, download the driver named in the format of `sgx_linux_x64_driver_{VERSION}.bin`. For example, [sgx_linux_x64_driver_1.35.bin](https://download.01.org/intel-sgx/sgx-dcap/1.7/linux/distro/ubuntu18.04-server/sgx_linux_x64_driver_1.35.bin).
    - To install this driver, simply run it as root like this:
        - `sudo bash ./sgx_linux_x64_driver_1.35.bin`

3. Pull the latest "Full" image for Open Enclave for your appropriate distribution from [this table](https://github.com/openenclave/openenclave/blob/master/DOCKER_IMAGES.md). Example:
```bash
docker pull oejenkinscidockerregistry.azurecr.io/oetools-20.04:2022.06.0931
```

4. Run an interactive container of one of these images. If you're using the Intel SGX DCAP driver, for example, you'll want to expose the /dev/sgx device to the container:
```bash
sudo docker run --device /dev/sgx:/dev/sgx -i -t oeciteam/oetools-18.04 bash
```
  - If you're using the Intel SGX (non-DCAP) driver, you'll want to do two things:
    - The device name is different (isgx as opposed to sgx), so you'll want this option instead:  `--device /dev/isgx:/dev/isgx`
    - The aesm service will need to be running on the container host, and then its socket file directory will need to be exposed to the container as a volume by adding the `-v /var/run/aesmd:/var/run/aesmd` option.

5. Clone the Open Enclave repository from within this container and run the build and tests. For example, if your system has the SGX DCAP driver installed and it has been made available to the container:
```bash
cd ~
git clone --recursive https://github.com/openenclave/openenclave.git
cd openenclave
mkdir build
cd build
cmake .. -G Ninja
ninja
ctest
```
