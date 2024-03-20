# Getting Started with building Open Enclave in a Docker Container

## Platform requirements

- Linux distribution capable of running Docker containers.

## Steps to building Open Enclave inside of a Docker container

1. Install Docker CE by following these instructions: https://docs.docker.com/install/linux/docker-ce/ubuntu/#install-docker-ce

2. Install the appropriate Intel SGX Driver for your platform from https://01.org/intel-software-guard-extensions/downloads
    - For a SGX with FLC system, choose Intel SGX DCAP Driver for your platform, such as [intel-sgx-dcap-1.16](https://download.01.org/intel-sgx/sgx-dcap/1.16/).
    - For a SGX without FLC system, choose the Intel SGX Driver for your platform, such as [intel-sgx-linux-2.19](https://download.01.org/intel-sgx/sgx-linux/2.19/distro/).
    - Once you select the correct version and platform, download the driver named in the format of `sgx_linux_x64_driver_{VERSION}.bin`. For example, [sgx_linux_x64_driver_1.41.bin](https://download.01.org/intel-sgx/sgx-linux/2.18/distro/ubuntu20.04-server/sgx_linux_x64_driver_1.41.bin).
    - To install this driver, simply run it as root like this:
        - `sudo bash ./sgx_linux_x64_driver_1.41.bin`

3. Pull the latest "Full" image for Open Enclave for your appropriate distribution from [this table](https://github.com/openenclave/openenclave/blob/master/DOCKER_IMAGES.md). Example:
```bash
docker pull openenclavedockerregistry.azurecr.io/oetools-20.04:latest
```

4. Run an interactive container of one of these images. Mount the appropriate devices based on which driver you are running:

```bash
sudo docker run --device <device> -i -t openenclavedockerregistry.azurecr.io/oetools-20.04:latest bash
```

- If you're using the out-of-tree Intel SGX DCAP driver, you'll want to expose the `/dev/sgx` device to the container, by passing `--device /dev/sgx`.

- If you're using the [upstreamed SGX driver](https://www.kernel.org/doc/html/v6.8/arch/x86/sgx.html) that has been part of the Linux kernel since 5.11, you'll need both of the following devices: `--device /dev/sgx_enclave:/dev/sgx_enclave` and `--device /dev/sgx_provision:/dev/sgx_provision`.

- If you're using the Intel SGX (non-DCAP) driver (`isgx`), you'll want to do two things:
    - The device name is different (isgx as opposed to sgx), so you'll want this option instead: `--device /dev/isgx:/dev/isgx`.
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
