FROM ubuntu:18.04 as oe-attested-tls

# This is the latest PSW version we are currently supporting. This may change in the future and you may require to update it
# In that case, refer: https://01.org/intel-software-guard-extensions/downloads
ENV PSW_VERSION=2.13.100

RUN if [ -z "$PSW_VERSION" ]; then echo "Please set PSW_VERSION (e.g. 2.11)." >&2; exit 1; fi
RUN apt-get update && apt-get install -y \
    wget \
    gnupg \
    python \
    apt-transport-https \
    libssl1.0.0 \
    make


# Use the APT preference file to pin sgx packages to specific versions
# Reference https://manpages.debian.org/buster/apt/apt_preferences.5.en.html
# Download the pref file from https://download.01.org/intel-sgx/sgx_repo/ubuntu/apt_preference_files/
# Assuming file name to follow *sgx_<PSW_VERSION>_bionic_custom_version.cfg convention
RUN ["/bin/bash", "-c", "wget -r -l1 --no-parent -nd -A *sgx_$(echo ${PSW_VERSION//./_})_bionic_custom_version.cfg https://download.01.org/intel-sgx/sgx_repo/ubuntu/apt_preference_files/"]
RUN ["/bin/bash", "-c", "mv *sgx_$(echo ${PSW_VERSION//./_})_bionic_custom_version.cfg /etc/apt/preferences.d/intel-sgx.pref"]


# Add the repository to sources, and add the key to the list of
# trusted keys used by the apt to authenticate packages
RUN echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main' | tee /etc/apt/sources.list.d/intel-sgx.list \
    && wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add -
RUN echo "deb http://apt.llvm.org/bionic/ llvm-toolchain-bionic-7 main" | tee /etc/apt/sources.list.d/llvm-toolchain-bionic-7.list \
    && wget -qO - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -
RUN echo "deb [arch=amd64] https://packages.microsoft.com/ubuntu/18.04/prod bionic main" | tee /etc/apt/sources.list.d/msprod.list \
    && wget -qO - https://packages.microsoft.com/keys/microsoft.asc | apt-key add -


RUN apt-get update && apt-get install -y --no-install-recommends \
    clang-10 libprotobuf10 libsgx-dcap-ql \
    libsgx-quote-ex az-dcap-client open-enclave libsgx-enclave-common \
    gcc g++ gdb git python-pip linux-base-sgx libssl-dev \
    libsgx-dcap-ql-dev libsgx-enclave-common-dev

RUN pip install cmake

## The following sets the flag for out of proc attestation mode. Alternatively you can set this flag on the kubernetes deployment files
ENV SGX_AESM_ADDR=1

# Copy sample code folder into the container
COPY . layered-attestation/
WORKDIR /layered-attestation

## Source openenclaverc, Set up environment variables
RUN . /opt/openenclave/share/openenclave/openenclaverc \
    && export CC=gcc && export CXX=g++ && export PKG_CONFIG_PATH=/opt/openenclave/share/pkgconfig/ \
    && mkdir build && cd build && cmake .. && make


## The following sets the flag for out of proc attestation mode. Alternatively you can set this flag on the deployment files
ENV SGX_AESM_ADDR=1

WORKDIR /layered-attestation/build

# ## Set the command to run the getting-report application, to validate that a report can be gotten
CMD make run