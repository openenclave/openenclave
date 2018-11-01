#!/bin/bash

# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# Install required packages.
#

source ./utils.sh


set -x

function error_exit() {
  echo $1
  echo "failed" > /opt/azure/acc/completed
  exit 1
}

#


#
# Presupposes the correct keys and ppas have been populated.
configure_repos_deb()
{
    # Configure apt to use clang-7
    wget -O /tmp/key  https://apt.llvm.org/llvm-snapshot.gpg.key
    apt-key add /tmp/key 2>/dev/null

    # Configure apt to use packages.microsoft.com repo
    wget -qO /tmp/key https://packages.microsoft.com/keys/microsoft.asc
    apt-key add /tmp/key 2>/dev/null

    # Configure apt to use Intel 01.org repo
    wget -qO /tmp/key https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key
    apt-key add /tmp/key 2>/dev/null

    export DEBIAN_FRONTEND=noninteractive
    # Update pkg repository
    retrycmd_if_failure 10 10 120 apt update
    if [ $? -ne 0  ]; then
      error_exit "apt update failed"
    fi
}

conditionally_install_packages() {
    IFS=' ' read -r -a pkgarray <<< "$1"
    local PACKAGES=""

    for pkg in ${pkgarray[*]}
    do
        pkgstr="^"
        pkgstr+="$pkg"
        pkgstr+="$"
        rslt=`dpkg -l | awk -F" " '{ print $2}' | grep $pkgstr`
        if [[ -z $rslt ]]
        then
            PACKAGES+="$pkg "
        else
            >&2 echo "skipping install of $pkg. Already present" 
        fi
    done
    echo $PACKAGES
}


#
# Mainline
#
cd /tmp
curl -L -o /tmp/oesgx https://oedownload.blob.core.windows.net/data/oesgx
chmod a+x /tmp/oesgx
/tmp/oesgx | grep "does not support"
if [ $? -eq 0 ] ; then
  error_exit "This hardware does not support open enclave"
fi

distro=`grep DISTRIB_ID /etc/*-release | awk -F"=" '{ print $2 }'`
version=`grep DISTRIB_RELEASE /etc/*-release| awk -F"=" '{ print $2 }'`
case $distro in
    "Ubuntu")
        install_tool="apt"
        case $version in
        "18.04") 
            echo "deb http://apt.llvm.org/bionic/ llvm-toolchain-bionic-7 main" >> /etc/apt/sources.list
            echo "deb-src http://apt.llvm.org/bionic/ llvm-toolchain-bionic-7 main" >> /etc/apt/sources.list
            echo "deb [arch=amd64] https://packages.microsoft.com/ubuntu/18.04/prod bionic main" | sudo tee /etc/apt/sources.list.d/msprod.list
            echo "deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main" | sudo tee /etc/apt/sources.list.d/intel-sgx.list
            ;;
        "16.04")
            echo "deb http://apt.llvm.org/xenial/ llvm-toolchain-xenial-7 main" >> /etc/apt/sources.list
            echo "deb-src http://apt.llvm.org/xenial/ llvm-toolchain-xenial-7 main" >> /etc/apt/sources.list
            echo "deb [arch=amd64] https://packages.microsoft.com/ubuntu/16.04/prod xenial main" | sudo tee /etc/apt/sources.list.d/msprod.list
            echo "deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu xenial main" | sudo tee /etc/apt/sources.list.d/intel-sgx.list
            ;;
        "*") echo "Version $version is not supported" 
            exit 1
            ;;
        esac

        configure_repos_deb

        # Add public packages:
        PACKAGES="make gcc gdb g++ libssl-dev pkg-config"

        # Add clang-7 packages:
        PACKAGES="$PACKAGES clang-7 lldb-7 lld-7 doxygen ocaml ocamlbuild"
        PACKAGES=`conditionally_install_packages "$PACKAGES"`

        echo "Install packages $PACKAGES"
        apt install $PACKAGES
         
        # Install SGX driver
        retrycmd_if_failure 10 10 120 curl -fsSL -O https://download.01.org/intel-sgx/dcap-1.0/sgx_linux_x64_driver_dcap_36594a7.bin
        if [ $? -ne 0  ]; then
            error_exit "failed to download SGX driver"
        fi
        chmod a+x ./sgx_linux_x64_driver_dcap_36594a7.bin
        ./sgx_linux_x64_driver_dcap_36594a7.bin
        if [ $? -ne 0  ]; then
            error_exit "failed to install SGX driver"
        fi

        # Add Intel packages
        PACKAGES="libsgx-enclave-common libsgx-enclave-common-dev libsgx-dcap-ql libsgx-dcap-ql-dev"

        # Add Microsoft packages
        PACKAGES="$PACKAGES az-dcap-client"
        PACKAGES=`conditionally_install_packages "$PACKAGES"`
        echo "Install packages $PACKAGES"
        apt install $PACKAGES

    ;;

    "CentOS" | "RedHat")
        echo "Redhat distro Version $version is not yet supported" 
    ;;
    *)
        echo "Distro $distro is not currently supported"
        exit 0
    ;;
esac


systemctl disable aesmd
systemctl stop aesmd

# Check to see this is an openenclave supporting hardware environment

# Indicate readiness
echo "ok" > /opt/azure/acc/completed
set +x
