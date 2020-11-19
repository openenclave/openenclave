#!/bin/bash
# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.
# 
# build-openenclave.sh
# Build openenclave using the nix based build image
#
# options:
#   -o <dir>  put build output in directory <dir>
#   -c        commit the result
#   -i        interactive. Allow user to execute nix-shell and nix-build for debugging 
#   -t        Do not run tests with build.
#    

set -x
OUTPUT_DIR="/output"
INTERACTIVE=false
COMMIT=false

while getopts "o:tic" opt; do
  case ${opt} in
    o ) # output dir
        OUTPUT_DIR=$OPTARG
        echo "output dir = ${OUTPUT_DIR}"
      ;;
    t ) # run tests with build
        DO_TESTS=true
      ;;
    i ) # Dont execute nix-build.sh, just bash
        INTERACTIVE=true
      ;;
    c ) # run tests with build
        COMMIT=true
      ;;
    \? ) echo "Usage: build-openenclave.sh [-o outdir] [-t]"
      ;;
  esac
done
shift $((OPTIND -1))

if [ -d /dev/sgx ]
then 
    SGX_DEVICE="--device /dev/sgx/enclave:/dev/sgx/enclave  --device /dev/sgx/provision:/dev/sgx/provision"
elif [ -c /dev/isgx ]
then
    SGX_DEVICE="--device /dev/isgx:/dev/isgx"
else
    SGX_DEVICE="-e OE_SIMULATION=1"
fi

if [ -h ${OUTPUT_DIR} ]
then
    echo "link /output found" 
elif [ -d ${OUTPUT_DIR} ]
then
    echo "directory ${OUTPUT_DIR} found" 
else
    echo "making directory ${OUTPUT_DIR}"
    sudo mkdir ${OUTPUT_DIR}
    sudo chmod 777 ${OUTPUT_DIR}
fi

# We remove the old build directory.
# nix-build has no idea of forcing a rebuild
if [ -d ${OUTPUT_DIR}/build ]
then
    rm -rf ${OUTPUT_DIR}/build/*
else
    mkdir -p ${OUTPUT_DIR}/build
    chmod 777 ${OUTPUT_DIR}/build
fi


if $INTERACTIVE
then 
    RUNCMD="/bin/bash"
else
    RUNCMD="/home/azureuser/nix-build.sh"
fi

if $DO_TESTS
then 
   DO_TESTS_ARG="--env DO_TESTS=true"
fi

CONTAINER_NAME="oe-nix-build-$(date +"%Y%j%H%M")"
#
# build.env specifies the commit or tag, and sha of the build. 
docker run -it ${SGX_DEVICE} --name ${CONTAINER_NAME} -v ${OUTPUT_DIR}:/output \
           -v /var/run/aesmd:/var/run/aesmd --cap-add=SYS_PTRACE ${DO_TESTS_ARG} \
           --env-file ./build.env -m 24G --memory-swap=-1 openenclave-build $RUNCMD

if $COMMIT
then
   docker commit ${CONTAINER_NAME} oe-nix-build-$(date +"%Y%j%H%M")
fi
set +x
