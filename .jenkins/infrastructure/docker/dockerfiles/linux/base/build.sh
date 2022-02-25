#!/usr/bin/env bash
# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.
#
# This script is used to build associated Dockerfile
# Recommended to create a new directory to build with a minimal build context

set -e

SOURCE_DIR=$(dirname "$0")
BUILD_DIR="${PWD}"
UBUNTU_VERSION="18.04"
IMAGE_TAG="latest"

usage() {
    echo "Usage: $0 -v <string> [OPTIONS..]" 1>&2
    echo "Create a base Docker image for Open Enclave" 1>&2
    echo "  -v     Intel SGX version (Example: 2.15.100)" 1>&2
    echo ""
    echo "Options:" 1>&2
    echo "  -u     Ubuntu release version [Default: 18.04]" 1>&2
    echo "  -t     Tag for the Docker image [Default: latest]" 1>&2
    exit 1
}

# Downloads, fetches, and dearmors keys
# Required parameters:
#   $1 key file name
#   $2 download url
fetch_repository_key() {
    echo "Downloading ${1} from ${2}"
    if [[ -f "${BUILD_DIR}/${1}" ]]; then
        rm "${BUILD_DIR}/${1}"
    fi
    wget \
    --directory-prefix="${BUILD_DIR}" \
    --no-verbose \
    --tries=3 \
    --waitretry=3 \
    "${2}"
    # Dearmor key
    if [[ -f "${BUILD_DIR}/${1}.gpg" ]]; then
        rm "${BUILD_DIR}/${1}.gpg"
    fi
    gpg --dearmor "${BUILD_DIR}/${1}"
}

# Parse options
while getopts "hv:u::t::" option; do
    case "${option}" in
       v) SGX_VERSION="${OPTARG//./_}"
          ;;
       u) UBUNTU_VERSION="${OPTARG}"
          ;;
       t) IMAGE_TAG="${OPTARG}"
          ;;
       *) usage
          ;;
    esac
done

# Catch extra parameters
shift "$((OPTIND-1))"
if [[ ! -z "${1}" ]]; then
    echo "Unknown parameter: ${1}" 1>&2
    exit 1
fi

# Check SGX version
if [[ -z ${SGX_VERSION+x} ]]; then
    usage
fi

# Set Ubuntu Codename
case "${UBUNTU_VERSION}" in
    18.04) UBUNTU_CODENAME="bionic"
           ;;
    20.04) UBUNTU_CODENAME="focal"
           ;;
esac

# Default image tag
if [[ -z "${IMAGE_TAG+x}" ]]; then
    IMAGE_TAG="SGX-${SGX_VERSION}"
fi

# Download Intel SGX package preferences to pin to a specific Intel SGX version
echo "Checking for Intel SGX version ${SGX_VERSION} for Ubuntu ${UBUNTU_CODENAME}..."
if [[ -d "${BUILD_DIR}/apt_preference_files" ]]; then
    rm -rf "${BUILD_DIR}/apt_preference_files"
    mkdir "${BUILD_DIR}/apt_preference_files"
fi
wget \
  --recursive \
  --level=1 \
  --no-parent \
  --no-directories \
  --accept="*sgx_${SGX_VERSION}_${UBUNTU_CODENAME}_custom_version.cfg" \
  --directory-prefix "${BUILD_DIR}/apt_preference_files" \
  --no-verbose \
  --tries=3 \
  --waitretry=3 \
  https://download.01.org/intel-sgx/sgx_repo/ubuntu/apt_preference_files/
find "${BUILD_DIR}/apt_preference_files" \
    -type f \
    -name "*sgx_${SGX_VERSION}_${UBUNTU_CODENAME}_custom_version.cfg" \
    -exec mv {} "${BUILD_DIR}/apt_preference_files/intel-sgx.pref" \;

# Download Intel SGX repository key
fetch_repository_key "intel-sgx-deb.key" "https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key"

# Download Microsoft repository key
fetch_repository_key "microsoft.asc" "https://packages.microsoft.com/keys/microsoft.asc"

# Build Docker image
set -x
DOCKER_BUILDKIT=1 docker build \
  --build-arg UBUNTU_VERSION="${UBUNTU_VERSION}" \
  --build-arg UBUNTU_CODENAME="${UBUNTU_CODENAME}" \
  --no-cache \
  --file "${SOURCE_DIR}/Dockerfile" \
  --tag "oeciteam/openenclave-base-ubuntu-${UBUNTU_VERSION}:${IMAGE_TAG}" \
  "${BUILD_DIR}"
