# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

all:

/etc/apt/sources.list.d/intel-sgx.list:
	echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu xenial main' | tee /etc/apt/sources.list.d/intel-sgx.list
	wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add -
	apt-get update

clean:

install: /etc/apt/sources.list.d/intel-sgx.list
	apt-get -y install libsgx-enclave-common libsgx-enclave-common-dev libsgx-dcap-ql libsgx-dcap-ql-dev

uninstall:
	apt-get --purge remove libsgx-enclave-common libsgx-enclave-common-dev libsgx-dcap-ql libsgx-dcap-ql-dev

