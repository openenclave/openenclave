# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

all: build

build:
	$(MAKE) -C enclave_a
	$(MAKE) -C enclave_b
	$(MAKE) -C host

clean:
	$(MAKE) -C enclave_a clean
	$(MAKE) -C enclave_b clean
	$(MAKE) -C host clean

run:
	host/attestation_host ./enclave_a/enclave1.signed ./enclave_b/enclave2.signed
