# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

build:
	$(MAKE) -C enclave_a_v1
	$(MAKE) -C enclave_a_v2
	$(MAKE) -C enclave_b
	$(MAKE) -C host

clean:
	$(MAKE) -C enclave_a_v1 clean
	$(MAKE) -C enclave_a_v2 clean
	$(MAKE) -C enclave_b clean
	$(MAKE) -C host clean

run:
	host/data-sealing_host ./enclave_a_v1/enclave_a_v1.signed  ./enclave_a_v2/enclave_a_v2.signed  ./enclave_b/enclave_b.signed
