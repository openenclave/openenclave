# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

build:
	$(MAKE) -C enc1
	$(MAKE) -C enc2
	$(MAKE) -C enc3
	$(MAKE) -C host

clean:
	$(MAKE) -C enc1 clean
	$(MAKE) -C enc2 clean
	$(MAKE) -C enc3 clean
	$(MAKE) -C host clean

run:
	host/data-sealing_host ./enc1/enclave_a_v1.signed  ./enc2/enclave_a_v2.signed  ./enc3/enclave_b.signed 
