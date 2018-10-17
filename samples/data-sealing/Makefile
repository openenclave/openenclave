# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

build:
	$(MAKE) -C enc
	$(MAKE) -C host

clean:
	$(MAKE) -C enc clean
	$(MAKE) -C host clean

run:
	host/data-sealing_host ./enc/enclave_a_v1.signed.so  ./enc/enclave_a_v2.signed.so  ./enc/enclave_b.signed.so
