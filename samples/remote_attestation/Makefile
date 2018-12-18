# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

all: build

genkey:
	$(MAKE) -C enc1 genkey
	$(MAKE) -C enc2 genkey

build:
	$(MAKE) -C enc1
	$(MAKE) -C enc2	
	$(MAKE) -C host

clean:
	$(MAKE) -C enc1 clean
	$(MAKE) -C enc2 clean
	$(MAKE) -C host clean

run:
	host/attestation_host ./enc1/enclave1.signed.so ./enc2/enclave2.signed.so
