# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

.PHONY: all build clean run

all: build

build:
	$(MAKE) -C enclave_a
	$(MAKE) -C enclave_b
	$(MAKE) -C host

clean:
	$(MAKE) -C enclave_a clean
	$(MAKE) -C enclave_b clean
	$(MAKE) -C host clean

run: runsgxlocal runsgxremote

runsgxlocal:
	host/attestation_host sgxlocal ./enclave_a/enclave_a.signed ./enclave_b/enclave_b.signed

runsgxremote:
	host/attestation_host sgxremote ./enclave_a/enclave_a.signed ./enclave_b/enclave_b.signed
