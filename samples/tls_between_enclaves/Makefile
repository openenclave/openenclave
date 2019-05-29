# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

all: build

build:
	$(MAKE) -C server
	$(MAKE) -C client
clean:
	$(MAKE) -C server clean
	$(MAKE) -C client clean

run:
	host/tls_attestation_host ./enc1/enclave1.signed ./enc2/enclave2.signed

run:
	./server/host/tls_server_host ./server/enc/tls_server_enc.signed -port:12341 &
	sleep 2
	./client/host/tls_client_host ./client/enc/tls_client_enclave.signed -server:localhost -port:12341
