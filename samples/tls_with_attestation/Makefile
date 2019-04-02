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
	# Launch first enclave at port 8000.
	# Ask it to attest enclave at localhost:8001.
	# Run this host in background.
	./server/host/tls_server_host ./server/enc/tls_server_enc.signed.so -port:8000 -keep-alive:6 `hostname`:8001 < /dev/null &

	# Launch second enclave at port 8001
	# Ask it to mutually attest with enclave at localhost:8000.
	./client/host/tls_client_host ./client/enc/tls_client_enc.signed.so -port:8000 -keep-alive:6 `hostname`:8001 < /dev/null &
#	host/attestation_host ./enc/attestation_enc.signed.so -port:8001 -keep-alive:6 `hostname`:8000
