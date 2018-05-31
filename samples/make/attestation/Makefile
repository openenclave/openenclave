# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

build:
	$(MAKE) -C enc
	$(MAKE) -C host

clean:
	$(MAKE) -C enc clean
	$(MAKE) -C host clean

run:
	# Launch first enclave at port 8000.
	# Run this host in background.
	host/attestation_host ./enc/attestation_enc.signed.so -port:8000 -keep-alive:25 `hostname`:8001 < /dev/null &

	# Launch second enclave at port 8001
	# Ask it to mutually attest with enclave at localhost:8000.
	host/attestation_host ./enc/attestation_enc.signed.so -port:8001 -keep-alive:25 `hostname`:8000
