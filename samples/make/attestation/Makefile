# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

SKIPPED=$(shell expr $(OE_SIMULATION) + $(USE_LIBSGX))

build:
	$(MAKE) -C enc
	$(MAKE) -C host

clean:
	$(MAKE) -C enc clean
	$(MAKE) -C host clean

run:
ifeq ($(SKIPPED),2)
	@ echo "Skipping samples attestation run"
else
	host/attestation_host ./enc/attestation_enc.signed.so
endif



