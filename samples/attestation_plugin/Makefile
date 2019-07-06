# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

.PHONY: all build clean run simulate

all: build

build:
	$(MAKE) -C enclave
	$(MAKE) -C host

clean:
	$(MAKE) -C enclave clean
	$(MAKE) -C host clean

run:
	host/attestation_plugin_host ./enclave/attestation_plugin_enc.signed

simulate:
	host/attestation_plugin_host ./enclave/attestation_plugin_enc.signed --simulate