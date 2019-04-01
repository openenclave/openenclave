# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

build:
	$(MAKE) -C enclave
	$(MAKE) -C host

clean:
	$(MAKE) -C enclave clean
	$(MAKE) -C host clean

run:
	host/file-encryptorhost testfile ./enclave/file-encryptorenc.signed

simulate:
	host/file-encryptorhost testfile ./enclave/file-encryptorenc.signed --simulate

