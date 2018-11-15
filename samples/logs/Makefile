# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

build:
	$(MAKE) -C enc
	$(MAKE) -C host

clean:
	$(MAKE) -C enc clean
	$(MAKE) -C host clean

run:
	host/logshost ./enc/logsenc.signed.so

simulate:
	host/logshost ./enc/logsenc.signed.so --simulate

