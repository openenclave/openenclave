# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

OPENENCLAVE_CONFIG=../config.mak
include $(OPENENCLAVE_CONFIG)

build:
	$(OE_BINDIR)/oeedger8r helloworld.edl --untrusted-dir host --trusted-dir enc
	$(MAKE) -C enc
	$(MAKE) -C host

clean:
	$(MAKE) -C enc clean
	$(MAKE) -C host clean

run:
	host/helloworldhost ./enc/helloworldenc.signed.so
