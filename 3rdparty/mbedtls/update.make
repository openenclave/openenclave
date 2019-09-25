#!/usr/bin/make -f

# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# mbedTLS library definitions
VERSION=2.16.2
BASE=mbedtls-$(VERSION)
PKG=$(BASE)-apache.tgz

all: update-mbedtls
	echo All done - please review changes

update-mbedtls:
	rm -rf mbedtls $(PKG)
	wget https://tls.mbed.org/download/$(PKG)
	tar zxf $(PKG)
	mv $(BASE) mbedtls
	rm -rf $(PKG)
	rm mbedtls/.gitignore
	rm mbedtls/programs/.gitignore
	rm mbedtls/include/.gitignore
	rm mbedtls/library/.gitignore
	rm mbedtls/tests/.gitignore
	rm mbedtls/tests/data_files/.gitignore
