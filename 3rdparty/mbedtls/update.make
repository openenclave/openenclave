#!/usr/bin/make -f

# mbedTLS library definitions
VERSION=2.6.0
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
	rm mbedtls/yotta/.gitignore
	rm mbedtls/programs/.gitignore
	rm mbedtls/include/.gitignore
	rm mbedtls/library/.gitignore
	rm mbedtls/tests/.gitignore
	rm mbedtls/tests/data_files/.gitignore
