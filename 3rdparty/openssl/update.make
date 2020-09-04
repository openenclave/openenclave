#!/usr/bin/make -f

# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

all: update-openssl-headers
	echo All done - please review changes

update-openssl-headers:
	perl openssl/Configure linux-x86_64 --with-rand-seed=none no-hw \
									no-afalgeng no-aria no-autoerrinit no-autoload-config \
									no-bf no-blake2 no-camellia no-capieng no-cast no-chacha \
									no-cms no-ct no-dso no-gost no-idea no-md2 no-md4 no-mdc2 no-nextprotoneg \
									no-poly1305 no-psk no-rc4 no-rfc3779 no-rmd160 no-scrypt no-seed \
									no-shared no-siphash no-sm2 no-sm3 no-sm4 no-srp no-ssl2 no-ssl3 \
									no-threads no-ui-console no-whirlpool no-zlib CC=clang-7 CXX=clang++-7; \
	perl "-I." -Mconfigdata "openssl/util/dofile.pl" "-oMakefile" "openssl/include/crypto/bn_conf.h.in" \
			> bn_conf.h; \
	perl "-I." -Mconfigdata "openssl/util/dofile.pl" "-oMakefile" "openssl/include/crypto/dso_conf.h.in" \
			> dso_conf.h; \
	perl "-I." -Mconfigdata "openssl/util/dofile.pl" "-oMakefile" "openssl/include/openssl/opensslconf.h.in" \
			> opensslconf.h; )
