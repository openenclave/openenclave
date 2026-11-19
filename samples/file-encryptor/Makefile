# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

.PHONY: all build clean run simulate

OE_CRYPTO_LIB := openssl_3
export OE_CRYPTO_LIB

TARGETS =

SYMCRYPT_TAR = symcrypt-linux-oe_full-AMD64-103.0.1-69dbff3.tar.gz
SYMCRYPT_URL = https://github.com/microsoft/SymCrypt/releases/download/v103.0.1/${SYMCRYPT_TAR}
SYMCRYPT_SHA256 = 27C8C1C309B217E74D6055734D305AA86D8CE9E05D6D75AFD12C885F13CEA710
SYMCRYPT_DIR = SymCrypt
SYMCRYPT_SO = libsymcrypt.so.103.0.1
# The linker can only resolve up to single number after .so
SYMCRYPT_LINK_SO = libsymcrypt.so.103

ifeq (${OE_CRYPTO_LIB}, openssl_symcrypt_fips)
	TARGETS += symcrypt
endif

TARGETS += build

all: ${TARGETS}

symcrypt:
	wget ${SYMCRYPT_URL}
	echo "${SYMCRYPT_SHA256} ${SYMCRYPT_TAR}" | sha256sum --check
	mkdir -p ${SYMCRYPT_DIR}
	tar zxvf ${SYMCRYPT_TAR} -C ${SYMCRYPT_DIR}
	rm ${SYMCRYPT_TAR}
	cp ${SYMCRYPT_DIR}/lib/${SYMCRYPT_SO} enclave/${SYMCRYPT_LINK_SO}

build:
	make symcrypt
	$(MAKE) -C enclave
	$(MAKE) -C host

clean:
	$(MAKE) -C enclave clean
	$(MAKE) -C host clean
	rm -rf ${SYMCRYPT_DIR}
	rm -f enclave/${SYMCRYPT_LINK_SO}

run:
	host/file-encryptorhost testfile ./enclave/file-encryptorenc.signed

simulate:
	host/file-encryptorhost testfile ./enclave/file-encryptorenc.signed --simulate

