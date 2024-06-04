# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

.PHONY: all symcrypt build clean run

# set OE_CRYPTO_LIB to either "mbedtls" or "openssl" based on the crypto wrapper to be used.
# OE_CRYPTO_LIB is case sensitive. Use all lowercase letters.
OE_CRYPTO_LIB := mbedtls
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
	cp ${SYMCRYPT_DIR}/lib/${SYMCRYPT_SO} server/enc/${SYMCRYPT_LINK_SO}
	cp ${SYMCRYPT_DIR}/lib/${SYMCRYPT_SO} client/enc/${SYMCRYPT_LINK_SO}

build:
	make symcrypt
	echo ${OE_CRYPTO_LIB}
	$(MAKE) -C server
	$(MAKE) -C client
	$(MAKE) -C non_enc_client

clean:
	$(MAKE) -C server clean
	$(MAKE) -C client clean
	$(MAKE) -C non_enc_client clean
	rm -rf ${SYMCRYPT_DIR}
	rm -f server/enc/${SYMCRYPT_LINK_SO}
	rm -f client/enc/${SYMCRYPT_LINK_SO}

run:
	echo "Launch processes to establish an Attested TLS between two enclaves"
	./server/host/tls_server_host ./server/enc/tls_server_enc.signed -port:12341 &
	sleep 2
	./client/host/tls_client_host ./client/enc/tls_client_enc.signed -server:localhost -port:12341
	echo "Launch processes to establish an Attested TLS between an non-encalve TLS client and an TLS server running inside an enclave"
	./server/host/tls_server_host ./server/enc/tls_server_enc.signed -port:12345 &
	sleep 2
	./non_enc_client/tls_non_enc_client -server:localhost -port:12345

run-server-in-loop:
	echo "Launch long-running Attested TLS server"
	./server/host/tls_server_host ./server/enc/tls_server_enc.signed -port:12341 -server-in-loop
