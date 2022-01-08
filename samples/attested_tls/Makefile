# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

.PHONY: all symcrypt build clean run

# set OE_CRYPTO_LIB to either "mbedtls" or "openssl" based on the crypto wrapper to be used.
# OE_CRYPTO_LIB is case sensitive. Use all lowercase letters.
OE_CRYPTO_LIB := mbedtls
export OE_CRYPTO_LIB

TARGETS =

SYMCRYPT_TAR = symcrypt_AMD64_openenclave_100.20.0-31fb2e94-pre.tgz
SYMCRYPT_URL = https://github.com/microsoft/SymCrypt/releases/download/SymCrypt_v100.20_master_2021-12-01T112555-0800_31fb2e9/${SYMCRYPT_TAR}
SYMCRYPT_SHA256 = 8d08f459e57751cd94580395922be905f51c172dd06f3ea0db403febb7b53e3e
SYMCRYPT_DIR = SymCrypt
SYMCRYPT_SO = libsymcrypt.so

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
	cp ${SYMCRYPT_DIR}/lib/${SYMCRYPT_SO} server/enc
	cp ${SYMCRYPT_DIR}/lib/${SYMCRYPT_SO} client/enc

build:
	echo ${OE_CRYPTO_LIB}
	$(MAKE) -C server
	$(MAKE) -C client
	$(MAKE) -C non_enc_client

clean:
	$(MAKE) -C server clean
	$(MAKE) -C client clean
	$(MAKE) -C non_enc_client clean
	rm -rf ${SYMCRYPT_DIR}
	rm -f server/enc/${SYMCRYPT_SO}
	rm -f client/enc/${SYMCRYPT_SO}

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
