# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include ../../../config.mk

CFLAGS=$(shell pkg-config oeenclave-$(C_COMPILER) --cflags)
CXXFLAGS=$(shell pkg-config oeenclave-$(CXX_COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oeenclave-$(CXX_COMPILER) --libs)
INCDIR=$(shell pkg-config oeenclave-$(C_COMPILER) --variable=includedir)

.PHONY: all build clean run

all:
	$(MAKE) build
	$(MAKE) sign

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../tls_server.edl --trusted \
		--trusted-dir . \
		--search-path $(INCDIR) \
		--search-path $(INCDIR)/openenclave/edl/sgx
	$(CXX) -g -c $(CXXFLAGS) $(INCLUDES) -std=c++11 ecalls.cpp server.cpp identity_verifier.cpp cert_verifier.cpp ../../common/utility.cpp
	$(CC) -c $(CFLAGS) $(CINCLUDES) tls_server_t.c
	$(CXX) -o tls_server_enc ecalls.o server.o cert_verifier.o identity_verifier.o utility.o tls_server_t.o $(LDFLAGS) -lmbedtls -lmbedcrypto -loehostsock -loehostresolver -loecore -loelibc -loesyscall

sign:
	oesign sign -e tls_server_enc -c enc.conf -k private.pem
	oesign dump -e tls_server_enc.signed > temp.dmp
	chmod u+x ../../scripts/gen_mrenclave_header.sh
	../../scripts/gen_mrenclave_header.sh ../../common/tls_server_enc_mrenclave.h temp.dmp
	rm temp.dmp

clean:
	rm -f *.o tls_server_enc tls_server_enc.signed tls_server_enc.signed.so tls_server_t.* tls_server_args.h yy ../../common/tls_server_enc_mrenclave.h
