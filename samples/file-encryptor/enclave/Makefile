# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include ../../config.mk

CFLAGS=$(shell pkg-config oeenclave-$(C_COMPILER) --cflags)
CXXFLAGS=$(shell pkg-config oeenclave-$(CXX_COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oeenclave-$(CXX_COMPILER) --libs)
INCDIR=$(shell pkg-config oeenclave-$(C_COMPILER) --variable=includedir)
CRYPTO_LDFLAGS=$(shell pkg-config oeenclave-$(COMPILER) --variable=${OE_CRYPTO_LIB}libs)

CRYPTO_SRC = $(OE_CRYPTO_LIB)_src
CXXINCDIR = -I. -I../ -I../..
CXXSRCS = common/ecalls.cpp \
	  $(CRYPTO_SRC)/encryptor.cpp \
	  $(CRYPTO_SRC)/keys.cpp \

all:
	$(MAKE) build
	$(MAKE) keys
	$(MAKE) sign

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../fileencryptor.edl --trusted \
		--search-path $(INCDIR) \
		--search-path $(INCDIR)/openenclave/edl/sgx
	$(CXX) -g -c $(CXXFLAGS) -DOE_API_VERSION=2 -std=c++11 $(CXXINCDIR) \
		$(CXXSRCS)
	$(CC) -g -c $(CFLAGS) -DOE_API_VERSION=2 fileencryptor_t.c -o fileencryptor_t.o
	$(CXX) -o file-encryptorenc ecalls.o encryptor.o keys.o fileencryptor_t.o $(LDFLAGS) $(CRYPTO_LDFLAGS)

sign:
	oesign sign -e file-encryptorenc -c common/file-encryptor.conf -k private.pem

clean:
	rm -f file-encryptorenc file-encryptorenc.signed *.o fileencryptor_t.* fileencryptor_args.h private.pem public.pem

keys:
	openssl genrsa -out private.pem -3 3072
	openssl rsa -in private.pem -pubout -out public.pem


