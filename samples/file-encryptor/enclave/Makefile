# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include ../../config.mk

CFLAGS=$(shell pkg-config oeenclave-$(C_COMPILER) --cflags)
CXXFLAGS=$(shell pkg-config oeenclave-$(CXX_COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oeenclave-$(CXX_COMPILER) --libs)

all:
	$(MAKE) build
	$(MAKE) keys
	$(MAKE) sign

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../fileencryptor.edl --trusted
	$(CXX) -g -c $(CXXFLAGS) -DOE_API_VERSION=2 -std=c++11 ecalls.cpp encryptor.cpp keys.cpp
	$(CC) -g -c $(CFLAGS) -DOE_API_VERSION=2 fileencryptor_t.c -o fileencryptor_t.o
	$(CXX) -o file-encryptorenc ecalls.o encryptor.o keys.o fileencryptor_t.o $(LDFLAGS)

sign:
	oesign sign -e file-encryptorenc -c file-encryptor.conf -k private.pem

clean:
	rm -f file-encryptorenc file-encryptorenc.signed *.o fileencryptor_t.* fileencryptor_args.h private.pem public.pem

keys:
	openssl genrsa -out private.pem -3 3072
	openssl rsa -in private.pem -pubout -out public.pem


