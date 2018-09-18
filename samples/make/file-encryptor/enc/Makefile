# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

OPENENCLAVE_CONFIG=../../config.mak
include $(OPENENCLAVE_CONFIG)

# C++ build environment setup
CXX = clang++-7
CXXFLAGS += -Wall -Werror -g -m64 -nostdinc -fPIC -std=c++11 -nostdinc++
CXXFLAGS += -mllvm -x86-speculative-load-hardening
INCLUDES += -I$(OE_INCLUDEDIR)
INCLUDES += -I$(OE_INCLUDEDIR)/libcxx
INCLUDES += -I$(OE_INCLUDEDIR)/libc

# C build environment setup
CC = clang-7
CFLAGS += -Wall -Werror -O2 -m64 -nostdinc -fPIC
CFLAGS += -mllvm -x86-speculative-load-hardening
CINCLUDES += -I$(OE_INCLUDEDIR)
CINCLUDES += -I$(OE_INCLUDEDIR)/libc

LDFLAGS += -Wl,--no-undefined 
LDFLAGS += -nostdlib 
LDFLAGS += -nodefaultlibs 
LDFLAGS += -nostartfiles 
LDFLAGS += -Wl,-Bstatic 
LDFLAGS += -Wl,-Bsymbolic 
LDFLAGS += -Wl,--export-dynamic 
LDFLAGS += -Wl,-pie

LIBRARIES += -L${OE_LIBDIR}/openenclave/enclave 
LIBRARIES += -loeenclave
LIBRARIES += -loelibcxx
LIBRARIES += -lmbedx509 
LIBRARIES += -lmbedcrypto 
LIBRARIES += -loelibc
LIBRARIES += -loecore

all:
	$(MAKE) build
	$(MAKE) keys
	$(MAKE) sign

build:
	$(OE_BINDIR)/oeedger8r ../fileencryptor.edl --trusted
	$(CXX) -c $(CXXFLAGS) $(INCLUDES) ecalls.cpp encryptor.cpp keys.cpp
	$(CC) -c $(CFLAGS) $(CINCLUDES) fileencryptor_t.c -o fileencryptor_t.o
	$(CXX) -o file-encryptorenc.so ecalls.o encryptor.o keys.o fileencryptor_t.o $(LDFLAGS) $(LIBRARIES)

sign:
	$(OE_BINDIR)/oesign file-encryptorenc.so file-encryptor.conf private.pem

clean:
	rm -f *.so *.o fileencryptor_t.* fileencryptor_args.h private.pem public.pem

keys:
	openssl genrsa -out private.pem -3 3072
	openssl rsa -in private.pem -pubout -out public.pem
