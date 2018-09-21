# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

OPENENCLAVE_CONFIG=../../config.mak
include $(OPENENCLAVE_CONFIG)

# C++ build environment setup
CXX = clang++-7
CXXFLAGS += -Wall -Werror  -m64 -nostdinc -fPIC -std=c++11 -nostdinc++
CXXFLAGS += -mllvm -x86-speculative-load-hardening
INCLUDES += -I$(OE_INCLUDEDIR)
INCLUDES += -I$(OE_INCLUDEDIR)/libcxx
INCLUDES += -I$(OE_INCLUDEDIR)/libc

# C build environment setup
CC = clang-7
CFLAGS += -Wall -Werror  -m64 -nostdinc -fPIC
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

OE_LIBS1 =  -Wl,--start-group -Wl,--whole-archive -loeenclave -loecore -Wl,--end-group
OE_LIBS2 =  -loelibcxx -loelibc -lmbedtls -lmbedx509 -lmbedcrypto

LIBRARIES = -L${OE_LIBDIR}/openenclave/enclave ${OE_LIBS1} ${OE_LIBS2}

all:
	$(MAKE) build
	$(MAKE) sign

build:
	$(OE_BINDIR)/oeedger8r ../remoteattestation.edl --trusted --trusted-dir ../common
	$(CXX) -g -c $(CXXFLAGS) $(INCLUDES) ecalls.cpp ../common/attestation.cpp ../common/crypto.cpp ../common/dispatcher.cpp
	$(CC) -c $(CFLAGS) $(CINCLUDES) ../common/remoteattestation_t.c	
	$(CXX) -o enclave1.so attestation.o crypto.o ecalls.o dispatcher.o remoteattestation_t.o $(LDFLAGS) $(LIBRARIES)

sign:
	$(OE_BINDIR)/oesign enclave1.so enc.conf private.pem

clean:
	rm -f *.o *.so ../common/remoteattestation_t.* ../common/remoteattestation_args.h
