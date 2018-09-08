# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

OPENENCLAVE_CONFIG=../../config.mak
include $(OPENENCLAVE_CONFIG)

CXXFLAGS = -Wall -Werror -g -m64 -nostdinc -fPIC -std=c++11 -nostdinc++

# To include Open Enclave SDK headers and
# Open Enclave compatible mbedtls headers.
INCLUDES += -I$(OE_INCLUDEDIR)

#  To use Open Enclave compatible C and C++ standard libraries.
INCLUDES += -I$(OE_INCLUDEDIR)/libcxx
INCLUDES += -I$(OE_INCLUDEDIR)/libc

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
	g++ -g -c $(CXXFLAGS) $(INCLUDES) ecalls.cpp ../common/attestation.cpp ../common/crypto.cpp ../common/dispatcher.cpp
	g++ -o enclave1.so attestation.o crypto.o ecalls.o dispatcher.o $(LDFLAGS) $(LIBRARIES)

sign:
	$(OE_BINDIR)/oesign enclave1.so enc.conf private.pem

clean:
	rm -f ecalls.o attestation.o crypto.o dispatcher.o enclave1.so enclave1.signed.so


