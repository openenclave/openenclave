# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include ../../config.mk

CFLAGS=$(shell pkg-config oeenclave-$(C_COMPILER) --cflags)
CXXFLAGS=$(shell pkg-config oeenclave-$(CXX_COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oeenclave-$(CXX_COMPILER) --libs)

all:
	$(MAKE) build
	$(MAKE) sign

build:
	cp ../enclave_a_v1/private.pem .
	@ echo "Compilers used: $(CC), $(CXX)"
	$(CXX) -g -c $(CXXFLAGS) $(INCLUDES) -I.. -DOE_API_VERSION=2 -std=c++11 ecalls.cpp ../common/dispatcher.cpp ../common/keys.cpp
	$(CC) -g -c $(CFLAGS) $(CINCLUDES) -I.. -DOE_API_VERSION=2 ../common/datasealing_t.c
	$(CXX) -o enclave_a_v2 ecalls.o dispatcher.o keys.o datasealing_t.o $(LDFLAGS)

sign:
	oesign sign -e enclave_a_v2 -c data-sealing.conf -k private.pem

clean:
	rm -f enclave_a_v2 enclave_a_v2.signed *.o *.pem ../common/datasealing_t.* ../common/datasealing_args.h
