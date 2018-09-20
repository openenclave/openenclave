# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

OPENENCLAVE_CONFIG=../../config.mak
include $(OPENENCLAVE_CONFIG)

define optlib
$(patsubst /usr/lib/lib%.so,-l%,$(wildcard /usr/lib/lib$(1).so))
endef

all: build

CXX = clang++-7

CXXFLAGS += -Wall -O2
CXXFLAGS += -mllvm -x86-speculative-load-hardening

INCLUDES = -I$(OE_INCLUDEDIR)

LDFLAGS += -rdynamic

LIBRARIES += -L$(OE_LIBDIR)/openenclave/host
LIBRARIES += -loehost
LIBRARIES += -lcrypto
LIBRARIES += -lpthread
LIBRARIES += -ldl
# Note: Do not insert space after comma as it's included in the
# call to optlib as part of the $1 parameter
LIBRARIES += $(call optlib,sgx_enclave_common)
LIBRARIES += $(call optlib,sgxoeql)
LIBRARIES += $(call optlib,sgx_urts)

build:
	$(CXX) -c $(CXXFLAGS) $(INCLUDES) host.cpp
	$(CXX) -o sorthost host.o $(LDFLAGS) $(LIBRARIES)

clean:
	rm -f sorthost host.o

