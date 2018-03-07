# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include ../../mak/defs.mak
include $(TOP)/mak/sgx.mak

ENCLAVE = emptyenc.so 
SIGNED_ENCLAVE = emptyenc.signed.so

##==============================================================================
##
## program:
##
##==============================================================================

PROGRAM = eenter

INCLUDES += -I$(TOP)/include

SOURCES = main.cpp

LIBRARIES += $(LIBDIR)/liboehost.a

LDFLAGS += -L$(LIBDIR) -lcrypto

all:
	$(MAKE) program

include $(TOP)/mak/program.mak

##==============================================================================
##
## tests:
##
##==============================================================================

tests:
	./eenter $(SIGNED_ENCLAVE)

gdb:
	gdb ./eenter

##==============================================================================
##
## sign:
##
##==============================================================================

sign:
	cp ../empty/enc/emptyenc.so .
	$(BINDIR)/oesign $(ENCLAVE) sign.conf private.pem

