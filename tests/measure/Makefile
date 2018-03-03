# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include ../../mak/defs.mak
include $(TOP)/mak/sgx.mak

##==============================================================================
##
## program:
##
##==============================================================================

PROGRAM = measure

INCLUDES += -I$(TOP)/include

SOURCES = main.cpp

LIBRARIES += $(LIBDIR)/liboehost.a

LDFLAGS += -L$(LIBDIR) -lcrypto

all:
	$(MAKE) program

include $(TOP)/mak/program.mak

tests:
	./measure log.txt log.bin
