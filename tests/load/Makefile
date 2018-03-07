# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include ../../mak/defs.mak

##==============================================================================
##
## program:
##
##==============================================================================

PROGRAM = load

INCLUDES += -I$(INCDIR) -I$(INCDIR)/host

SOURCES = main.cpp

LIBRARIES += $(LIBDIR)/host/liboehost.a

LDFLAGS += -L$(LIBDIR) -lcrypto -lpthread -ldl

all:
	$(MAKE) program

CLEAN += log.txt log.bin log.hex pages.bin

include $(TOP)/mak/program.mak

##==============================================================================
##
## tests:
##
##==============================================================================

tests:

t:
	./load testload.signed.so

##==============================================================================
##
## sign:
##
##==============================================================================

sign:
	$(BINDIR)/oesign testload.so sign.conf private.pem

##==============================================================================
##
## mc:
##
##==============================================================================

mc:
	$(MEMCHECK) ./load ../echo/enc/echoenc.signed.so

