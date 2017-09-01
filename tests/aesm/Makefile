include ../../mak/defs.mak

##==============================================================================
##
## program:
##
##==============================================================================

PROGRAM = aesm

INCLUDES += -I$(HOSTINCDIR)

SOURCES = main.cpp

LIBRARIES += $(LIBDIR)/host/liboehost.a

LDFLAGS +=

all:
	$(MAKE) program

include $(TOP)/mak/program.mak

tests:
	@ ./aesm
