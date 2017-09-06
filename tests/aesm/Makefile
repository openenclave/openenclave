include ../../mak/defs.mak

##==============================================================================
##
## program:
##
##==============================================================================

PROGRAM = aesm

INCLUDES += -I$(INCDIR) -I$(INCDIR)/host

SOURCES = main.cpp

LIBRARIES += $(LIBDIR)/host/liboehost.a

LDFLAGS +=

all:
	$(MAKE) program

include $(TOP)/mak/program.mak

tests:
	@ ./aesm
