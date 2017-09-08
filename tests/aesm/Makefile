include ../../mak/defs.mak

##==============================================================================
##
## program:
##
##==============================================================================

PROGRAM = aesm

INCLUDES += -I$(INCDIR)

SOURCES = main.cpp

LIBRARIES += $(LIBDIR)/host/liboehost.a

LDFLAGS +=

all:
	$(MAKE) program

include $(TOP)/mak/program.mak

ifneq ($(OE_SIMULATION),1)
tests:
	@ ./aesm
endif
