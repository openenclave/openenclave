include ../../mak/defs.mak

PROGRAM = mem

INCLUDES += -I$(TOP)/include/host

SOURCES = main.c

#LIBRARIES += $(LIBDIR)/libhost.a

LDFLAGS += -L$(LIBDIR) -lcrypto

all:
	$(MAKE) program

CLEAN += log.txt log.bin log.hex

include $(TOP)/mak/program.mak

tests:
	./mem

mc:
	$(MEMCHECK) ./mem
