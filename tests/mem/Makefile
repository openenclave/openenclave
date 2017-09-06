include ../../mak/defs.mak

PROGRAM = mem

INCLUDES += -I$(INCDIR) -I$(INCDIR)/host

SOURCES = main.c

#LIBRARIES += $(LIBDIR)/liboehost.a

LDFLAGS += -L$(LIBDIR) -lcrypto

all:
	$(MAKE) program

CLEAN += log.txt log.bin log.hex

include $(TOP)/mak/program.mak

tests:
	./mem

mc:
	$(MEMCHECK) ./mem
