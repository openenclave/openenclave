include ../../mak/defs.mak

PROGRAM = str

INCLUDES += -I$(TOP)/include/host

SOURCES = main.c

LIBRARIES += $(LIBDIR)/host/liboehost.a

LDFLAGS += -L$(LIBDIR) -lcrypto

all:
	$(MAKE) program

CLEAN += log.txt log.bin log.hex

include $(TOP)/mak/program.mak

tests:
	./str

mc:
	$(MEMCHECK) ./str
