include ../../mak/defs.mak

PROGRAM = tsearch

INCLUDES += -I$(INCDIR) -I$(INCDIR)/host

SOURCES = $(wildcard *.c)

LIBRARIES += $(LIBDIR)/host/liboehost.a

LDFLAGS += -L$(LIBDIR) -lcrypto

all:
	$(MAKE) program

search.o: search.c
	gcc $(CFLAGS) $(DEFINES) $(INCLUDES) -I./include -c search.c

tdestroy.o: tdestroy.c
	gcc $(CFLAGS) $(DEFINES) $(INCLUDES) -I./include -c tdestroy.c

CLEAN += log.txt log.bin log.hex

include $(TOP)/mak/program.mak

tests:
	./tsearch
