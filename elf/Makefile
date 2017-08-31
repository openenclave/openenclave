include ../mak/defs.mak

CFLAGS =

PROGRAM=$(BINDIR)/oeelf

INCLUDES = -I$(TOP)/include/host

LDFLAGS = -L$(LIBDIR)/host -lhost

SOURCES += main.c

include $(MAKDIR)/program.mak

tests:
	$(BINDIR)/oeelf ../../tests/echo/enc/echoenc.signed.so

nm:
	nm ../../tests/echo/enc/echoenc.signed.so

mc:
	valgrind --tool=memcheck $(BINDIR)/oeelf echoenc.so
