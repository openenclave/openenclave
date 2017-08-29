include ../mak/defs.mak

CFLAGS =

PROGRAM=$(BINDIR)/encelf

INCLUDES = -I$(TOP)/include/host

LDFLAGS = -L$(LIBDIR)/host -lhost

SOURCES += main.c

include $(MAKDIR)/program.mak

tests:
	$(BINDIR)/encelf ../../tests/echo/enc/echoenc.signed.so

nm:
	nm ../../tests/echo/enc/echoenc.signed.so

mc:
	valgrind --tool=memcheck $(BINDIR)/encelf echoenc.so
