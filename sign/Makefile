include ../mak/defs.mak

PROGRAM = $(BINDIR)/encsign

INCLUDES += -I$(TOP)/include/host

SOURCES = main.c

LIBRARIES += $(LIBDIR)/host/libhost.a

LDFLAGS += -L$(LIBDIR) -lcrypto -lpthread

all:
	$(MAKE) program

CLEAN += log.txt pages.bin out err echoenc.signed.so private.pem

include $(TOP)/mak/program.mak

tests:

update:
	cp /tmp/log.txt log.txt
	cp /tmp/log.bin pages.bin
	cp ../../tests/echo/enc/echoenc.signed.so .
	cp ../../tests/echo/enc/private.pem .

ntests:
	@ $(BINDIR)/encsign echoenc.signed.so sign.conf private.pem > out 2>> err

redo:
	$(MAKE) -C ../../tests/echo redo
	$(MAKE) update
	$(MAKE) ntests
	diff log.txt out

N=100
SEQ=$(shell seq 1 $(N))

define NL


endef

n:
	$(foreach i, $(SEQ), $(MAKE) redo $(NL) )

mc:
	$(MEMCHECK) $(BINDIR)/encsign echoenc.signed.so sign.conf private.pem

etests:
	$(BINDIR)/encsign ../../tests/echo/enc/echoenc.signed.so sign.conf ../../tests/echo/enc/private.pem

