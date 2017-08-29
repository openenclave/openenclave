include ../../../mak/defs.mak

PROGRAM = testerhost

SOURCES = host.cpp tester_u.c

include $(TOP)/mak/host.mak

gen:
	$(BINDIR)/encgen -u ../tester.idl
