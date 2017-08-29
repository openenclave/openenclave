include ../../../mak/defs.mak

PROGRAM = pingponghost

SOURCES = host.cpp pingpong_u.c

include $(TOP)/mak/host.mak

gen:
	$(BINDIR)/encgen -u ../pingpong.idl
