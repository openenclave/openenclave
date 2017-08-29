include ../../../mak/defs.mak

PROGRAM = filehost

SOURCES = host.cpp file_u.c

include $(TOP)/mak/host.mak

gen:
	$(BINDIR)/encgen -u ../file.idl
