include ../../mak/defs.mak

DIRS = enc host

define NL


endef

build:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) $(NL) )

clean:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) clean $(NL) )

depend:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) depend $(NL) )

ENCLAVE = ./enc/ocallenc.signed.so

tests:
	host/ocallhost $(ENCLAVE)

mc:
	$(MEMCHECK) host/ocallhost $(ENCLAVE)

elf:
	$(MAKE) -C enc elf

gdb:
	gdb host/ocallhost -x gdb.commands

size:
	size ./enc/ocallenc.signed.so

rebuild:
	( cd $(TOP)/host; $(MAKE) clean; $(MAKE) )
	( cd $(TOP)/enclave ; $(MAKE) clean; $(MAKE) )
	$(MAKE) clean
	$(MAKE)
