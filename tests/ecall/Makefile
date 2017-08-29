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

ENCLAVE = ./enc/ecallenc.signed.so

tests:
	host/ecallhost $(ENCLAVE)

mc:
	$(MEMCHECK) host/ecallhost $(ENCLAVE)

elf:
	$(MAKE) -C enc elf

gdb:
	gdb host/ecallhost -x gdb.commands
