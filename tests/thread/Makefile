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

ENCLAVE = ./enc/threadenc.signed.so

tests:
	host/threadhost $(ENCLAVE)

mc:
	$(MEMCHECK) host/threadhost $(ENCLAVE)

elf:
	$(MAKE) -C enc elf

gdb:
	gdb host/threadhost -x gdb.commands

size:
	size $(ENCLAVE)
