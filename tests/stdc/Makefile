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

ENCLAVE = ./enc/stdcenc.signed.so

tests:
	host/stdchost $(ENCLAVE)

mc:
	$(MEMCHECK) host/stdchost $(ENCLAVE)

elf:
	$(MAKE) -C enc elf

gdb:
	gdb host/stdchost -x gdb.commands

size:
	size $(ENCLAVE)
