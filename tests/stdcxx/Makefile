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

ENCLAVE = ./enc/stdcxxenc.signed.so

tests:
	host/stdcxxhost $(ENCLAVE)

mc:
	$(MEMCHECK) host/stdcxxhost $(ENCLAVE)

elf:
	$(MAKE) -C enc elf

gdb:
	gdb host/stdcxxhost -x gdb.commands

size:
	size $(ENCLAVE)

vaddr:
	readelf -S $(ENCLAVE) | grep "\.text"
