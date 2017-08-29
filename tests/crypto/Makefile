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

ENCLAVE = ./enc/cryptoenc.signed.so

tests:
	host/cryptohost $(ENCLAVE)

mc:
	$(MEMCHECK) host/cryptohost $(ENCLAVE)

elf:
	$(MAKE) -C enc elf

gdb:
	gdb host/cryptohost -x gdb.commands

size:
	size $(ENCLAVE)
