.PHONY: wraptests

include ../../mak/defs.mak

build:
	$(MAKE) -C host

TESTS=$(shell cat tests.supported)

tests: build
	$(foreach i, $(TESTS), @ $(MAKE) -s TEST=$(i) test $(NEWLINE) )

test:
	@ $(MAKE) -s -C enc clean
	@ $(MAKE) -s -C enc TEST=$(TEST)
	@ $(MAKE) -s -C enc tests
	@ $(MAKE) -s -C enc clean

clean:
	$(MAKE) -C host clean
	$(MAKE) -C enc clean

depend:

gdb:
	gdb ./host/libchost -x gdb.commands
