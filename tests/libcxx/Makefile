.PHONY: wraptests

include ../../mak/defs.mak

build:
	$(MAKE) -C host

TESTS=$(shell cat tests.supported)

tests: build
	$(foreach i, $(TESTS), @ $(MAKE) -s TEST=$(i) test $(NEWLINE) )

test:
	@ rm -f enc/main.o enc/*.so
	@ $(MAKE) -s -C enc TEST=$(TEST)
	@ $(MAKE) -s -C enc tests

clean:
	$(MAKE) -C host clean
	$(MAKE) -C enc clean

depend:
