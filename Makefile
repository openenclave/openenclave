include mak/defs.mak
.PHONY: tests
.PHONY: packages

DIRS = 3rdparty gen host elibc enclave ecrypto elf sign tests

define NL


endef

build:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) $(NL) )

clean:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) clean $(NL) )
	rm -rf bin
	rm -rf lib
	rm -rf obj

depend:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) depend $(NL) )

distclean: clean
	rm -rf include/musl
	rm -rf include/stlport
	$(MAKE) -C 3rdparty distclean
	rm -rf lib

tests:
	$(MAKE) -s -C tests tests

SOURCES = $(shell find . -name '*.[ch]') $(shell find . -name '*.cpp')

sub:
	sub $(SOURCES)

world:
	$(MAKE) -s clean
	$(MAKE)
	$(MAKE) -s -C tests tests

dist:
	@ make -s clean
	@ make -s distclean
	@ ( cd ..; tar zcf OpenEnclave.tar.gz OpenEnclave )
	@ echo "Created OpenEnclave.tar.gz"

big:
	find . -size +1000
