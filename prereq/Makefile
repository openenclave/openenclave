DIRS = packages isgx aesm

define NL


endef

all:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) $(NL) )

install:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) install $(NL) )

clean:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) clean $(NL) )

distclean:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) distclean $(NL) )
