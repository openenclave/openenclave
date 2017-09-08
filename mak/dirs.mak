ifndef NEWLINE
$(error NEWLINE is undefined)
endif

build:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) $(NEWLINE) )

clean:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) clean $(NEWLINE) )

distclean:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) distclean $(NEWLINE) )

depend:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) depend $(NEWLINE) )
