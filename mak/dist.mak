TMPDIR := $(shell /bin/mktemp -d --suffix=.oe.dist)

dist:
	@ ( cd ..; cp -r openenclave $(TMPDIR)/$(DISTNAME) )
	@ $(MAKE) -C $(TMPDIR)/$(DISTNAME) -s distclean
	@ ( cd $(TMPDIR); tar zcf $(TOP)/$(DISTNAME).tar.gz $(DISTNAME) )
	@ echo "Created $(TOP)/$(DISTNAME).tar.gz"
	@ rm -rf $(TMPDIR)
