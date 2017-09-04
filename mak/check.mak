TMPDIR := $(shell /bin/mktemp -d --suffix=.oe.check)

check:
	@ $(MAKE) dist
	@ install -D $(DISTNAME).tar.gz $(TMPDIR)/$(DISTNAME).tar.gz
	@ ( cd $(TMPDIR); tar zxvf $(DISTNAME).tar.gz )
	@ ( cd $(TMPDIR)/$(DISTNAME); ./configure --prefix=$(TMPDIR)/install )
	@ ( cd $(TMPDIR)/$(DISTNAME); $(MAKE) world )
	@ ( cd $(TMPDIR)/$(DISTNAME); $(MAKE) install )
	@ ( source $(TMPDIR)/install/share/openenclave/environment; \
          cd $(TMPDIR)/install/share/openenclave/samples; \
          $(MAKE) world )
	@ rm -rf $(TMPDIR)
	@ echo "=== Check okay!"
