all:
	$(MAKE) -C musl
	$(MAKE) -C musl install
	$(MAKE) -C libcxx
	$(MAKE) -C libcxx install

clean:
	$(MAKE) -C musl clean
	$(MAKE) -C libcxx clean

distclean:
	$(MAKE) -C musl distclean
	$(MAKE) -C libcxx distclean
	$(MAKE) -C samples clean
