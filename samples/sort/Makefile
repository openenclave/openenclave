build:
	$(MAKE) -C enc
	$(MAKE) -C host

clean:
	$(MAKE) -C enc clean
	$(MAKE) -C host clean

tests:
	host/sorthost ./enc/sortenc.signed.so
