build:
	$(MAKE) -C enc
	$(MAKE) -C host

clean:
	$(MAKE) -C enc clean
	$(MAKE) -C host clean

tests:
	host/hellohost ./enc/helloenc.signed.so
