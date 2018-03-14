

all:
	$(MAKE) -C gen
	$(MAKE) -C openssl
	$(MAKE) -C mbedtls

clean:
	$(MAKE) -C gen clean
	$(MAKE) -C openssl clean
	$(MAKE) -C mbedtls clean

tests:
	@ $(MAKE) -s -C openssl tests
	@ $(MAKE) -s -C mbedtls tests
