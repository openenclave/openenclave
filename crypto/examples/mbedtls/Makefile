.PHONY: verify
.PHONY: main
.PHONY: sample

INCLUDES = -I ../../../include

all: gen
	g++ $(INCLUDES) -DOE_Memset=memset -Wall -o main main.cpp -L/usr/local/lib -lmbedx509 -lmbedtls -lmbedcrypto

gen:
	$(MAKE) -C ../gen

tests:
	@ ./main ../gen/leaf.crt ../gen/cert.chain

bad:
	@ ./main ../gen/leaf.crt ../gen/bad.cert.chain

clean:
	@ rm -f main
