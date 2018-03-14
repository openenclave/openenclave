.PHONY: verify
.PHONY: main
.PHONY: sample

all: gen
	g++ -Wall -o main main.cpp -lssl -lcrypto

gen:
	$(MAKE) -C ../gen

tests:
	@ ./main ../gen/leaf.crt ../gen/cert.chain

bad:
	@ ./main ../gen/leaf.crt ../gen/bad.cert.chain

clean:
	@ rm -f main
