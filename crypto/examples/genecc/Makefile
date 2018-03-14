

all: private public

private:
	openssl ecparam -name secp256k1 -genkey -noout -out private.pem

public:
	openssl ec -in private.pem -pubout -out public.pem

names:
	openssl ecparam -list_curves

clean:
	rm -f private.key public.key
