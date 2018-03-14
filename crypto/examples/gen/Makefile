##
## Create a chain of certificates:
##
##     root -> intermediate -> leaf
##

all: .gen

.gen:
	$(MAKE) gen_all
	touch .gen

gen_all: root intermediate leaf chain verify

root:
	@ openssl genrsa -out root.key 2048 2> /dev/null
	@ echo "Created root.key"
	@ openssl req -sha256 -new -x509 -days 1826 -key root.key -out root.crt -config root.conf
	@ touch .gen
	@ echo "Created root.crt"

intermediate:
	@ echo 1000 > serial
	@ echo 1000 > crlnumber
	@ touch database database.attr
	@ openssl genrsa -out intermediate.key 2048 2> /dev/null
	@ echo "Created intermediate.key"
	@ openssl req -new -sha256 -key intermediate.key -out intermediate.csr -config intermediate.conf 2> /dev/null
	@ echo "Created intermediate.csr"
	@ openssl ca -batch -config root.conf -notext -in intermediate.csr -out intermediate.crt 2> /dev/null
	@ echo "Created intermediate.crt"

leaf:
	@ openssl genrsa -out leaf.key 2048 2> /dev/null
	@ echo "Created leaf.key"
	@ openssl req -new -sha256 -key leaf.key -out leaf.csr -config leaf.conf
	@ echo "Created leaf.csr"
	@ openssl ca -batch -config intermediate.conf -notext -in leaf.csr -out leaf.crt 2> /dev/null
	@ echo "Created leaf.crt"
	@ openssl ca -config intermediate.conf -gencrl -keyfile intermediate.key -cert intermediate.crt -out root.crl.pem 2> /dev/null
	@ echo "Created root.crl.pem"
	@ openssl crl -inform PEM -in root.crl.pem -outform DER -out root.crl
	@ echo "Created root.crl"

chain:
	@ cat root.crt intermediate.crt > cert.chain
	@ echo "Created cert.chain"

verify:
	@ openssl verify -CAfile cert.chain leaf.crt 

clean:
	@ rm -f *.crt *.key *.csr *.pem 
	@ rm -rf database* serial* crlnumber*
	@ rm -f root.crl
	@ rm -f cert.chain
	@ rm -f .gen

