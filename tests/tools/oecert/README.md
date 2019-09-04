oecert
=====

oecert is a utility that generates certificates (in der format) and
OE reports in binary format.  For certificates, the user can pass
in the public/private key
 1. Self-signed certificates used for remote attestation over TLS.
 2. Binary file format of an OE report.

Usage: oecert ENCLAVE_PATH Options

where Options are:
    --cert PRIVKEY PUBKEY : generate der remote attestation certificate.
    --report              : generate binary enclave report.
    --out FILENAME        : specify output filename.

Creating RSA and EC keys pairs in linux using openssl.
Generate an RSA private key, of size 2048, and output it to a file named key.pem
=====
openssl genrsa -out keyrsa.pem 2048


Extract the public key from the key pair, which can be used in a certificate:
=====
openssl rsa -in keyrsa.pem -outform PEM -pubout -out publicrsa.pem


Generate an EC private key, of size 256, and output it to a file named key.pem
=====
openssl ecparam -name prime256v1 -genkey -noout -out keyec.pem


Extract the public key from the key pair, which can be used in a certificate
=====
openssl ec -in keyec.pem -pubout -out publicec.pem
