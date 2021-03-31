oecert
=====

oecert is a utility that generates certificates (in der format),
evidence (OE report and OE evidence), and endorsements for evidence in binary format. For certificates, the user can pass
in the public/private key.

 1. Self-signed certificates used for remote attestation over TLS.
 2. Binary file format of an OE report.
 3. Binary file format of an OE evidence.
 4. Binary file format of an endorsement.

Usage: oecert Options

where Options are:

    --cert PRIVKEY PUBKEY : generate der remote attestation certificate.
    --report              : generate binary OE report.
    --evidence            : generate binary OE evidence.
    --out FILENAME        : specify certificate/report/evidence output filename, default: out.bin
    --endorsements        : specify endorsements output filename.
    --verify              : verify generated certificate/report/evidence
    --log LOG_FILENAME    : log file name, default: oecert.log
    --verbose             : dump verbose info of evidence

Example 1 Generate, verify and dump a ceritificate, output certificate to default output file "out.bin":

    ./oecert --cert keyecec.pem publickeyec.pem --verify --verbose

Example 2 Generate an OE report and output its endorsements binary, output OE report to "report.bin":

    ./oecert --report --endorsements endorsements.bin --out report.bin

Example 3 Generate and verify an evidence, and dump evidence buffer and its verified claims, output OE evidence to "evidence.bin":

    ./oecert --evidence --verify --verbose --out evidence.bin


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
