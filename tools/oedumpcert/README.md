oedumpcert
==========

This directory contains the **oedumpcert** utility which dumps the contents
of a PEM certificate or PEM certificate chain. It is intended only as a test 
utility for the Open Enclave crypto feature. Use the **openssl** utility to 
get a more complete dump. For example:

```
# openssl x509 -in cert.pem -text -noout
```

The **oedumpcert** utility takes a single command-line argument as shown below.

```
# oedumpcert cert.pem
OE_Cert
{
    subject=/CN=Test Leaf/ST=Texas/C=US/O=Microsoft/OU=OpenEnclave
    ...
    RSAPublicKey
    {
        modulus=00E8CB034B543FF4B0F8BF4AA3028BF783C97B6064F6ED1879E45AD33D4FC88A0B544DCA09E38B42E7A8EE04306A1D2CFD9035E77960824CADDD58CC3940B91414B9872EFD55CA089EBAD2F431BC3ED6419370286C371404D8A95882799687E28E9A62B9115FAF81ED30DF5360985F5A76AEEE9B9EA795FF1DE5B4937FC7A31F3E47A19DBBBE1091320B56B0E1E84717CCB52F5D716ED1B8BFA4386805E5BE1C6C4AF28B7EC232ADFCD8E761CDCA96B350543CC10C4A57C797A75856E8C37ECEE9169BFA21C292F398BC97B5B60253A48EB9422EBCF17737FCD173677940DCF113FB12A38F3052D701EBBA60AEF4BDEE8092776551F01E50D0F6EF6A4D11E51987
        exponent=00010001
    }
    ...
}
```
