#!/usr/bin/make -f

# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

all: update-openssl-headers
	echo All done - please review changes

update-openssl-headers:
	perl openssl/Configure linux-x86_64 --with-rand-seed=none no-hw no-afalgeng no-aria no-autoerrinit no-autoload-config no-bf no-blake2 no-camellia no-capieng no-cast no-chacha no-cms no-ct no-dso no-gost no-idea no-md2 no-md4 no-mdc2 no-nextprotoneg no-poly1305 no-psk no-rc4 no-rfc3779 no-rmd160 no-scrypt no-seed no-shared no-siphash no-sm2 no-sm3 no-sm4 no-srp no-ssl2 no-ssl3 no-ui-console no-whirlpool no-zlib CC=clang-10 CXX=clang++-10; \
	perl "-I." -Mconfigdata "openssl/util/dofile.pl" "-oMakefile" "openssl/include/crypto/bn_conf.h.in" \
			> include/bn_conf.h; \
	perl "-I." -Mconfigdata "openssl/util/dofile.pl" "-oMakefile" "openssl/include/crypto/dso_conf.h.in" \
			> include/dso_conf.h; \
	perl "-I." -Mconfigdata "openssl/util/dofile.pl" "-oMakefile" "openssl/include/openssl/crypto.h.in" > include/crypto.h;
	perl "-I." -Mconfigdata "openssl/util/dofile.pl" "-oMakefile" "openssl/include/openssl/bio.h.in" > include/bio.h;
	perl "-I." -Mconfigdata "openssl/util/dofile.pl" "-oMakefile" "openssl/include/openssl/cmp.h.in" > include/cmp.h;
	perl "-I." -Mconfigdata "openssl/util/dofile.pl" "-oMakefile" "openssl/include/openssl/cms.h.in" > include/cms.h;
	perl "-I." -Mconfigdata "openssl/util/dofile.pl" "-oMakefile" "openssl/include/openssl/conf.h.in" > include/conf.h;
	perl "-I." -Mconfigdata "openssl/util/dofile.pl" "-oMakefile" "openssl/include/openssl/asn1.h.in" > include/asn1.h;
	perl "-I." -Mconfigdata "openssl/util/dofile.pl" "-oMakefile" "openssl/include/openssl/asn1t.h.in" > include/asn1t.h;
	perl "-I." -Mconfigdata "openssl/util/dofile.pl" "-oMakefile" "openssl/include/openssl/x509.h.in" > include/x509.h;
	perl "-I." -Mconfigdata "openssl/util/dofile.pl" "-oMakefile" "openssl/include/openssl/x509v3.h.in" > include/x509v3.h;
	perl "-I." -Mconfigdata "openssl/util/dofile.pl" "-oMakefile" "openssl/include/openssl/crmf.h.in" > include/crmf.h;
	perl "-I." -Mconfigdata "openssl/util/dofile.pl" "-oMakefile" "openssl/include/openssl/err.h.in" > include/err.h;
	perl "-I." -Mconfigdata "openssl/util/dofile.pl" "-oMakefile" "openssl/include/openssl/srp.h.in" > include/srp.h;
	perl "-I." -Mconfigdata "openssl/util/dofile.pl" "-oMakefile" "openssl/include/openssl/ssl.h.in" > include/ssl.h;
	perl "-I." -Mconfigdata "openssl/util/dofile.pl" "-oMakefile" "openssl/include/openssl/ess.h.in" > include/ess.h;
	perl "-I." -Mconfigdata "openssl/util/dofile.pl" "-oMakefile" "openssl/include/openssl/ui.h.in" > include/ui.h;
	perl "-I." -Mconfigdata "openssl/util/dofile.pl" "-oMakefile" "openssl/include/openssl/ct.h.in" > include/ct.h;
	perl "-I." -Mconfigdata "openssl/util/dofile.pl" "-oMakefile" "openssl/include/openssl/lhash.h.in" > include/lhash.h;
	perl "-I." -Mconfigdata "openssl/util/dofile.pl" "-oMakefile" "openssl/include/openssl/fipskey.h.in" > include/fipskey.h;
	perl "-I." -Mconfigdata "openssl/util/dofile.pl" "-oMakefile" "openssl/include/openssl/x509_vfy.h.in" > include/x509_vfy.h;
	perl "-I." -Mconfigdata "openssl/util/dofile.pl" "-oMakefile" "openssl/include/openssl/pkcs7.h.in" > include/pkcs7.h;
	perl "-I." -Mconfigdata "openssl/util/dofile.pl" "-oMakefile" "openssl/include/openssl/pkcs12.h.in" > include/pkcs12.h;
	perl "-I." -Mconfigdata "openssl/util/dofile.pl" "-oMakefile" "openssl/include/openssl/ocsp.h.in" > include/ocsp.h;
	perl "-I." -Mconfigdata "openssl/util/dofile.pl" "-oMakefile" "openssl/include/openssl/opensslconf.h.in" > include/opensslconf.h;
	perl "-I." -Mconfigdata "openssl/util/dofile.pl" "-oMakefile" "openssl/include/openssl/configuration.h.in" > include/configuration.h;
	perl "-I." -Mconfigdata "openssl/util/dofile.pl" "-oMakefile" "openssl/include/openssl/safestack.h.in" > include/safestack.h;
	cd openssl
	perl "-I." -Mconfigdata -Moids_to_c "util/dofile.pl" "-oMakefile" "providers/common/der/der_dsa_gen.c.in" > providers/common/der/der_dsa_gen.c;
	perl "-I." -Mconfigdata -Moids_to_c "util/dofile.pl" "-oMakefile" "providers/common/der/der_ec_gen.c.in" > providers/common/der/der_ec_gen.c;
	perl "-I." -Mconfigdata -Moids_to_c "util/dofile.pl" "-oMakefile" "providers/common/der/der_ecx_gen.c.in" > providers/common/der/der_ecx_gen.c;
	perl "-I." -Mconfigdata -Moids_to_c "util/dofile.pl" "-oMakefile" "providers/common/der/der_wrap_gen.c.in" > providers/common/der/der_wrap_gen.c;
	perl "-I." -Mconfigdata -Moids_to_c "util/dofile.pl" "-oMakefile" "providers/common/der/der_rsa_gen.c.in" > providers/common/der/der_rsa_gen.c;
	perl "-I." -Mconfigdata -Moids_to_c "util/dofile.pl" "-oMakefile" "providers/common/der/der_sm2_gen.c.in" > providers/common/der/der_sm2_gen.c;
	perl "-I." -Mconfigdata -Moids_to_c "util/dofile.pl" "-oMakefile" "providers/common/include/prov/der_digests.h.in" > ../include/prov/der_digests.h;
	perl "-I." -Mconfigdata -Moids_to_c "util/dofile.pl" "-oMakefile" "providers/common/include/prov/der_dsa.h.in" > ../include/prov/der_dsa.h;
	perl "-I." -Mconfigdata -Moids_to_c "util/dofile.pl" "-oMakefile" "providers/common/include/prov/der_ec.h.in" > ../include/prov/der_ec.h;
	perl "-I." -Mconfigdata -Moids_to_c "util/dofile.pl" "-oMakefile" "providers/common/include/prov/der_ecx.h.in" > ../include/prov/der_ecx.h;
	perl "-I." -Mconfigdata -Moids_to_c "util/dofile.pl" "-oMakefile" "providers/common/include/prov/der_rsa.h.in" > ../include/prov/der_rsa.h;
	perl "-I." -Mconfigdata -Moids_to_c "util/dofile.pl" "-oMakefile" "providers/common/include/prov/der_sm2.h.in" > ../include/prov/der_sm2.h;
	perl "-I." -Mconfigdata -Moids_to_c "util/dofile.pl" "-oMakefile" "providers/common/include/prov/der_wrap.h.in" > ../include/prov/der_wrap.h;
  