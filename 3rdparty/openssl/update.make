#!/usr/bin/make -f

# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

all: update-openssl-headers update-openssl_3-headers
	echo All done - please review changes

update-openssl-headers:
	perl openssl/Configure linux-x86_64 --with-rand-seed=none no-hw \
									no-afalgeng no-aria no-autoerrinit no-autoload-config \
									no-bf no-blake2 no-camellia no-capieng no-cast no-chacha \
									no-cms no-ct no-dso no-gost no-idea no-md2 no-md4 no-mdc2 no-nextprotoneg \
									no-poly1305 no-psk no-rc4 no-rfc3779 no-rmd160 no-scrypt no-seed \
									no-shared no-siphash no-sm2 no-sm3 no-sm4 no-srp no-ssl2 no-ssl3 \
									no-ui-console no-whirlpool no-zlib CC=clang-11 CXX=clang++-11; \
	perl "-I." -Mconfigdata "openssl/util/dofile.pl" "-oMakefile" "openssl/include/crypto/bn_conf.h.in" \
			> include/bn_conf.h; \
	perl "-I." -Mconfigdata "openssl/util/dofile.pl" "-oMakefile" "openssl/include/crypto/dso_conf.h.in" \
			> include/dso_conf.h; \
	perl "-I." -Mconfigdata "openssl/util/dofile.pl" "-oMakefile" "openssl/include/openssl/opensslconf.h.in" \
			> include/opensslconf.h; \

update-openssl_3-headers:
	perl openssl_3/Configure linux-x86_64 --with-rand-seed=rdcpu \
			no-afalgeng no-aria no-autoerrinit no-autoload-config \
			no-bf no-blake2 no-camellia no-capieng no-cast no-chacha no-cmp \
			no-cms no-ct no-dso no-gost no-idea no-legacy no-md2 no-md4 no-mdc2 no-nextprotoneg \
			no-padlockeng no-poly1305 no-psk no-rc4 no-rfc3779 no-rmd160 no-scrypt no-seed \
			no-shared no-siphash no-siv no-sm2 no-sm3 no-sm4 no-srp no-ssl no-ssl3 \
			no-ssl-trace no-ui-console no-uplink no-whirlpool no-zlib CC=clang-10 CXX=clang++-10; \
	perl "-I." -Mconfigdata "openssl_3/util/dofile.pl" "-oMakefile" "openssl_3/include/crypto/bn_conf.h.in" > include_3/crypto/bn_conf.h;
	perl "-I." -Mconfigdata "openssl_3/util/dofile.pl" "-oMakefile" "openssl_3/include/crypto/dso_conf.h.in" > include_3/crypto/dso_conf.h;
	perl "-I." -Mconfigdata "openssl_3/util/dofile.pl" "-oMakefile" "openssl_3/include/openssl/asn1.h.in" > include_3/openssl/asn1.h;
	perl "-I." -Mconfigdata "openssl_3/util/dofile.pl" "-oMakefile" "openssl_3/include/openssl/asn1t.h.in" > include_3/openssl/asn1t.h;
	perl "-I." -Mconfigdata "openssl_3/util/dofile.pl" "-oMakefile" "openssl_3/include/openssl/bio.h.in" > include_3/openssl/bio.h;
	perl "-I." -Mconfigdata "openssl_3/util/dofile.pl" "-oMakefile" "openssl_3/include/openssl/cmp.h.in" > include_3/openssl/cmp.h;
	perl "-I." -Mconfigdata "openssl_3/util/dofile.pl" "-oMakefile" "openssl_3/include/openssl/cms.h.in" > include_3/openssl/cms.h;
	perl "-I." -Mconfigdata "openssl_3/util/dofile.pl" "-oMakefile" "openssl_3/include/openssl/conf.h.in" > include_3/openssl/conf.h;
	perl "-I." -Mconfigdata "openssl_3/util/dofile.pl" "-oMakefile" "openssl_3/include/openssl/configuration.h.in" > include_3/openssl/configuration.h;
	perl "-I." -Mconfigdata "openssl_3/util/dofile.pl" "-oMakefile" "openssl_3/include/openssl/crmf.h.in" > include_3/openssl/crmf.h;
	perl "-I." -Mconfigdata "openssl_3/util/dofile.pl" "-oMakefile" "openssl_3/include/openssl/crypto.h.in" > include_3/openssl/crypto.h;
	perl "-I." -Mconfigdata "openssl_3/util/dofile.pl" "-oMakefile" "openssl_3/include/openssl/ct.h.in" > include_3/openssl/ct.h;
	perl "-I." -Mconfigdata "openssl_3/util/dofile.pl" "-oMakefile" "openssl_3/include/openssl/err.h.in" > include_3/openssl/err.h;
	perl "-I." -Mconfigdata "openssl_3/util/dofile.pl" "-oMakefile" "openssl_3/include/openssl/ess.h.in" > include_3/openssl/ess.h;
	perl "-I." -Mconfigdata "openssl_3/util/dofile.pl" "-oMakefile" "openssl_3/include/openssl/fipskey.h.in" > include_3/openssl/fipskey.h;
	perl "-I." -Mconfigdata "openssl_3/util/dofile.pl" "-oMakefile" "openssl_3/include/openssl/lhash.h.in" > include_3/openssl/lhash.h;
	perl "-I." -Mconfigdata "openssl_3/util/dofile.pl" "-oMakefile" "openssl_3/include/openssl/ocsp.h.in" > include_3/openssl/ocsp.h;
	perl "-I." -Mconfigdata "openssl_3/util/dofile.pl" "-oMakefile" "openssl_3/include/openssl/opensslv.h.in" > include_3/openssl/opensslv.h;
	perl "-I." -Mconfigdata "openssl_3/util/dofile.pl" "-oMakefile" "openssl_3/include/openssl/pkcs12.h.in" > include_3/openssl/pkcs12.h;
	perl "-I." -Mconfigdata "openssl_3/util/dofile.pl" "-oMakefile" "openssl_3/include/openssl/pkcs7.h.in" > include_3/openssl/pkcs7.h;
	perl "-I." -Mconfigdata "openssl_3/util/dofile.pl" "-oMakefile" "openssl_3/include/openssl/safestack.h.in" > include_3/openssl/safestack.h;
	perl "-I." -Mconfigdata "openssl_3/util/dofile.pl" "-oMakefile" "openssl_3/include/openssl/srp.h.in" > include_3/openssl/srp.h;
	perl "-I." -Mconfigdata "openssl_3/util/dofile.pl" "-oMakefile" "openssl_3/include/openssl/ssl.h.in" > include_3/openssl/ssl.h;
	perl "-I." -Mconfigdata "openssl_3/util/dofile.pl" "-oMakefile" "openssl_3/include/openssl/ui.h.in" > include_3/openssl/ui.h;
	perl "-I." -Mconfigdata "openssl_3/util/dofile.pl" "-oMakefile" "openssl_3/include/openssl/x509.h.in" > include_3/openssl/x509.h;
	perl "-I." -Mconfigdata "openssl_3/util/dofile.pl" "-oMakefile" "openssl_3/include/openssl/x509_vfy.h.in" > include_3/openssl/x509_vfy.h;
	perl "-I." -Mconfigdata "openssl_3/util/dofile.pl" "-oMakefile" "openssl_3/include/openssl/x509v3.h.in" > include_3/openssl/x509v3.h;
	cp openssl_3/providers/common/der/oids_to_c.pm ./
	perl "-I." -Mconfigdata -Moids_to_c "openssl_3/util/dofile.pl" "-oMakefile" "openssl_3/providers/common/der/der_digests_gen.c.in" > providers_3/common/der/der_digests_gen.c;
	perl "-I." -Mconfigdata -Moids_to_c "openssl_3/util/dofile.pl" "-oMakefile" "openssl_3/providers/common/der/der_dsa_gen.c.in" > providers_3/common/der/der_dsa_gen.c;
	perl "-I." -Mconfigdata -Moids_to_c "openssl_3/util/dofile.pl" "-oMakefile" "openssl_3/providers/common/der/der_ec_gen.c.in" > providers_3/common/der/der_ec_gen.c;
	perl "-I." -Mconfigdata -Moids_to_c "openssl_3/util/dofile.pl" "-oMakefile" "openssl_3/providers/common/der/der_ecx_gen.c.in" > providers_3/common/der/der_ecx_gen.c;
	perl "-I." -Mconfigdata -Moids_to_c "openssl_3/util/dofile.pl" "-oMakefile" "openssl_3/providers/common/der/der_rsa_gen.c.in" > providers_3/common/der/der_rsa_gen.c;
	perl "-I." -Mconfigdata -Moids_to_c "openssl_3/util/dofile.pl" "-oMakefile" "openssl_3/providers/common/der/der_sm2_gen.c.in" > providers_3/common/der/der_sm2_gen.c;
	perl "-I." -Mconfigdata -Moids_to_c "openssl_3/util/dofile.pl" "-oMakefile" "openssl_3/providers/common/der/der_wrap_gen.c.in" > providers_3/common/der/der_wrap_gen.c;
	perl "-I." -Mconfigdata -Moids_to_c "openssl_3/util/dofile.pl" "-oMakefile" "openssl_3/providers/common/include/prov/der_digests.h.in" > include_3/prov/der_digests.h;
	perl "-I." -Mconfigdata -Moids_to_c "openssl_3/util/dofile.pl" "-oMakefile" "openssl_3/providers/common/include/prov/der_dsa.h.in" > include_3/prov/der_dsa.h;
	perl "-I." -Mconfigdata -Moids_to_c "openssl_3/util/dofile.pl" "-oMakefile" "openssl_3/providers/common/include/prov/der_ec.h.in" > include_3/prov/der_ec.h;
	perl "-I." -Mconfigdata -Moids_to_c "openssl_3/util/dofile.pl" "-oMakefile" "openssl_3/providers/common/include/prov/der_ecx.h.in" > include_3/prov/der_ecx.h;
	perl "-I." -Mconfigdata -Moids_to_c "openssl_3/util/dofile.pl" "-oMakefile" "openssl_3/providers/common/include/prov/der_rsa.h.in" > include_3/prov/der_rsa.h;
	perl "-I." -Mconfigdata -Moids_to_c "openssl_3/util/dofile.pl" "-oMakefile" "openssl_3/providers/common/include/prov/der_sm2.h.in" > include_3/prov/der_sm2.h;
	perl "-I." -Mconfigdata -Moids_to_c "openssl_3/util/dofile.pl" "-oMakefile" "openssl_3/providers/common/include/prov/der_wrap.h.in" > include_3/prov/der_wrap.h;
