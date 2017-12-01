#include <string.h>
#include <errno.h>
#include <iconv.h>
#include "test.h"

int main(void)
{
	iconv_t cd;
	char buf[100];
	char *inbuf = "test";
	char *outbuf = buf;
	size_t inlen = strlen(inbuf);
	size_t outlen;
	size_t r;
	char *bad = "bad-codeset";

	cd = iconv_open(bad, bad);
	if (cd != (iconv_t)-1)
		t_error("iconv_open(\"%s\",\"%s\") didn't fail\n", bad, bad);
	if (errno != EINVAL)
		t_error("iconv_open(\"%s\",\"%s\") did not fail with EINVAL, got %s\n", bad, bad, strerror(errno));

	errno = 0;
	cd = iconv_open("UTF-8", "UTF-8");
	if (cd == (iconv_t)-1)
		t_error("iconv_open(\"\",\"\") failed: %s\n", strerror(errno));

	errno = 0;
	outlen = 0;
	r = iconv(cd, &inbuf, &inlen, &outbuf, &outlen);
	if (r != -1)
		t_error("iconv() did not fail with 0 output length\n");
	if (errno != E2BIG)
		t_error("iconv() did not fail with E2BIG, got %s\n", strerror(errno));

	errno = 0;
	outlen = sizeof buf;
	r = iconv(cd, &inbuf, &inlen, &outbuf, &outlen);
	if (r)
		t_error("iconv() did not return 0 when converting utf8 to utf8, got %d\n", r);
	if (errno)
		t_error("iconv() failed: %s\n", strerror(errno));

	r = iconv_close(cd);
	if (r == -1)
		t_error("iconv_close failed: %s\n", strerror(errno));

	return t_status;
}
