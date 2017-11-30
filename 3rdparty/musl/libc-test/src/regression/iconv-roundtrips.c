// commit: b7bfb5c3a8330002250f304cb5deb522fa054eae
// fix iconv conversions for iso88592-iso885916
#include <iconv.h>
#include <string.h>
#include "test.h"

int main(void)
{
	static char *test_charsets[] = {
		"iso-8859-1",
		"iso-8859-2",
		"iso-8859-4",
		"iso-8859-5",
		"iso-8859-9",
		"iso-8859-10",
		"iso-8859-13",
		"iso-8859-14",
		"iso-8859-15",
		"iso-8859-16",
		0
	};
	char all_codepoints[256];
	int i;

	for (i=0; i<256; i++)
		all_codepoints[i] = 255-i;

	for (i=0; test_charsets[i]; i++) {
		iconv_t there = iconv_open("UTF-8", test_charsets[i]);
		if (there == (iconv_t)-1) continue;
		iconv_t andback = iconv_open(test_charsets[i], "UTF-8");
		if (andback == (iconv_t)-1) {
			iconv_close(there);
			continue;
		}
		char u8buf[1024];
		char buf[256];
		size_t u8rem = sizeof u8buf;
		int r1 = iconv(there,
			&(char *){all_codepoints}, &(size_t){sizeof all_codepoints},
			&(char *){u8buf}, &u8rem);
		size_t u8len = sizeof u8buf - u8rem;
		int r2 = iconv(andback,
			&(char *){u8buf}, &(size_t){u8len},
			&(char *){buf}, &(size_t){sizeof buf});

		if (r1) t_error("got %d converting from %s\n", r1, test_charsets[i]);
		if (r2) t_error("got %d converting back to %s\n", r2, test_charsets[i]);

		if (memcmp(all_codepoints, buf, sizeof buf)) {
			t_error("round trip corrupted %s characters\n", test_charsets[i]);
		}

		iconv_close(there);
		iconv_close(andback);
	}

	return t_status;
}
