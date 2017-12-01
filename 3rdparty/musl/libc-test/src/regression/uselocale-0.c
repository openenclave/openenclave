// commit: 63f4b9f18f3674124d8bcb119739fec85e6da005
// uselocale(0) should not change the current locale
#include <locale.h>
#include "test.h"

int main(void)
{
	locale_t c = newlocale(LC_ALL_MASK, "C", 0);

	if (!c) {
		t_error("newlocale failed\n");
		return t_status;
	}

	if (!uselocale(c))
		t_error("uselocale(c) failed\n");

	locale_t l1 = uselocale(0);
	if (l1 != c)
		t_error("uselocale failed to set locale: "
			"%p != %p\n", (void*)l1, (void*)c);

	locale_t l2 = uselocale(0);
	if (l2 != l1)
		t_error("uselocale(0) changed locale: "
			"%p != %p\n", (void*)l2, (void*)l1);

	return t_status;
}
