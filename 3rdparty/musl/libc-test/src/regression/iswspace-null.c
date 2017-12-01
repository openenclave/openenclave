// commit: d8e8f1464cb02d6a62f01c7153ca4d7b0cd5c5e6 2013-11-11
// iswspace(0) should be 0
#include <wctype.h>
#include "test.h"

int main(void)
{
	if (iswspace(0)!=0)
		t_error("iswspace(0) returned non-zero\n");
	return t_status;
}
