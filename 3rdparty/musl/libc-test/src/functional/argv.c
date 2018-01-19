#include <limits.h>
#include <stdio.h>
#include "test.h"

#define TEST(c, ...) \
	( (c) || (t_error(#c " failed: " __VA_ARGS__),0) )

int main(int argc, char **argv)
{
	char buf[PATH_MAX];
	TEST(argc == 1, "argc should be 1\n");
	TEST(argv[0] != 0, "argv[0] should not be NULL\n");
	TEST(argv[1] == 0, "argv[1] should be NULL\n");
	TEST(argv[0][0] != 0, "argv[0] should not be empty\n");
	TEST(snprintf(buf, sizeof buf, "%s", argv[0]) < sizeof buf, "argv[0] is not a valid path\n");
	return t_status;
}
