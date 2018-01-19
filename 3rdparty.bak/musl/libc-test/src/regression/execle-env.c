// commit 2b2aff37aced66e4a50a38a14607a9b1dc0ee001 2013-10-03
// execle should pass env properly
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include "test.h"

int main(void)
{
	char *env[] = {"VAR=abc", 0};

	execle("/bin/sh", "sh", "-c",
		"[ \"$VAR\" = abc ] || { echo '"__FILE__": env is not passed'; exit 1; }",
		(char*)0, env);

	t_error("execle failed: %s\n", strerror(errno));
	return 1;
}
