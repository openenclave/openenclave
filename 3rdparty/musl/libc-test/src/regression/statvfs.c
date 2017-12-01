// commit 7673acd31503016f2af93e187aac98da07af42b4 2014-03-12
// internal statfs struct was wrong on mips
// this test does various sanity checks to catch such bugs
#include <string.h>
#include <errno.h>
#include <sys/statvfs.h>
#include "test.h"

int main(void)
{
	struct statvfs f;

	if (statvfs("/", &f))
		t_error("statvfs(\"/\") failed: %s\n", strerror(errno));
	if (f.f_bsize == 0 || f.f_bsize > 1<<28)
		t_error("/ has bogus f_bsize: %lu\n", (unsigned long)f.f_bsize);
	if (f.f_blocks == 0)
		t_error("/ has 0 blocks\n");
	if (f.f_blocks < f.f_bfree)
		t_error("/ has more free blocks (%llu) than total blocks (%llu)\n",
			(unsigned long long)f.f_bfree, (unsigned long long)f.f_blocks);
	if (f.f_blocks < f.f_bavail)
		t_error("/ has more avail blocks (%llu) than total blocks (%llu)\n",
			(unsigned long long)f.f_bavail, (unsigned long long)f.f_blocks);
	if (f.f_files == 0)
		t_error("/ has 0 file nodes\n");
	if (f.f_files < f.f_ffree)
		t_error("/ has more free file nodes (%llu) than total file nodes (%llu)\n",
			(unsigned long long)f.f_ffree, (unsigned long long)f.f_files);
	if (f.f_files < f.f_favail)
		t_error("/ has more avail file nodes (%llu) than total file nodes (%llu)\n",
			(unsigned long long)f.f_favail, (unsigned long long)f.f_files);
	if (f.f_namemax > 1<<16 || f.f_namemax < 8)
		t_error("/ has bogus f_namemax: %lu\n", (unsigned long)f.f_namemax);

	return t_status;
}
