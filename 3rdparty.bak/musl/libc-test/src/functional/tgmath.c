#include <tgmath.h>
#include "test.h"

int main(void)
{
	long i;

	i = lrint(123456789.1f) & 0x7fffffff;
	if (i != 123456792)
		t_error("lrint(123456789.1f)&0x7fffffff want 123456792 got %ld\n", i);
	i = lrint(123456789.1) & 0x7fffffff;
	if (i != 123456789)
		t_error("lrint(123456789.1)&0x7fffffff want 123456789 got %ld\n", i);

	if (sqrt(2.0f) != 1.41421353816986083984375)
		t_error("sqrt(2.0f) want 0x1.6a09e6p+0 got %a\n", sqrt(2.0f));
	if (sqrt(2.0) != 1.414213562373095145474621858738828450441360)
		t_error("sqrt(2.0) want 0x1.6a09e667f3bcdp+0 got %a\n", sqrt(2.0));
	if (sqrt(2) != 1.414213562373095145474621858738828450441360)
		t_error("sqrt(2) want 0x1.6a09e667f3bcdp+0 got %a\n", sqrt(2.0));

	if (sizeof pow(sqrt(8),0.5f) != sizeof(double))
		t_error("sizeof pow(sqrt(8),0.5f) want %d got %d\n", (int)sizeof(double), (int)sizeof pow(sqrt(8),0.5f));
	if (sizeof pow(2.0,0.5) != sizeof(double))
		t_error("sizeof pow(2.0,0.5) want %d got %d\n", (int)sizeof(double), (int)sizeof pow(2.0,0.5));
	if (sizeof pow(2.0f,0.5f) != sizeof(float))
		t_error("sizeof pow(2.0f,0.5f) want %d got %d\n", (int)sizeof(float), (int)sizeof pow(2.0f,0.5f));
	if (sizeof pow(2.0,0.5+0*I) != sizeof(double complex))
		t_error("sizeof pow(2.0,0.5+0*I) want %d got %d\n", (int)sizeof(double complex), (int)sizeof pow(2.0,0.5+0*I));

	if (pow(2.0,0.5) != 1.414213562373095145474621858738828450441360)
		t_error("pow(2.0,0.5) want 0x1.6a09e667f3bcdp+0 got %a\n", pow(2.0,0.5));
	if (pow(2,0.5) != 1.414213562373095145474621858738828450441360)
		t_error("pow(2,0.5) want 0x1.6a09e667f3bcdp+0 got %a\n", pow(2,0.5));
	if (pow(2,0.5f) != 1.414213562373095145474621858738828450441360)
		t_error("pow(2,0.5f) want 0x1.6a09e667f3bcdp+0 got %a\n", pow(2,0.5f));

	return t_status;
}
