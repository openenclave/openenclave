__thread char v[123];
__thread int x = 42;
__thread long double y;

void *f()
{
	int i;
	for (i=0; i<sizeof v; i++)
		v[i] = i%16;
	return v;
}
void *g() {return &x;}
void *h() {return &y;}
