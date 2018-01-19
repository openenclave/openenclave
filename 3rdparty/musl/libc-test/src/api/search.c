#include <search.h>
#define T(t) (t*)0;
#define F(t,n) {t *y = &x.n;}
#define C(n) switch(n){case n:;}
static void f()
{
T(size_t)
T(ACTION)
T(VISIT)
T(ENTRY)
{
struct entry x;
F(char*,key)
F(void*,data)
}
switch((ACTION)0){
case FIND:
case ENTER:;
}
switch((VISIT)0){
case preorder:
case postorder:
case endorder:
case leaf:;
}
{int(*p)(size_t) = hcreate;}
{void(*p)(void) = hdestroy;}
{ENTRY*(*p)(ENTRY,ACTION) = hsearch;}
{void(*p)(void*,void*) = insque;}
{void*(*p)(const void*,const void*,size_t*,size_t,int(*)(const void*,const void*)) = lfind;}
{void*(*p)(const void*,void*,size_t*,size_t,int(*)(const void*,const void*)) = lsearch;}
{void(*p)(void*) = remque;}
{void*(*p)(const void*restrict,void**restrict,int(*)(const void*,const void*)) = tdelete;}
{void*(*p)(const void*,void*const*,int(*)(const void*,const void*)) = tfind;}
{void*(*p)(const void*,void**,int(*)(const void*,const void*)) = tsearch;}
{void(*p)(const void*,void(*)(const void*,VISIT,int)) = twalk;}
}
