#include "pthread_impl.h"

int pthread_attr_init(pthread_attr_t *a)
{
	*a = (pthread_attr_t){0};
	a->_a_stacksize = DEFAULT_STACK_SIZE;
	a->_a_guardsize = DEFAULT_GUARD_SIZE;
	return 0;
}
