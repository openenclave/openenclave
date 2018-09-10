#include "pthread_impl.h"
#include <string.h>

extern size_t __default_stacksize;
extern size_t __default_guardsize;

int pthread_setattr_default_np(const pthread_attr_t *attrp)
{
	/* Reject anything in the attr object other than stack/guard size. */
	pthread_attr_t tmp = *attrp, zero = { 0 };
	tmp._a_stacksize = 0;
	tmp._a_guardsize = 0;
	if (memcmp(&tmp, &zero, sizeof tmp))
		return EINVAL;

	__inhibit_ptc();
	if (attrp->_a_stacksize >= __default_stacksize)
		__default_stacksize = attrp->_a_stacksize;
	if (attrp->_a_guardsize >= __default_guardsize)
		__default_guardsize = attrp->_a_guardsize;
	__release_ptc();

	return 0;
}

int pthread_getattr_default_np(pthread_attr_t *attrp)
{
	__acquire_ptc();
	*attrp = (pthread_attr_t) {
		._a_stacksize = __default_stacksize,
		._a_guardsize = __default_guardsize,
	};
	__release_ptc();
	return 0;
}
