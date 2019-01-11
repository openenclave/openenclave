This README lists the set of changes made to the libcxxrt library.
When upgrading the library, make sure to preserve the following changes.

1. exception.cc: Use oe_thread_data_t's __cxx_thread_info instead of
    calloc-ing it on demand. This prevents crashes when an std::bad_alloc
	is thrown.
