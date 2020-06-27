// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
/**
 * @file allocator.h
 *
 * This file defines the interface that pluggable allocators must implement.
 * See
 * https://github.com/openenclave/openenclave/blob/master/docs/DesignDocs/PluggableAllocators.md
 *
 */

#ifndef OE_ADVANCED_ALLOCATOR_H
#define OE_ADVANCED_ALLOCATOR_H

#include <openenclave/bits/types.h>

/**
 * @cond IGNORE
 */
OE_EXTERNC_BEGIN

/**
 * @endcond
 */

/**
 * Callback for initializing the allocator.
 *
 * The allocator is expected to perform any global initialization needed by the
 * allocator in this function. This function is called prior to other enclave
 * initialization methods, which can depend on the allocator being ready for
 * use.
 *
 * @param[in] heap_start_address The starting address of the enclave heap to be
 * managed by the allocator.
 * @param[in] heap_end_address The ending address of the enclave heap.
 */
void oe_allocator_init(void* heap_start_address, void* heap_end_address);

/**
 * Callback for cleaning up the allocator.
 *
 * This function will be called by oecore during enclave termination.
 * atexit functions will be executed prior to oe_allocator_cleanup.
 * oe_allocator_cleanup may not register functions with atexit.
 */
void oe_allocator_cleanup(void);

/**
 * Callback for performing thread-specific initialization.
 *
 * This function will be called by oecore during initialization of an enclave
 * thread, after the thread-local variables for the thread have been
 * initialized.
 *
 * Note: Each ecall starts a new enclave thread that terminates when the ecall
 * returns.
 */
void oe_allocator_thread_init(void);

/**
 * Callback for performing thread-specific cleanup.
 *
 * This function will be called by oecore just prior to the termination of
 * enclave thread. Thread-specific exit functions (__cxa_thread_atexit
 * functions) will be executed prior to oe_allocator_thread_cleanup.
 *
 * Note: Each ecall starts a new enclave thread that terminates when the ecall
 * returns.
 */
void oe_allocator_thread_cleanup(void);

/**
 * Callback to allocate memory.
 *
 * This function will be called by oecore to implement malloc.
 * oe_allocator_malloc must provide the same semantics as malloc.
 * See: https://en.cppreference.com/w/c/memory/malloc
 *
 * @param[in] size Number of bytes to allocate.
 * @returns Pointer to allocated memory.
 * @returns NULL if out of memory.
 */
void* oe_allocator_malloc(size_t size);

/**
 * Callback to free memory.
 *
 * This function will be called by oecore to implement free.
 * oe_allocator_free must provide the same semantics as free.
 * See: https://en.cppreference.com/w/c/memory/free
 *
 * @param[in] ptr Pointer to memory to be freed.
 */
void oe_allocator_free(void* ptr);

/**
 * Callback to allocate and zero memory.
 *
 * This function will be called by oecore to implement calloc.
 * oe_allocator_calloc must provide the same semantics as calloc.
 * See: https://en.cppreference.com/w/c/memory/calloc
 *
 * @param[in] nmemb Number of objects to allocate.
 * @param[in] size Size of each object.
 * @returns Pointer to allocated memory.
 * @returns NULL if out of memory.
 */
void* oe_allocator_calloc(size_t nmemb, size_t size);

/**
 * Callback to reallocate memory.
 *
 * This function will be called by oecore to implement realloc.
 * oe_allocator_realloc must provide the same semantics as realloc.
 * See: https://en.cppreference.com/w/c/memory/realloc
 *
 * @param[in] ptr Pointer to memory area to be reallocated.
 * @param[in] size New size in bytes.
 * @returns Pointer to allocated memory.
 * @returns NULL if out of memory.
 */
void* oe_allocator_realloc(void* ptr, size_t size);

/**
 * Callback to perform aligned memory allocation.
 *
 * This function will be called by oecore to implement aligned_alloc.
 * Memory allocated by this function can be freed via free.
 * oe_allocator_aligned_alloc must provide the same semantics as C11
 * aligned_alloc.
 * See: https://en.cppreference.com/w/c/memory/aligned_alloc
 *
 * @param[in] alignment Specified alignment. Must be a power of two.
 * @param[in] size Number of bytes to allocate. An integral multiple of
 * alignment
 * @returns Pointer to allocated memory.
 * @returns NULL if out of memory.
 */
void* oe_allocator_aligned_alloc(size_t alignment, size_t size);

/**
 * Callback to perform aligned memory allocation.
 *
 * This function will be called by oecore to implement posix_memalign.
 * Memory allocated by this function can be freed via free.
 * oe_allocator_posix_memalign must provide the same semantics as
 * posix_memalign.
 * See: https://linux.die.net/man/3/posix_memalign
 *
 * @param[out] memptr Pointer of location to store the address of allocated
 * memory.
 * @param[in] alignment Specified alignment. Must be a power of two.
 * @param[in] size Number of bytes to allocate. An integral multiple of
 * alignment
 * @returns 0 on success.
 * @returns Error value upon failure.
 */
int oe_allocator_posix_memalign(void** memptr, size_t alignment, size_t size);

/**
 * Callback to return usable size of an allocated memory location.
 *
 * This function is called by oecore to implement malloc_usable_size.
 * oe_allocator_malloc_usable_size must provide the same semantics as
 * malloc_usable_size.
 * See: https://man7.org/linux/man-pages/man3/malloc_usable_size.3.html
 *
 * @param[in] ptr Pointer to allocated memory.
 * @returns Number of usable bytes in the block pointed to by ptr.
 */
size_t oe_allocator_malloc_usable_size(void* ptr);

OE_EXTERNC_END

#endif // OE_ADVANCED_ALLOCATOR_H
