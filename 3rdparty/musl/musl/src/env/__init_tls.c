#include <elf.h>
#include <limits.h>
#include <sys/mman.h>
#include <string.h>
#include <stddef.h>
#include "pthread_impl.h"
#include "libc.h"
#include "atomic.h"
#include "syscall.h"

#ifndef SHARED
static
#endif
int __init_tp(void *p)
{
	pthread_t td = p;
	td->self = td;
	int r = __set_thread_area(TP_ADJ(p));
	if (r < 0) return -1;
	if (!r) libc.can_do_threads = 1;
	td->tid = __syscall(SYS_set_tid_address, &td->tid);
	td->locale = &libc.global_locale;
	td->robust_list.head = &td->robust_list.head;
	return 0;
}

#ifndef SHARED

static struct builtin_tls {
	char c;
	struct pthread pt;
	void *space[16];
} builtin_tls[1];
#define MIN_TLS_ALIGN offsetof(struct builtin_tls, pt)

struct tls_image {
	void *image;
	size_t len, size, align;
} __static_tls;

#define T __static_tls

void *__copy_tls(unsigned char *mem)
{
	pthread_t td;
	if (!T.image) return mem;
	void **dtv = (void *)mem;
	dtv[0] = (void *)1;
#ifdef TLS_ABOVE_TP
	mem += sizeof(void *) * 2;
	mem += -((uintptr_t)mem + sizeof(struct pthread)) & (T.align-1);
	td = (pthread_t)mem;
	mem += sizeof(struct pthread);
#else
	mem += libc.tls_size - sizeof(struct pthread);
	mem -= (uintptr_t)mem & (T.align-1);
	td = (pthread_t)mem;
	mem -= T.size;
#endif
	td->dtv = td->dtv_copy = dtv;
	dtv[1] = mem;
	memcpy(mem, T.image, T.len);
	return td;
}

#if ULONG_MAX == 0xffffffff
typedef Elf32_Phdr Phdr;
#else
typedef Elf64_Phdr Phdr;
#endif

void __init_tls(size_t *aux)
{
	unsigned char *p;
	size_t n;
	Phdr *phdr, *tls_phdr=0;
	size_t base = 0;
	void *mem;

	for (p=(void *)aux[AT_PHDR],n=aux[AT_PHNUM]; n; n--,p+=aux[AT_PHENT]) {
		phdr = (void *)p;
		if (phdr->p_type == PT_PHDR)
			base = aux[AT_PHDR] - phdr->p_vaddr;
		if (phdr->p_type == PT_TLS)
			tls_phdr = phdr;
	}

	if (tls_phdr) {
		T.image = (void *)(base + tls_phdr->p_vaddr);
		T.len = tls_phdr->p_filesz;
		T.size = tls_phdr->p_memsz;
		T.align = tls_phdr->p_align;
	}

	T.size += (-T.size - (uintptr_t)T.image) & (T.align-1);
	if (T.align < MIN_TLS_ALIGN) T.align = MIN_TLS_ALIGN;

	libc.tls_size = 2*sizeof(void *)+T.size+T.align+sizeof(struct pthread)
		+ MIN_TLS_ALIGN-1 & -MIN_TLS_ALIGN;

	if (libc.tls_size > sizeof builtin_tls) {
#ifndef SYS_mmap2
#define SYS_mmap2 SYS_mmap
#endif
		mem = (void *)__syscall(
			SYS_mmap2,
			0, libc.tls_size, PROT_READ|PROT_WRITE,
			MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
		/* -4095...-1 cast to void * will crash on dereference anyway,
		 * so don't bloat the init code checking for error codes and
		 * explicitly calling a_crash(). */
	} else {
		mem = builtin_tls;
	}

	/* Failure to initialize thread pointer is always fatal. */
	if (__init_tp(__copy_tls(mem)) < 0)
		a_crash();
}
#else
void __init_tls(size_t *auxv) { }
#endif
