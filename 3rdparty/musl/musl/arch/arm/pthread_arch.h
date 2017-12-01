#if ((__ARM_ARCH_6K__ || __ARM_ARCH_6ZK__) && !__thumb__) \
 || __ARM_ARCH_7A__ || __ARM_ARCH_7R__ || __ARM_ARCH >= 7

static inline __attribute__((const)) pthread_t __pthread_self()
{
	char *p;
	__asm__( "mrc p15,0,%0,c13,c0,3" : "=r"(p) );
	return (void *)(p+8-sizeof(struct pthread));
}

#else

static inline __attribute__((const)) pthread_t __pthread_self()
{
#ifdef __clang__
	char *p;
	__asm__( "bl __a_gettp\n\tmov %0,r0" : "=r"(p) : : "cc", "r0", "lr" );
#else
	register char *p __asm__("r0");
	__asm__( "bl __a_gettp" : "=r"(p) : : "cc", "lr" );
#endif
	return (void *)(p+8-sizeof(struct pthread));
}

#endif

#define TLS_ABOVE_TP
#define TP_ADJ(p) ((char *)(p) + sizeof(struct pthread) - 8)

#define CANCEL_REG_IP 18
