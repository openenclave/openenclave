static inline struct pthread *__pthread_self()
{
#ifdef __clang__
	char *tp;
	__asm__ __volatile__ ("mr %0, 2" : "=r"(tp) : : );
#else
	register char *tp __asm__("r2");
	__asm__ __volatile__ ("" : "=r" (tp) );
#endif
	return (pthread_t)(tp - 0x7000 - sizeof(struct pthread));
}
                        
#define TLS_ABOVE_TP
#define TP_ADJ(p) ((char *)(p) + sizeof(struct pthread) + 0x7000)

#define DTP_OFFSET 0x8000

// the kernel calls the ip "nip", it's the first saved value after the 32
// GPRs.
#define MC_PC gregs[32]

#define CANARY canary_at_end
