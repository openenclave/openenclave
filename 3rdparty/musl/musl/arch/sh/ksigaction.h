struct k_sigaction {
	void (*handler)(int);
	unsigned long flags;
	void *restorer;
	unsigned mask[2];
};

extern unsigned char __restore[], __restore_rt[];
