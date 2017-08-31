#include <unistd.h>
#include <assert.h>
#include <openenclave.h>
#include <oeinternal/globals.h>

#define PAGE_SIZE 4096

#if 0
void* sbrk(long increment)
{
    static unsigned char* _heapNext;
    static OE_Spinlock _lock = OE_SPINLOCK_INITIALIZER;
    void* ptr = NULL;

    OE_SpinLock(&_lock);
    {
        size_t remaining;

        if (!_heapNext)
            _heapNext = (unsigned char*)__OE_GetHeapBase();

        remaining = (unsigned char*)__OE_GetHeapEnd() - _heapNext;

        if (increment <= remaining)
        {
            ptr = _heapNext;
            _heapNext += increment;
        }
    }
    OE_SpinUnlock(&_lock);

    return ptr;
}
#endif

int getpagesize(void)
{
    return PAGE_SIZE;
}
