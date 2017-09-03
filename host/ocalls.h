#ifndef _OE_HOST_OCALLS_H
#define _OE_HOST_OCALLS_H

void HandlePuts(uint64_t argIn);
void HandlePutchar(uint64_t argIn);
void HandlePutws(uint64_t argIn);

void HandleMalloc(uint64_t argIn, uint64_t* argOut);
void HandleFree(uint64_t arg);

void HandleThreadWait(uint64_t arg);
void HandleThreadWake(uint64_t arg);
void HandleThreadWakeWait(uint64_t argIn);

void HandleInitQuote(uint64_t argIn);

void HandleStrftime(uint64_t argIn);

void HandleGettimeofday(uint64_t argIn);

void HandleClockgettime(uint64_t argIn);

void HandleNanosleep(uint64_t argIn);

#endif /* _OE_HOST_OCALLS_H */
