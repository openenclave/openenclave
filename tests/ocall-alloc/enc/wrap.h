OE_EXTERNC_BEGIN
void* MyOE_HostAllocForCallHost(size_t size);
void MyOE_HostFreeForCallHost(void* p);
OE_EXTERNC_END

size_t MyGetAllocationCount();
size_t MyGetAllocationBytes();
void MyExit();
