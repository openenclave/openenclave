
extern "C" __attribute__((section(".ecall"))) void __Ping(void* args);

int main()
{
    __Ping(0);
    return 0;
}
