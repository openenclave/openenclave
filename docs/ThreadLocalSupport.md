Thread-Local Storage Support In Enclaves
----------------------------------------

Thread-locals are supported within enclaves since release 0.5.0.


Both GNU **_\_\_thread_** and C++11 **_thread\_local_** keywords are supported.

```c
__thread int x1 = 5;             // GNU style thread-local```
thread_local uint64_t magic = 123456; // C++11 thread-locals


class MyClass {
    MyClass();   // Non-trivial constructor
    ~MyClass();  // Non-trivial destructor
};

thread_local MyObject obj(param1, param2); // thread-local objects
```

Every _ecall_ into an enclave creates a new enclave-thread and binds it to the calling host thread.
After creating the new enclave-thread, thread-local storage for the thread is allocated and constructed.
Constructing the thread-local storage involves setting the variables to their initial values.
For thread-local variables with non-trivial C++ constructors, the constructors are called the first
time the variable is accessed.

When the _ecall_ returns, the enclave-thread terminates and the thread-locals are cleaned up.
Cleaning up thread-locals may involve calling destructors. The binding between the host-thread
and the enclave-thread is also removed.

Open Enclave SDK requires that enclaves be compiled using the **_local-exec_** thread-local model via
**_-ftls-model=local-exec_** GCC/Clang option. The **_local-exec_** thread-local model results in the most
optimal thread-local implementation for enclaves.

See [GCC Code Gen Options](https://gcc.gnu.org/onlinedocs/gcc/Code-Gen-Options.html) for -ftls-model options.

See [ELF Handling For Thread-Local Storage](https://www.akkadia.org/drepper/tls.pdf) for a detailed explanation of various thread-local storage models.
