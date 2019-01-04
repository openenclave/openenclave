Thread Local Storage Tests
=====================

The following constructs are tested:

1. GNU __thread keyword
2. C++11 thread_local keyword
3. Simple types 
4. Types with constructors
5. Types with destructors
6. extern thread_local variables with complex initializers.
7. Reinitialization of tls via thread recreation.

Disabled in simulation mode since simulation mode needs
completely different implementation of tls variables.
