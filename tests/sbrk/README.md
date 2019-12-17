sbrk
====

This test verifies the **oe_sbrk()** function. It verifies these three cases:

- Allocation (with a positive increment parameter)
- Deallocation (with a negative increment parameter)
- Getting current the program break (with a zero increment parameter)

The test also verifies that **oe_sbrk()** correctly zero-fills allocated memory.
