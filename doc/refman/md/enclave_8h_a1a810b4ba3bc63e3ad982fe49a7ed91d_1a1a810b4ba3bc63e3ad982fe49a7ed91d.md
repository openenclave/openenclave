[Index](index.md)

---
# OE_RegisterECall()

Registers a low-level ECALL function.

## Syntax

    OE_Result OE_RegisterECall(
        uint32_t func,
        OE_ECallFunction ecall);
## Description 

This function registers a low-level ECALL function that may be called from the host by the **OE_ECall()** function. The registered function has the following prototype.

```
void (*)(uint64_t argIn, uint64_t* argOut);
```



This interface is intended mainly for internal use and developers are encouraged to use the high-level interface instead.



## Parameters

#### func

The number of the function to be called.

#### ecall

The address of the function to be called.

## Return value

#### OE_OK

The function was successful.

#### OE_OUT_OF_RANGE

The function number was greater than OE_MAX_ECALLS.

#### OE_ALREADY_IN_USE

The function number is already in use.

---
[Index](index.md)

