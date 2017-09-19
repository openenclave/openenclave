[Index](index.md)

---
# OE_RegisterOCall()

Registers a low-level OCALL function.

## Syntax

    OE_Result OE_RegisterOCall(uint32_t func, OE_OCallFunction ocall)
## Description 

This function registers a low-level OCALL function that may be called from the encalve by the **** function. The registered function has the following prototype.

```
void (*)(uint64_t argIn, uint64_t* argOut);
```



This interface is intended mainly for internal use and developers are encouraged to use the high-level interface instead.



## Parameters

#### func

The number of the function to be called.

#### ocall

The address of the function to be called.

## Return value

#### OE_OK

The function was successful.

#### OE_OUT_OF_RANGE

The function number was greater than OE_MAX_OCALLS.

#### OE_ALREADY_IN_USE

The function number is already in use.

---
[Index](index.md)

