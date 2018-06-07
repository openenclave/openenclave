[Index](index.md)

---
# OE_ThreadKeyDelete()

Delete a key for accessing thread-specific data.

## Syntax

    OE_Result OE_ThreadKeyDelete(OE_ThreadKey key)
## Description 

This function deletes the thread-specific data (TSD) entry associated with the given key, calling the function given by the **destructor** parameter initially passed to [OE_ThreadKeyCreate()](thread_8h_ab18490c558c8a126e107ce64a7af35cb_1ab18490c558c8a126e107ce64a7af35cb.md).



## Parameters

#### key

Delete the TSD entry associated with this key.

## Returns

OE_OK the operation was successful

## Returns

OE_INVALID_PARAMETER one or more parameters is invalid

---
[Index](index.md)

