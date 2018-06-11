[Index](index.md)

---
# OE_ThreadSetSpecific()

Sets the value of a thread-specific data entry.

## Syntax

    OE_Result OE_ThreadSetSpecific(OE_ThreadKey key, const void *value)
## Description 

This function sets the value of a thread-specific data (TSD) entry associated with the given key.



## Parameters

#### key

Set the TSD entry associated with this key.

#### value

Set the TSD entry to this value.

## Returns

OE_OK the operation was successful

## Returns

OE_INVALID_PARAMETER one or more parameters is invalid

---
[Index](index.md)

