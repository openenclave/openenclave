cppException tests
============

This directory runs cpp exception tests within enclave.
All test functions are included in enc/cppException.cpp.

# Following scenarios are tested

* Basic types (char, int, string, class, derived class from std::exception) can
be thrown and caught correctly.
* Ellipsis catch can catch all kinds of cpp exception.
* Handlers for a given try block are examined in order of their appearance.
* Find the matching handler through nested try blocks.
* Find the matching catch handler through call stack
* Re-throw the same exception in the catch clause.
* New exception can be thrown in catch clause.
* Stack local unwind.
* Stack global unwind.
* The exception happens in function-try-block is handled.
* Unhandled exception.
