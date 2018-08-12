// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

// Assert that given arguments are of specified types.
// Results in compile error on type mismatch.
template <typename... Args>
void check_type(Args&...)
{
}

// Check the type of _retval field of a given args type.
template <typename args_type, typename R>
void check_return_type()
{
    args_type args;
    check_type<R>(args._retval);
}
