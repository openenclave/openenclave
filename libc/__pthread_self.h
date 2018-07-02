// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

//==============================================================================
//
// Some MUSL functions reference the following definition of CURRENT_LOCALE:
//
//     __pthread_self()->locale
//
// To satisfy this reference, the following definitions provide a local
// __pthread_self() function that returns a structure with a 'locale' field.
//
//==============================================================================

struct __pthread_self_return
{
    locale_t locale;
};

static const struct __pthread_self_return* __pthread_self(void)
{
    static const struct __locale_struct _c_locale = {0};
    static const struct __pthread_self_return _ret = { (locale_t)&_c_locale };
    return &_ret;
}
