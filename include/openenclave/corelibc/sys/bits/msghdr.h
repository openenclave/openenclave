// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// clang-format off
void* msg_name;        /* Address to send to/receive from.  */
socklen_t msg_namelen; /* Length of address data.  */

struct OE_IOVEC_TYPE* msg_iov; /* Vector of data to send/receive into.  */
size_t msg_iovlen;        /* Number of elements in the vector.  */

void* msg_control;     /* Ancillary data (eg BSD filedesc passing). */
size_t msg_controllen; /* Ancillary data buffer length.
                          !! The type should be socklen_t but the
                          definition of the linux kernel is incompatible
                          with this.  */
int msg_flags; /* Flags on received message.  */
// clang-format on
