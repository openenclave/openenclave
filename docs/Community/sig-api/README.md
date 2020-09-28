API Special Interest Group
==========================

SIG-API is responsible for reviewing and approving changes to the project's
public APIs, and for maintaining [guidelines](../../ApiGuidelines.md)
around creating such APIs.  It is also responsible for reviewing public API
documentation and sample code, since the point of documentation and sample
code is to illustrate how to effectively use public Open Enclave APIs.

Meetings
--------

Currently combined with [SIG-Architecture](../sig-architecture/README.md).

SIG Chair
---------

Dave Thaler ([dthaler](https://github.com/dthaler))

SIG Approvers
-------------

TBD

SIG Reviewers
-------------

TBD

Charter
-------

References that API reviewers are expected to be familiar with the existence
of (but not necessarily their contents), so they can be consulted when
appropriate include:

* [Open Enclave API guidelines](../../ApiGuidelines.md): All pull requests
  that affect public APIs are expected to conform to these guidelines.
  SIG-API is responsible for any updates to these guidelines, and SIG-API
  reviewers are expected to be familiar with these guidelines and review
  PR's for conformance to them.

* [Doxygen manual](https://www.doxygen.nl/manual/commands.html):
  This reference is relevant to comments on public APIs, which
  are used to generate the public docs reachable under "API Documentation"
  on the [Open Enclave SDK site](https://openenclave.io/sdk/).
  For example, the difference between `returns` and `retval`,
  the use of [`[in,out]` annotations](https://www.doxygen.nl/manual/commands.html#cmdparam),
  etc. are explained at this site.

* [C/C++ Language Reference](https://en.cppreference.com/w/):
  This reference covers standard [C](http://www.open-std.org/JTC1/SC22/WG14/)
  and [C++](http://www.open-std.org/JTC1/SC22/WG21/) language concepts
  and library (e.g., libc) APIs, and explains any differences between
  language versions, such as C++11 and C99.  Libc APIs are normally
  expected to conform to these specifications.  Samples should
  generally follow recommendations in these specifications where
  appropriate (e.g., avoiding deprecated APIs, use of
  [nullptr](https://en.cppreference.com/w/cpp/language/nullptr)
  in C++11 samples).

* [POSIX API specification](https://pubs.opengroup.org/onlinepubs/9699919799/functions/contents.html):
  [POSIX](http://www.open-std.org/JTC1/SC22/WG15/) APIs
  are normally expected to conform to this specification.

* [Linux man pages](https://linux.die.net/man/):
  Linux is not always compliant to the POSIX API or C/C++ standards.
  For example, the [malloc page](https://linux.die.net/man/3/malloc)
  explains that when `malloc()` returns non-NULL there is no guarantee
  that the memory really is available.
  Hence this reference should be consulted for discussion of "standard" APIs.

* [Windows API documentation](https://docs.microsoft.com/en-us/windows/win32/api/):
  Windows is not always compliant to the POSIX API or C/C++ standards.
  For example, Windows requires [`closesocket()`](https://docs.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-closesocket)
  to close a socket rather than the POSIX `close()` API.
  Hence this reference should be consulted for discussion of "standard" APIs.

* (Microsoft-internal only) [Win32 API Design Guidelines](https://osgwiki.com/wiki/Win32_API_Design_Guidelines):
  Although this reference is only accessible to Microsoft employees, it does
  contain some useful design guidance for C APIs, such as the
  [recommendation against call-twice APIs](https://osgwiki.com/wiki/Win32_API_Design_Guidelines#Designing_variable-sized_out_parameters).
