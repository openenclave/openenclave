# API Guidelines

## APIs

There are three types of APIs: 

1. Public
2. Experimental
3. Internal

### Public APIs

Public APIs are the supported APIs that apps can use. 

Public API requirements: 

* All public APIs must have at least one test case. This means that, for any
  pull request to be merged that adds a public API, it must also add at least
  one test case for it.
* All public APIs must be in a header file that is published to a location under the SDK output directory.
* All public APIs must be fully documented using doxygen markup in the public header files
* All public APIs must be used in some sample code or snippet. Ideally, the sample
  should be one that is compiled as part of the build, and uses no experimental APIs. For rarely 
  used public APIs, the sample might simply be a snippet in the doxygen comments.
  This means that, for any pull request to be merged that adds a public API,
  it must also add at least one sample or snippet showing how it is used.
* Public APIs must follow [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html)
  rules.  This includes both source-breaking changes (meaning changes that
  would cause a build break when trying to compile an app with a newer
  version of the Open Enclave SDK), but also binary-breaking changes
  for platforms where shared libraries are built (meaning changes
  that would cause runtime errors if a shared library were replaced
  with a newer version). Source- and binary-breaking changes can still
  be made to a new 
  API before it is released for the first time.  See the Breaking Changes section below for further discussion.
* A public API must not be added to Open Enclave if there is already a non-deprecated API that can just 
  as easily be used (i.e., with approximately the same number of lines of code).
* A public API must not be added to Open Enclave if the API would provide generic functionality
  (i.e., not Open Enclave specific functionality) that could be provided by an external library.
* All new Public C API names must start with oe_.
* All public headers must follow Open Enclave [coding conventions](Community/DevelopmentGuide.md).

### Experimental APIs

Experimental APIs are considered to be potential future public APIs, but there is no guarantee 
of support in future releases, nor is there any guarantee that breaking changes will not occur 
across releases. 

Experimental API requirements: 

* Experimental APIs should be optional to compile in. That is, there must be some way to build
  Open Enclave in a way that does not expose any experimental APIs, so that an application
  can easily verify that it uses only fully-supported public APIs, and so that the Open Enclave
  code size requirement can be minimized.
* Experimental APIs must be in a header file that is published to the SDK output directory. They
  can be in their own header, or in a header file that is shared with public APIs but only
  if surrounded by an appropriate ifdef (e.g., "#ifdef OE\_CONTEXT\_SWITCHLESS\_EXPERIMENTAL\_FEATURE").
* Experimental APIs should be fully documented using doxygen markup in the header file, and include the @experimental markup.
* Experimental APIs must have at least one test case. This means that, for any
  pull request to be merged that adds an experimental API, it must also add at
  least one test case for it.
* Experimental APIs should ideally be used in some sample code (separate from samples that
  use only public APIs) or snippet. Ideally, the sample should be one that is compiled as part
  of the build. For rarely used APIs, the sample might simply be a snippet in the doxygen
  comments. Having working samples may help others evaluate and determine how ready it is for
  prime time before the API moves from experimental to public.

### Internal APIs

Internal APIs are considered to be usable within Open Enclave but are not intended to be
used by applications that use Open Enclave. 

Internal API requirements: 

* Internal APIs must not appear in any header file that is published to the SDK package output directory
* Internal APIs should ideally be documented using doxygen markup in the private header files
* Internal APIs must not be used in sample code

## Breaking Changes

* Public APIs cannot have source-breaking changes (and, for platforms where shared libraries or built,
  cannot have binary-breaking changes) across releases, except as covered by deprecation as explained
  below. API additions can be made at any time.
* Experimental and internal APIs can have breaking changes across releases.
* Any breaking change to, or deprecation of, a released API must have a design
  reviewed and approved before the change is made, where the design minimally
  must state why a change is needed.

APIs can be deprecated by marking them as @deprecated. The associated text should explain what
an application should do instead. Public APIs must be @deprecated in a release before they can be
removed.

Until the Open Enclave SDK reaches version 1.0, any breaking change to a public
API can only be made when changing the MINOR version number.  Once the
Open Enclave SDK reaches version 1.0, any breaking change to a public API
can only be made when incrementing the MAJOR version number, as explained in
[Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

Any breaking change to an experimental API can only be made when changing
the MINOR version number, regardless of whether the Open Enclave has reached
1.0 or not.

The only exception to the above is if an API has just been added and hasn't
been in any release yet, then it can have breaking changes up until it is
first released.
