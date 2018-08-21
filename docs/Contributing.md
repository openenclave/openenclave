Contributing to Open Enclave
============================

The Open Enclave team maintains guidelines for contributing to the Open Enclave
repos. An Open Enclave team member will be happy to explain why a guideline is
defined as it is.

_As the Open Enclave project is not yet public, the team requests that all
potential contributions be raised as issues for discussion first until the
initial project development is completed._

General contribution guidance is included in this document. Additional guidance
is defined in the documents linked below.

- [Development Guide](DevelopmentGuide.md) describes the coding style and other
development practices applied to this project.

Help Wanted
------------

The team marks the most straightforward issues as ["help wanted"](
https://github.com/Microsoft/openenclave/labels/help%20wanted). This set of
issues is the place to start if you are interested in contributing but new to
the codebase.

Contribution "Bar"
------------------

Project maintainers will merge changes that improve the product significantly
and broadly and that align with the [Open Enclave roadmap](
https://github.com/Microsoft/openenclave/projects).

Contributions must also satisfy the other published guidelines defined in this
document. We may revert changes if they are found to be breaking.

General Guidelines
------------------

Please do:

* **DO** follow our coding style described in the [Development Guide](
  DevelopmentGuide.md)
* **DO** give priority to the current style of the project or file you're
  changing even if it diverges from the general guidelines.
* **DO** include tests when adding new features. When fixing bugs, start with
  adding a test that highlights how the current behavior is broken.
* **DO** update README.md files in the source tree and other documents to be up
  to date with changes in the code.
* **DO** keep the discussions focused. When a new or related topic comes up it's
  often better to create new issue than to side track the discussion.

DOs and DON'Ts for Pull Requests
--------------------------------

Please do:

* **DO** submit all code changes via pull requests (PRs) rather than through a
  direct commit. PRs will be reviewed and potentially merged by the repo
  maintainers after a peer review that includes at least one maintainer.
* **DO** give PRs short-but-descriptive names (e.g. "Improve code coverage for
  System.Console by 10%", not "Fix #1234")
* **DO** refer to any relevant issues and include [keywords](
  https://help.github.com/articles/closing-issues-via-commit-messages/) that
  automatically close issues when the PR is merged.
* **DO** tag any users that should know about and/or review the change.
* **DO** ensure each commit successfully builds on all platforms and passes all
  unit tests.
* **DO** address PR feedback in an additional commit(s) rather than amending the
  existing commits, and only rebase/squash them when necessary.  This makes it
  easier for reviewers to track changes.
* **DO** assume that ["Squash and Merge"](
  https://github.com/blog/2141-squash-your-commits) will be used to merge your
  commit unless you request otherwise in the PR.

Please do not:

* **DON'T** make PRs for style changes. For example, do not send PRs that are
  focused on changing usage of ```Int32``` to ```int```. The team would prefer
  to address these holistically with tooling.
* **DON'T** surprise us with big pull requests. Instead, file an issue and start
  a discussion so we can agree on a direction before you invest a large amount
  of time.
* **DON'T** commit code that you didn't write. If you find code that you think
  is a good fit to add to Open Enclave, file an issue and start a discussion
  before proceeding.
* **DON'T** submit PRs that alter licensing related files or headers. If you
  believe there's a problem with them, file an issue and we'll be happy to
  discuss it.
* **DON'T** submit changes to the public API without filing an issue and
  discussing with us first.
* **DON'T** submit "work in progress" PRs.  A PR should only be submitted when
  it is considered ready for review and subsequent merging by the contributor.
* **DON'T** fix merge conflicts using a merge commit. Prefer `git rebase`.
* **DON'T** mix independent, unrelated changes in one PR. Separate real
  product/test code changes from larger code formatting/dead code removal
  changes. Separate unrelated fixes into separate PRs, especially if they are
  in different libraries.

Merging Pull Requests (for contributors with write access)
----------------------------------------------------------

Please use ["Squash and Merge"](https://github.com/blog/2141-squash-your-commits
) by default for individual contributions unless requested by the PR author.
Do so, even if the PR contains only one commit. It creates a simpler history
than "Create a Merge Commit". Reasons that PR authors may request "Merge and
Commit" may include (but are not limited to):

  - The change is easier to understand as a series of focused commits. Each
    commit in the series must be buildable so as not to break `git bisect`.
  - Contributor is using an e-mail address other than the primary GitHub address
    and wants that preserved in the history. Contributor must be willing to
    squash the commits manually before acceptance.

Commit Messages
---------------

Please format commit messages as follows (based on [A Note About Git Commit
Messages](http://tbaggery.com/2008/04/19/a-note-about-git-commit-messages.html))
:

```
Summarize change in 50 characters or less

Provide more detail after the first line. Leave one blank line below the
summary and wrap all lines at 72 characters or less.

- Bullet points are okay, especially to break down descriptions of a
  complex fix or feature.

- Typically, a hyphen or asterisk is used for the bullet, followed by a
  single space, with blank lines in between.

- Use a hanging indent

If the change fixes an issue, leave another blank line after the final
paragraph and indicate which issue is fixed in the specific format
below.

Fix #42
```

Also do your best to factor commits appropriately, not too large with unrelated
things in the same commit, and not too small with the same small change applied
_n_ times in _n_ different commits.

Contributor License Agreement
-----------------------------

You must sign a [Microsoft Contribution License Agreement (CLA)](
https://opensource.microsoft.com/pdf/microsoft-contribution-license-agreement.pdf)
before your PR will be merged. This is a one-time requirement for Open Enclave.
You can read more about [Contribution License Agreements (CLA)](
http://en.wikipedia.org/wiki/Contributor_License_Agreement) on Wikipedia.

You don't have to do this up-front. You can simply clone, fork, and submit your
pull-request as usual. When your pull-request is created, it is classified by a
CLA bot. If the change is trivial (for example, you just fixed a typo), then the
PR is labelled with `cla-not-required`. Otherwise it's classified as
`cla-required`. Once you signed a CLA, the current and all future pull-requests
will be labelled as `cla-signed`.

Copying Files from Other Projects
---------------------------------

Open Enclave uses some files from other projects, typically to provide a default
level of functionality within the enclave where a binary distribution does not
exist or would be inconvenient.

The following rules must be followed for PRs that include files from another
project:

- The license of the file is [permissive](
  https://en.wikipedia.org/wiki/Permissive_free_software_licence).
- The license of the file is left intact.
- The contribution is correctly attributed in the [3rd party notices](
  ../THIRD_PARTY_NOTICES) file in the repository, as needed.

Porting Files from Other Projects
---------------------------------

There are many good algorithms implemented in other languages that would benefit
the Open Enclave project. The rules for porting files written in other languages
to C/C++ used in Open Enclave are the same as would be used for copying the same
file, as described above.

[Clean-room](https://en.wikipedia.org/wiki/Clean_room_design) implementations of
existing algorithms that are not permissively licensed will generally not be
accepted. If you want to create or nominate such an implementation, please create
an issue to discuss the idea.

Reporting Security Issues
-------------------------

Security issues and bugs should be reported privately, via email, to the
Microsoft Security Response Center (MSRC) at [secure@microsoft.com](
mailto:secure@microsoft.com). You should receive a response within 24 hours.
If for some reason you do not, please follow up via email to ensure we received
your original message. Further information, including the [MSRC PGP](
https://technet.microsoft.com/en-us/security/dn606155) key, can be found in the
[Security TechCenter](https://technet.microsoft.com/en-us/security/default).

Code of Conduct
---------------

This project has adopted the [Microsoft Open Source Code of Conduct](
https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](
https://opensource.microsoft.com/codeofconduct/faq/) or contact 
[opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional
questions or comments.