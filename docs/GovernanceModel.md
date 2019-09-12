Open Enclave SDK Governance Model
=================================

We intend our governance model to be as flexible as possible. Our primary goal
is to enable a vibrant development community for the Open Enclave SDK. If you
feel we should make any changes to our guidelines, please start a discussion
with us.

Our model is based on the
[liberal contribution policy](https://opensource.guide/leadership-and-governance/).
See [below](#accepting-contributions) for more info.

Code of Conduct
---------------

In order to maintain a pleasant and welcoming environment, we want to reiterate
that it is imperative that all community members adhere to our
[Code of Conduct](Contributing.md#code-of-conduct).
Anyone failing to follow the Code of Conduct will be removed from the community
by the [Community Governance Committee](Maintainers.md). If you are made to
feel uncomfortable, or have any concerns about behavior within the community, we
encourage you to reach out to members of the Community Governance Committee.

Design and Development Discussions
----------------------------------

To this end, we want to be open and upfront about all changes, with the majority
of discussions happening in public (on our GitHub repository). Understanding
that many discussions may still happen in person, the outcome of those talks
should always be reiterated on the relevant GitHub issues and PRs such that the
whole community has a chance to participate in the discussion.

Issue Responses
---------------

Please understand that we may not be able to respond to every issue as soon as
we would like, but we intend to reply within one week. If you haven't heard
anything by then, please feel free to remind us with a ping on the thread.

Remember that security issues should be reported through a separate channel, and
will receive a response within 24 hours. See [Reporting Security
Issues](Contributing.md#reporting-security-issues).

Community Maintenance Commitee Members, Committers, and Contributors
--------------------------------------------------------------------

A "committer" is anyone with direct write access to the Open Enclave repository on
GitHub, as granted by the Committee. All Committee members are committers, but not all
committers are Committee members. Finally, "contributor" is anyone else making
contributions to the project, including: creating or commenting on issues,
opening or reviewing pull requests, or other useful contributions such as
providing support in forums or chats.

See the [Community Governance Committee document](Maintainers.md) for more information
on the Community Governance Committee, our process for adding new committers and maintainers, as well the
areas of expertise for each of the committers.

Accepting Contributions
-----------------------

Project committers will merge changes that improve the product significantly and
broadly and that align with the
[Open Enclave roadmap](https://github.com/openenclave/openenclave/projects).
Contributions must also satisfy the other [published guidelines](Contributing.md).
Committers may revert changes if they are found to be breaking.

We make most decisions through a consensus seeking process, rather than a formal
voting process. For example, committers can merge contributions that were
reviewed without objections. If there are objections that cannot be resolved, an
issue can be escalated to the Community Governance Committee to make a
decision, which handles issues as discussed in the
[Community Governance Committee document](Maintainers.md).

See the [Community Governance Committee document](Maintainers.md) for the list of project
committers, and how to become one.

Community Approval of Releases
------------------------------

We want to ensure that our releases go through a process of community feedback.
That means that before any release is finalized, a feedback solicitation period
will happen. The release manager will open a GitHub issue announcing a Release
Candidate (RC), with currently built and tested packages attached, and the
suggested release notes in the description. The title should be "Release
Candidate 1 for v0.4.0", with the candidate number and version updated as
appropriate.

We are starting with a waiting period of about one week (in addition to the week
between the initial announcement / version bump and the release candidate), but
this time frame of two weeks is flexible to the community's and individual
release's needs. During this time, the community is encouraged to provide
feedback and test out the candidate packages.

- If something is missing in the release, open an issue where you mention the
  release manager and reference the RC issue. If it is a blocker, reply to the
  RC issue that is it not ready to be released.
- If something breaks, do the same!
- If everything works as intended, please provide that feedback as well.
- If you simply need more time to test, ask on the RC issue to extend the
  waiting period.

It is likely that a release goes through multiple RCs. When an RC is not ready
for release, the release manager will work with the community to incorporate the
necessary changes on the release branch, craft a new RC, and when it is ready,
close the current RC issue and open a new one to begin the process again.

We do not intend to finalize a release until the majority of the community
agrees it is ready. Once a consensus is reached, that is, all major grievances
have been discussed and resolved, the release is considered approved, and the
release manager will close the issue and move forward with the releasing
process. Note that "resolved" does not necessarily mean fixed, but means the
grievance has been discussed, and a fix or compromise was agreed upon.

Servicing of Releases
---------------------

We do not currently intend to service releases before `v1.0.0`. That is, if a
major bug is found, we will include the fix in the next release rather than
attempt to backport. As this is pre-release software, our expectation is that
users are happy to move forward with us as we develop the SDK. As we approach a
stable release, we would like the community to help us decide how to provide
release servicing.
