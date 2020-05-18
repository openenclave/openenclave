Open Enclave SDK Release Process
================================

(TODO - Update this)

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
