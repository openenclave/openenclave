Open Enclave SDK Release Procedures
===================================

This document covers how we handle creating a release. Let's look at it from an
example:

Selecting a Release Manager
---------------------------

The Community Governance Committee will select a release manager from one of the
Committers by submitting a Pull Request that adds a "Release" tag to that
Committer's "Area" in [Committers.md](Committers.md).

Version Bump
------------

> A note on naming: please prepend the `v` for consistency. Tags are `v0.7.0`
> and branches are `v0.7.x`. We follow [Semantic
> Versioning](https://semver.org/spec/v2.0.0.html).

The initial announcement of the upcoming release will be a PR by the release
manager to the `master` branch with the commit to bump the [VERSION
file](../VERSION) to _next_ pre-release, e.g. `v0.7.x`, and the commit to update
the [CHANGELOG](#changelog-updates) "Unreleased" section to `v0.7.0` (and change
the previous to `v0.6.0`).

Release Branch
--------------

After this is merged, a release branch named `v0.7.x` is created from the last
commit in `master` before the version changed to `v0.7.x`. The VERSION file in
this commit should currently have `v0.6.x` in it, and the first commit to the
release branch is to change it to `v0.6.0-rc1`.

As release candidates are created, the suffix is incremented, e.g. `v0.6.0-rc2`.
It is from this branch that pre-release packages are created.

When the release is finalized, the branch is once again bumped to the final
version number without the suffix, e.g. `v0.6.0`.

Hotfix releases are made from this branch, following a similar process, but with
the patch version incremented to `v0.6.1`.

All normal development continues to happen on the `master` branch. As PRs are
opened against `master`, if the author believes the PR also belongs in `v0.6.x`,
they will note this in the PR (this should be done with the milestone). After
approval, the PR will be merged into `master` as we do normally (with `bors
r+`).

Backports to Release Branch
---------------------------

For PRs that should also land in the release, the _release manager_ will craft a
second PR with the same changes rebased onto the `v0.6.x` branch, and will open
a PR targeting the release branch. This PR will go through the same review
process, and explicitly requires the original author to approve it. After
approval, the PR will be merged to the release branch, again with `bors r+`.

The above is driven by a desire to keep developers' workflow as uninterrupted as
possible. That is, we do not want to require developers to know which branch to
target, they always target `master`. This responsibility is, instead, on the
release manager. However, if the author feels up to the task, they are free to
share this responsibility.

Furthermore, the number of these PRs should be few, as major feature work should
be merged to `master` before the release branch is crafted. These PRs should be
reserved for critical fixes and release-specific changes.

Changelog Updates
-----------------

The [Unreleased](../CHANGELOG.md#unreleased) section of the changelog will be
moved upward, and in its place a new section will be added, in the following
format, based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/):

``` markdown
[v0.4.0] - YYYY-MM-DD
---------------------
...
Entries from Unreleased section.
...

[Unreleased]: https://github.com/openenclave/openenclave/compare/v0.4.0...HEAD
[v0.4.0]: https://github.com/openenclave/openenclave/compare/v0.1.0...v0.4.0
```

The `v0.4.0` comparison URL will be added at the bottom of the file, after the
URL for the Unreleased section, and the Unreleased comparison URL will be
updated to end with `v0.4.0...HEAD`.

Release Notes
-------------

Release notes will be curated from the new `v0.4.0` section of our changelog. In
the same way that the changelog is intended to be a less verbose version of the
Git history, the release notes are intended to be a more concise version of the
changelog. While the changelog is in bullet point format, the release manager
will read these and write a few concise paragraphs describing the nature of the
release. These notes should be suitable for a blog post.

Community Approval
------------------

See the [Governance Model](Governance.md#community-approval-of-releases)
documentation for the necessary steps to approve the release with the community.

GitHub Release and Git Tag Creation
-----------------------------------

After the following has happened:

1. The `VERSION` file has been bumped.
2. The changelog has been updated.
3. The release branch has been published.
4. All outstanding PRs for the release have been merged.
5. Packages have been generated for the release.
6. The packages have been sufficiently tested.
7. The desired release notes have been written.
8. The release has been approved by the community.

The release manager will draft a [GitHub
Release](https://help.github.com/articles/creating-releases/). When published,
this will create a Git tag, which should be named `v0.4.0` pointing at the head
of the `v0.4.x` branch. That is, the left field will be filled with `v0.4.0`,
and the right field will select `v0.4.x` (note that it defaults to `master` and
must be changed).

The release notes will be added to the description field (which supports
Markdown), and the packages will be uploaded as binaries.

Until version `v1.0.0`, the checkbox "This is a pre-release" _will_ be checked.

**The release manager will confirm that the packages' commit hash matches the
head of the release branch, at which the tag will point. No other changes will
be made without re-packaging and re-testing.**

The release manager will then click "Publish release" on GitHub to publish the
release, and coordinate uploading the packages to the correct package
repositories.

> We will not be GPG signing our pre-releases. This may change for `v1.0.0`.

Announcements
-------------

Once published, the release manager will coordinate the announcement of the
release on various channels (such as a blog post, which can reuse the release
notes, and any social media we currently use).

Servicing
---------

See the [Governance Model](Governance.md#servicing-of-releases)
documentation for our intended servicing model.
