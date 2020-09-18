# Open Enclave Repository Guidelines

This document attempts to outline a structure for creating and associating
GitHub repositories with the Open Enclave project. It also describes how
and when repositories are removed.

- [Repository Types](#repository-types)
  - [Core Repositories](#core-repositories)
    * [Rules](#rules)
  - [Temporary Forks](#temporary-forks)
    * [Rules](#rules)
- [Creating Repositories](#creating-repositories)
- [Removing Repositories](#removing-repositories)
  * [Grounds for removal](#grounds-for-removal)

## Repository Types

### Core Repositories

Core repositories are considered core components of Open Enclave. They are
utilities, tools, applications, or libraries that are expected to be present
in nearly every Open Enclave deployment, such as components and tools
included in official Open Enclave releases. Additionally, the openenclave.io
website and other project-wide infrastructure will remain in the openenclave
github organization.

#### Rules

   1. Must adopt the Open Enclave [Code of Conduct](Governance.md#code-of-conduct)
      statement in their repo.
   2. Must use the [MIT License](../../LICENSE)
      unless otherwise approved by the [CGC](governance/README.md).
   3. Must adopt the [DCO](Contributing.md#developer-certificate-of-origin)
      bot automation for pull requests
      unless otherwise approved by the [CGC](governance/README.md).
   4. Must follow other [contributing guidelines](Contributing.md)
      unless otherwise approved by the [CGC](governance/README.md).
   5. Must live under `github.com/openenclave/<project-name>`.
   6. Code repositories must be approved by
      [SIG-Architecture](sig-architecture/README.md).
      Non-code repositories must be approved by the
      [CGC](governance/README.md).

### Temporary forks

Sometimes the Open Enclave project will want changes to other external
repositories.  Ideally, such changes would be contributed
directly to the upstream project.  However, in some cases it may be
necessary to use a temporary fork for some period of time, whether for
development, or for use while the upstream submission is being reviewed
and iterated on.  In such cases, a fork might be done under an individual's
github organization or the openenenclave organization.  (A fork is not
needed at all if a branch can be created in the related project.)

If the Open Enclave SDK needs to directly depend on a fork of the related
project, it is generally better for the fork to be done under the openenclave
organization.  This makes it clear that the fork is a dependency for Open Enclave
SDK and is not intended for general public use.

#### Rules

The repository must:

   1. Adopt the Open Enclave [Code of Conduct](Governance.md#code-of-conduct)
      statement in their repo.
   2. Use the same license and copyright rules as the forked project.
   3. Adopt the [DCO](Contributing.md#developer-certificate-of-origin)
      bot automation for pull requests
      unless otherwise approved by the [CGC](governance/README.md).
   4. Follow the other [contributing guidelines](Contributing.md)
      unless otherwise approved by the [CGC](governance/README.md).
   5. Be created under `github.com/openenclave/<project-name>`.
   6. Be approved by [SIG-Architecture](sig-architecture/README.md).

Other than rule 2, all other rules are the same as for core repositories.

## Creating Repositories

Requests for creating repositories can be made by filing an
[Open Enclave issue](https://github.com/openenclave/openenclave/issues)
if one does not already exist.

In addition to stating any deviations from the Open Enclave defaults
discussed under Rules above, any request to create a new repository
should also answer the following questions:

1. How should issues with the new repo be tracked and triaged?
   Should github issues be filed in the new repo, or in the main
   openenclave repo?  Should they be discussed in the master openenclave
   triage meeting, or in some separate process?
2. Should one or more of the existing SIGs (e.g.,
   [SIG-Architecture](sig-architecture/README.md),
   [SIG-Testing](sig-testing/README.md)) oversee relevant aspects of the
   new repo, or not?
3. Who is reponsible for maintaining the new repo?  How is their
   contact info published?

Once a repository is created, answers to 1-3 are also expected to be
explained in the repository's README.md file, or other files reachable
from that file.

## Removing Repositories

As important as it is to add new repositories, it is equally important to prune
old repositories that are no longer relevant or useful.

It is in the best interests of everyone involved in the Open Enclave community
that our various projects and repositories are active and healthy. This ensures
that repositories are kept up to date with the latest Open Enclave wide
processes, it ensures a rapid response to potential required fixes (e.g.,
critical security problems), and (most importantly) it ensures that
contributors and users receive quick feedback on their issues and
contributions.

### Grounds for removal

Core repositories may be removed from the project if they
are deemed _inactive_. Inactive repositories are those that meet any of the
following criteria:

   * There are no longer any active maintainers for the project and no
     replacements can be found.
   * All PRs or Issues have gone un-addressed for longer than six months.
   * The contents have been folded into another actively maintained project.
