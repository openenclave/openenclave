SIG Release Charter
===================

## Scope

SIG Release is responsible for the generation of periodic numerical binary releases of the Open Enclave SDK project. This includes the processes necessary for tracking feature delivery and coordinating various teams' execution towards planned milestones.

## In Scope

### Code, Binaries, or Services

- Creation of numerical release tags in GitHub, and their application to issues and PRs
- Maintenance of kanban-style boards for the N+1 release tracking
- Creation of release notes, when a release is published, and inclusion of those notes in the appropriate locations (e.g., in Git and on the website)
- Validation of the output of the build system (e.g., final qualification of the binary outputs of a CI/CD pipeline)

### Cross-cutting or Externally Facing Processes

- Establishing meetings, as needed, to unblock any at-risk work items in the lead up to a release
- Monitoring the build system and coordinating reviews leading up to cutting a release
- Ensuring that releases are cut on time, or alerting the CGC if there will be delays in the release process

### Out of Scope

SIG-Release is *not* responsible for actually writing code, fixing tests, or unbreaking CI. Those deliverables are the responsibility of their respective SIGs

## Process & Management

SIG-Release meets only as needed. Meetings are generally more frequent in the run-up to a release.

Meetings are held at PLACE, with AGENDA/MINUTES available or not. Meetings are OPEN/CLOSED.

Membership in the SIG may be gained by: showing up to help.

The current SIG Chair is: Radhika.

**Note (Aeva)** -- Proposed succession process here **please review**

At the mid-point of any release cycle, a new SIG Chair may be nominated for the
upcoming release by the current chair. If the CGC approves the nomination and
the nominee accepts the appointment, then the new chair would shadow the current
chair for the remainder of the current release cycle and take on full
responsibilities for the following release.

## Roles & Structure

SIG-Release loosely follows the structure defined in [the governance charter template](../governance/sig-charter-template.md), but has little need for Approvers or Reviewers at this time as all responsibilities can be handled by 1 - 2 Chairs.