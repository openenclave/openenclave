Community Governance Committee
==============================

This document describes the Open Enclave Community Governance Committee. By
our liberal contribution policy outlined in our
[governance model](Governance.md), Committee members are committers that are
trusted to grant new committer rights, and grant new membership into the
Committee.

When making decisions, the Community Governance Committee uses a "consensus
seeking" process. This means that most decisions should be reached by consensus,
but when that fails, the Committee calls for a vote where the super majority
(two-thirds) wins. This is to prevent obstructionism by removing the possibility
of a one person veto.

Quorum for Community Maintenance Committee meetings requires at least two-thirds
all members of the Community Maintenance Committee to be present. The
Community Maintenance Committee may continue to meet if quorum is not met but will
be prevented from making any decisions at the meeting.

All decisions by vote, whether during a meeting or otherwise, require a super majority
vote of all members of the Community Maintenance Committee.


Committee Members
-----------------

| Name                 | Company   | Email                         | GitHub Alias   |
|----------------------|-----------|-------------------------------|----------------|
| Akash Gupta          | Microsoft | akagup@microsoft.com          | gupta-ak       |
| Amaury Chamayou      | Microsoft | amaury.chamayou@microsoft.com | achamayou      |
| Anand Krishnamoorthi | Microsoft | anakrish@microsoft.com        | anakrish       |
| Andrew Schwartzmeyer | Microsoft | andschwa@microsoft.com        | andschwa       |
| Dave Thaler          | Microsoft | dthaler@microsoft.com         | dthaler        |
| John Kordich         | Microsoft | johnkord@microsoft.com        | johnkord       |
| Mike Brasher         | Microsoft | mikbras@microsoft.com         | mikbras        |
| Simon Leet           | Microsoft | simon.leet@microsoft.com      | CodeMonkeyLeet |

Committee Responsibilities
--------------------------

The primary responsibility of the Committee is to grant new committer rights
(that is, write access to the main Open Enclave SDK repository or related
repositories), and to grant new membership into the Committee. Conversely, the
Committee must also remove committer rights and membership from those found to
be violating the project's Code of Conduct or otherwise negatively affecting the
project's community health.

This Committee is not intended to make every technical decision, as those should
generally be made by agreement among committers as PRs are reviewed and merged.
Where disagreements take place and need further resolution, those can be brought
up with the Committee as part of its responsibility to maintain the project's
community health. Otherwise technical decisions are left to the active
committers (by virtue of the liberal contribution policy).

The Community Governance Committee should meet regularly, for example, once a
month. This meeting is a private meeting among just the Committee members to nominate
new committers and Committee members. Priority consideration should be given to
those actively contributing to the project. The Committee uses the consensus
seeking process outlined above when making decisions, including adding or
removing any members. The Committee should also discuss the community's health
and work to resolve any negative issues.

In order to maintain a healthy developer community, it is recommended that the
Committee also host a regular public community meeting. This meeting should be
open all members of the community, and start with an open forum to hear
questions or concerns from the community. Any remaining time in the meeting
should be used to discuss and review open pull requests or issues (especially
including design documents).

Project Committers
==================

The following people have been granted commit permissions (that is, write
access) to the Open Enclave SDK by the Community Governance Committee. The area
column describes which technical areas each committer is most interested in, and
therefore should usually be consulted for changes relating to that area.
However, it is up to each committer to determine who should review which PR, and
when to merge it. Remember that a PR must not be merged if a committer objects;
instead, it should be brought up with the Community Governance Committee.

| Name                  | GitHub Alias        | Area                           |
|-----------------------|---------------------|--------------------------------|
| Amaury Chamayou       | achamayou           | Build, CCF Integration         |
| Anand Krishnamoorthi  | anakrish            | Debugging, SGX, EDL, Dev Tools |
| Andrew Schwartzmeyer  | andschwa            | EDL, CMake, Git, Dev Tools     |
| Brett McLaren         | BRMcLaren           | Build, CMake, CI               |
| Brian Telfer          | Britel              | TrustZone, Attestation         |
| Simon Leet            | CodeMonkeyLeet      | SGX, APIs                      |
| Dave Thaler           | dthaler             | TrustZone, APIs, Dev Tools     |
| Emil Alexandru Stoica | EmilAlexandruStoica | Build, CMake, CI, Ansible      |
| Akash Gupta           | gupta-ak            | SGX, TrustZone, APIs           |
| Hernan Gatta          | HernanGatta         | TrustZone                      |
| Sergio Wong           | jazzybluesea        | Attestation, SGX               |
| Jiri Appl             | jiria               | Attestation, TrustZone         |
| John Kordich          | johnkord            | Build, CI, Dev Tools           |
| Xuejun Yang           | jxyang              | SGX                            |
| Mike Brasher          | mikbras             | SGX, APIs, EDL                 |
| Marius Oprin          | oprinmarius         | Build, CMake, CI, Ansible      |
| Paul Allen            | paulcallen          | TrustZone                      |
| Radhika Jandhyala     | radhikaj            | SGX, APIs                      |
| Shruti Ratnam         | shruti25ratnam      | Attestation                    |
| Cheng-mean Liu        | soccerGB            | Attestation, SGX               |
| Bruce Campbell        | yakman2020          | Windows, SGX                   |
