Project Committers
==================

**NOTE**
This document will be superseded by the creation of SIGs and WGs.

It is kept for now as the discussion and definition of the [new governance process](Governance.md) is ongoing.

List of Committers
------------------

The following people have been granted commit permissions (that is, write
access) to the Open Enclave SDK by the Community Governance Committee. The area
column describes which technical areas each committer is most interested in, and
therefore should usually be consulted for changes relating to that area.


| Name                  | GitHub Alias        | Area                           |
|-----------------------|---------------------|--------------------------------|
| Amaury Chamayou       | achamayou           | Build, CCF Integration         |
| Anand Krishnamoorthi  | anakrish            | Debugging, SGX, EDL, Dev Tools |
| Andrew Schwartzmeyer  | andschwa            | EDL, CMake, Dev Tools, Website |
| Brett McLaren         | BRMcLaren           | Build, CMake, CI               |
| Brian Telfer          | Britel              | TrustZone, Attestation         |
| Simon Leet            | CodeMonkeyLeet      | SGX, APIs                      |
| Dave Thaler           | dthaler             | TrustZone, APIs, Dev Tools     |
| Emil Alexandru Stoica | EmilAlexandruStoica | Build, CMake, CI, Ansible      |
| Akash Gupta           | gupta-ak            | SGX, Attestation, APIs         |
| Hernan Gatta          | HernanGatta         | TrustZone                      |
| Sergio Wong           | jazzybluesea        | Attestation, SGX               |
| Jiri Appl             | jiria               | Attestation, TrustZone         |
| John Kordich          | johnkord            | Build, CI, Dev Tools, Release  |
| Jordan Hand           | jhand2              | Windows, Build, SGX            |
| Xuejun Yang           | jxyang              | SGX                            |
| Mike Brasher          | mikbras             | SGX, APIs, EDL                 |
| Ming-Wei Shih         | mingweishih         | SGX, Dev tools, EDL            |
| Marius Oprin          | oprinmarius         | Build, CMake, CI, Ansible      |
| Paul Allen            | paulcallen          | TrustZone                      |
| Radhika Jandhyala     | radhikaj            | SGX, APIs, Website             |
| Shruti Ratnam         | shruti25ratnam      | Attestation                    |
| Cheng-mean Liu        | soccerGB            | Attestation, SGX               |
| Bruce Campbell        | yakman2020          | Windows, SGX                   |

Current Expectations
--------------------

However, it is up to each committer to determine who should review which PR, and
when to merge it. It is up to each committer to decide [when to accept a contribution](Governance.md#Accepting-Contributions).

Current Challenges
------------------

As the project has grown, some community members are frustrated with the current
GitHub workflows and reviewer expectations. The structure described above is not
programatically enforced, and not represented through any of the development
tools (ie, GitHub itself).

As more developers join the community and bring domain-specific knowledge, there
is no way to delegate domain ownership, authority or autonomy over changes to
code. And as the community itself grows, the current communication channels do
not support rapid iteration, or facilitate remote and open collaboration.

Specific challenges:

* any change to commit rights must be done through a manual GitHub UI process,
  which is not tracked in the project's git history
* commit rights are not granular (every Committer in the list above has commit
  rights on the entire code base, rather than their "Area")
* integration of third-party test systems (downstream CI/CD) is difficult and not documented
* permission to initiate a test run is limited to committers and requires an
  out-of-tree action to change
