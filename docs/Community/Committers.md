Project Committers
==================

Current Status
--------------

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
| Marius Oprin          | oprinmarius         | Build, CMake, CI, Ansible      |
| Paul Allen            | paulcallen          | TrustZone                      |
| Radhika Jandhyala     | radhikaj            | SGX, APIs, Website             |
| Shruti Ratnam         | shruti25ratnam      | Attestation                    |
| Cheng-mean Liu        | soccerGB            | Attestation, SGX               |
| Bruce Campbell        | yakman2020          | Windows, SGX                   |

Desired Status
--------------

As the project grows, in order to scale the management of the project, it is becoming increasingly necessary to delegate responsibility to domain-owners and improve the community's development workflow through automation. This will be handled through the use of [Prow](https://git.k8s.io/test-infra/prow).

Commits should be fully gated through automated checks, with only a skeleton-crew of folks (a subset of the governance committee) able to directly merge code (and this power is only there for emergency measures, eg. if Prow has failed and needs to be restored).

Ownership should be defined through directory-specific OWNERS files. All actions, such as initiating a test or merging code, should be performed through comments on GitHub that interact with the Prow bot.

For a discussion of why this approach was adopted by other projects, and an exploration of how it works in practice, see
https://kubernetes.io/blog/2018/08/29/the-machines-can-do-the-work-a-story-of-kubernetes-testing-ci-and-automating-the-contributor-experience/
