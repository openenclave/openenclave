Open Enclave SDK Community Governance Guidelines
==========================

**Note**
This document reflects the proposed state of governance *after* migration to SIGs and WGs is completed.

Like all documentation, this is a living document, a work in progress, representing
approximately how the community operates and the principles which infuse our
culture today.

It should be edited and revised from time to time.

Core Principles
---------------

The Open Enclave SDK community adheres to the principles of the Four Opens:

* **Open Community**: We are welcoming and respectful of everyone.
* **Open Design**: Project planning and design discussions happen in transparent, collaborative, and accessible ways.
* **Open Development**: All ideas and contributions are welcome and accepted based on merit and alignment with project goals.
* **Open Source**: All project code and dependencies are open source; see contribution guidelines below.

Code of Conduct
---------------

The Open Enclave SDK community abides by the
[OE SDK Code of Conduct](../CODE_OF_CONDUCT.md). Here is an
excerpt:

*In the interest of fostering an open and welcoming environment, we as
contributors and maintainers pledge to make participation in our project and our
community a harassment-free experience for everyone, regardless of age, body
size, disability, ethnicity, sex characteristics, gender identity and
expression, level of experience, education, socio-economic status, nationality,
personal appearance, race, religion, or sexual identity and orientation.*

As a member of the OE SDK project, you represent the project and your fellow
contributors. We value our community tremendously and want to build and maintain
a friendly, inclusive, collaborative environment for all our contributors and
users.

If there is conflict, either within or between SIGs, or between any members of
the community, wherein it is desirable, the issue can be raised to the [CGC](governance/README.md).

Community Governance Structure
------------------------------

The Open Enclave SDK community uses a
[consensus-seeking](https://en.wikipedia.org/wiki/Consensus-seeking_decision-making)
approach to governance at all levels. To support a growing project, we have
adopted a loose hierarchy wherein domain-specific decisions are handled within
each domain, or Special Interest Group (**SIG**), cross-domain work is enabled
through Working Groups (**WG**), and a Community Governance Committee (**CGC**)
meets to review the overall structure, ensuring the health of the project.

Each group (SIGs, WGs, and CGC) shall maintain documentation in this repository.
Creating a new SIG or WG requires the approval of the CGC, and is formally
created by the merging of a "charter" document. A SIG is generally responsible
for the delivery of a technical artifact (code, release binaries, operation of
infrastructure, etc), whereas a WG is generally not responsible for these types
of artifacts.

A SIG Chair is responsible for the health of that SIG, and should be considered
authoritative for that subsection of the project's code base insofar as code or
other technical deliverables are a responsibility of that SIG. It is the SIG
Chair's responsibility to ensure there are sufficient Approvers and Reviewers to
support the development velocity and SIG health, and ensure a succession plan is
in place should the chair intend to step down. Each SIG is responsible for
establishing its own governance process (defining the process for SIG Chair
selection, for example).

When a change affects code owned by multiple SIGs, it should be coordinated with
the respective SIGs. If long-term collaboration is anticipated, cross-SIG
efforts can be coordinated by establishing a Working Group (WG), which is given
a charter and which reports progress back to the relevant SIGs and/or the CGC.

An example of this is the [Architecture SIG](sig-architecture), which is a
special kind of Working Group in that it exists across SIGs but owns delivery of
architecture documents and plans, and is therefore designated as a SIG.

New SIGs can be created by copying the
[SIG charter template](governance/sig-charter-template.md) and making a proposal
to the CGC. Templates for WGs and Committees may be added in the future.

Technical Discussions
---------------------

Technical discussions generally happen in one of these places:

* [on the GitHub project](https://github.com/openenclave/openenclave), either in
  an Issue or a Pull Request
* in the public meetings of Committees, Special Interest Groups, or Working Groups, which can be found via the [community calendar](https://lists.confidentialcomputing.io/calendar).
* on the community mailing list or chat server, which is detailed in the [Communications](Communication.md) document

While we strive for openness and transparency, it is natural that some
discussions will also happen in private channels, or in impromptu face-to-face
conversations (for those who work in the same building, or bump into each other
at a conference). The outcome of such discussions should be considered
non-binding until the information is shared through an open medium and relevant
stake-holders have the opportunity to contribute to the discussion.

All SIG and WG leaders are responsible for their groups' creation of minutes from
any meetings which they may hold, ensuring that the meetings are open and inclusive, and
that decisions they make are fair and transparent.

If a private discussion pertains to an open issue or PR, and results in a
decision, that item should be updated and reference given to the conversation.

Project-wide technical discussions are currently handled in
[SIG-Architecture](sig-architecture/README.md) meetings. This SIG is comprised
of the Leads of all other SIGs and functions analogously to a "technical
steering committee" in other projects.

Issue/PR Review Process
-----------------------

The community strives to triage and respond to all incoming issues within one
week. If you haven't heard anything by then, or an issue or PR is not getting
any response within a reasonable time after it is triaged, please feel free to
remind us with a ping on the thread.

Security issues should be reported through a separate channel, and
will receive a response within 24 hours. See [Reporting Security
Issues](Contributing.md#reporting-security-issues).

Committers and Contributors
---------------------------

At present, we maintain a list of [Project Committers](Committers.md) along with
descriptions of their knowledge areas.

This will be updated and replaced with a more scalable approach to commit-rights
management that integrates with SIG/WG governance. In the interrim, all current
Committers should be considered to be Approvers using the new terminology.

**Proposal** The following roles would be sufficient for SIGs, WGs, and
Committees to self-govern.

- **Chair**: the primary point of contact for a SIG or WG, responsible for the
  processes within the SIG; a tie-breaker in votes within the SIG, if needed
- **Approver**: members of the SIG who are empowered to approve code changes
- **Reviewer**: members of the SIG whose knowledge is respected by Approvers,
  and whom are frequently asked to provide code reviews for patches
- **Member**: a voting member of a working group (role does not apply to SIGs)
- **Emeritus**: a previously-active member of a SIG or WG, who has no current
  rights but whose contributions the community wishes to honor, and who may
  receive a fast-track back to privileges should they become active in this
  group again

Accepting Contributions
-----------------------

SIGs will generally accept changes that improve the project and that align with the
[Open Enclave roadmap](https://github.com/openenclave/openenclave/projects).

All contributions are expected to be reviewed by at least one *Reviewer* or
*Approver* other than the contributor, and have no significant objections from
other *Reviewers* or *Approvers*, within the same SIG. Each SIG may,
optionally, establish its own review criteria, as outlined in that SIG's
charter.

If a change requires the approval of multiple SIGs (e.g., because it affects
code in both SIG domains), then approval from both SIGs is required.

If a change only requires one approval from one SIG, and another SIG objects to
it, a discussion should be invited and given reasonable time to move towards a
consensus; overruling the objection of another SIG should only be done after
careful consideration. *Even when we disagree, our community leaders aspire to
uphold our [core principles](#core-principles).*

All contributions must also satisfy the
[contribution guidelines](Contributing.md), such as having a
[Developer Certificate of Origin (DCO)](https://developercertificate.org/) and
being signed-off by the developer, having appropriate license headers in code
files, passing tests, and so on.
