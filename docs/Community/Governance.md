Open Enclave SDK Community Governance Guidelines
==========================

Like all documentation, this is a living document, a work in progress, representing
approximately how the community operates and the principles which infuse our
culture today.

It should be edited and revised from time to time.

Core Principles
---------------
*NOTE(Aeva): Suggestion of principles only, but what ever they are, they should be articulated here*

The Open Enclave SDK community adheres to the principles of the Four Opens:

* **Open Source**: All project code and dependencies are open source; see contribution guidelines below.
* **Open Design**: Project planning and design discussions happen in transparent, collaborative, and accessible ways.
* **Open Development**: All ideas and contributions are welcome and accepted based on merit and alignment with project goals.
* **Open Community**: We are welcoming and respectful of everyone.


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
contributors. We value our community trememdously and want to build and maintain
a friendly, inclusive, collaborative environment for all our contributors and
users.

Community Governance Structure
------------------------------

*Note(Aeva) section added*

The Open Enclave SDK community uses a
[concensus-seeking](https://en.wikipedia.org/wiki/Consensus-seeking_decision-making)
approach to governance at all levels. To support a growing project, we have
adopted a loose hierarchy wherein domain-specific decisions are handled within
each domain, or Special Interest Group (**SIG**), cross-domain work is enabled
through Working Groups (**WG**), and a Community Governance Committee (**CGC**)
meets to review the overall structure, ensuring the health of the project.

Each group (SIGs, WGs, and CGC) maintain documentation in this repository.
Creating a new SIG or WG requires the approval of the CGC. SIGs are generally
responsible for code, whereas a WG is not.

SIG leaders are responsible for the code within their domain, and should be
considered authoritative for that subsection of the project's code base insofar
as code reviews and architectural discussions. When a change affects code owned
by multiple SIGs, it should be coordinated with the respective SIG leads.
Cross-SIG efforts can be coordinated by establishing a Working Group (WG), which
is given a charter and which reports progress back to the relevant SIG leaders
or the CGC.

If there is conflict, either within or between SIGs, or between any members of
the community, wherein it is desirable, the issue can be raised to the CGC.

Technical Discussions
---------------------

*Note(Aeva) section added*

Technical discussions generally happen in one of these places:

* [on the GitHub project](https://github.com/openenclave/openenclave), either in an Issue or a Pull Request
* in public SIG or WG meetings, which are typically held on Zoom (public calendar TBD)(TODO)
* on our mailing list or chat server (details TBD) (TODO)

While we strive for openness and transparency, it is natural that some
discussions will also happen in person (eg, in the hallway track) or other
private channels. The outcome of such discussions should be considered
non-binding until the information is shared through an open medium and relevant
stake-holders have opportunity to contribute to the discussion.

All SIG and WG leaders are responsible for creating and publishing minutes from
the meetings they hold, ensuring that the meetings are open and inclusive, and
that decisions they make are fair and transparent.

If a private discussion pertains to an open issue or PR, and results in a
decision, that item should be updated and reference given to the conversation.

Issue/PR Review Process
-----------------------

*Note(Aeva) section updated*

The community strives to triage and respond to all incoming issues within one
week. If you haven't heard anything by then, or an issue or PR is not getting
any response within a resonable time after it is triaged, please feel free to
remind us with a ping on the thread.

Security issues should be reported through a separate channel, and
will receive a response within 24 hours. See [Reporting Security
Issues](Contributing.md#reporting-security-issues).

Committers and Contributors
---------------------------

*Note(Aeva) section removed*

At present, we maintain a list of [Project Committers](Committers.md) along with
descriptions of their knowledge areas.

This will be updated and replaced with a more scaleable approach to
commit-rights management.

Accepting Contributions
-----------------------

*Note(Aeva) section updated*

SIGs will generally accept changes that improve the project and that align with the
[Open Enclave roadmap](https://github.com/openenclave/openenclave/projects).

All contributions are expected to be reviewed by at least one SIG lead other
than the contributor, and have no significant objections from other SIG leads
within the same SIG. Objections from leads of other SIGs should be respected,
and consensus sought (but not required); overruling the objection of another SIG
lead should only be done after careful consideration.

All contributions must also satisfy the
[contribution guidelines](Contributing.md), such as having a DCO and being
signed-off by the developer, having appropriate license headers in code files,
passing tests, and so on.

SIG leads may revert changes if they are found to be breaking, or if deemed necessary.
