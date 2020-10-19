# Security Advisory Process for Maintainers

## Reporting

For instructions on reporting a vulnerability, refer to the Open Enclave SDK [SECURITY.md](https://github.com/openenclave/openenclave/security/policy#reporting-a-vulnerability).

Vulnerability reporting for the OE SDK is currently still being handled through the [Microsoft Security Response Center (MSRC)](https://www.microsoft.com/en-us/msrc) as they:

- provide a 24-hour turnaround time for acknowledging reports
- maintain a [PGP key](https://www.microsoft.com/en-us/msrc/pgp-key-msrc#:~:text=MSRC%20PGP%20Key%20Last%20updated%3A%20October%2031%2C%202019,us.%20Click%20here%20to%20submit%20a%20security%20vulnerability) for secure reporting of vulnerabilities to secure@microsoft.com.

Once a vulnerability related to the Open Enclave SDK is reported to MSRC, the report is forwarded to the committers responsible for reviewing security issues:

- Anand Krishnamoorthi ([@anakrish](https://github.com/anakrish))
- Ming-Wei Shih ([@mingweishih](https://github.com/mingweishih))
- Simon Leet ([@codemonkeyleet](https://github.com/codemonkeyleet))

> - [ ] TODO: Formalize SIG-Security and its membership with the CGC.

## Handling Embargoed Vulnerabilities

The security reviewers are responsible for the initial triage of the report. This includes:

- reaching out to the appropriate OE SDK area owners or subject matter experts
- evaluating the severity of the issue against the bug bar
- writing up an initial assessment and a plan of action for MSRC
- coordinating with MSRC on additional information, acknowledgment, and public disclosure plans with the reporters of the issue

> - [ ] TODO: Clean up and finalize the security bug triage bar (PR #2634).

The report is treated as under embargo and will only be discussed using private communication channels.
All individuals entrusted with the information should exercise due diligence in maintaining its confidentiality.

> - [ ] TODO: Formalize the protected channel of communication for discussing the development of embargoed bug fixes (e.g., Protected mailing list, Element private channel).

If OE SDK needs to issue a Security Advisory to address the reported concern, one of the security reviewers will:

1. [Create](https://docs.github.com/en/github/managing-security-vulnerabilities/creating-a-security-advisory#creating-a-security-advisory)
   a new GitHub [Security Advisory (SA) for OE SDK](https://github.com/openenclave/openenclave/security/advisories).
   1. The description of the SA should accurately capture the nature, severity, and workarounds for the issue.
      1. It does not need to capture the full technical details of the vulnerability or fix for brevity.
2. [Request a Common Vulnerability Enumeration (CVE)](https://docs.github.com/en/github/managing-security-vulnerabilities/publishing-a-security-advisory#requesting-a-cve-identification-number) through GitHub.
   1. This was previously done through MSRC as a CVE Numbering Authority (CNA), but OE has shifted to using GitHub as the CNA as a Linux Foundation project.
3. [Assign the appropriate collaborators](https://docs.github.com/en/github/managing-security-vulnerabilities/adding-a-collaborator-to-a-security-advisory) to the SA, which includes:
   1. The assignee(s) responsible for fixing the issue.
   2. Any area owners or subject matter experts needed for review.
   3. CI/CD coordinators for private testing and integration with the release. (e.g., [@brmclaren](https://github.com/brmclaren)).
4. [Create a temporary private fork](https://docs.github.com/en/github/managing-security-vulnerabilities/collaborating-in-a-temporary-private-fork-to-resolve-a-security-vulnerability#creating-a-temporary-private-fork)
   to implement the code changes as part of the SA.
   1. The assignee should follow the GitHub instructions and create an `advisory-fix` branch for their code changes.
      1. The code changes should include an update to [CHANGELOG.md](/CHANGELOG.md) under the `### Security` subheader describing the issue addressed.
   2. Once the changes are ready for review, they should be submitted as a PR to the master branch of the temporary fork.
      1. GitHub does not currently appear to support requiring PR reviews to merge into the master branch of a temporary fork, so maintainers will need to enforce this process manually.
5. Reach out to the CI/CD maintainers to establish a private CI/CD pipeline for testing code changes.

By default, all SAs are targeted for inclusion into the next release of the OE SDK, which usually happens quarterly.
If the fix cannot be implemented or verified in time for an upcoming release, it can be included in a following patch version release.
The security reviewers are responsible for deciding if a patch release is needed to address a vulnerability before its scheduled public disclosure date.

Once the security fix is reviewed, tested, and merged into the temporary fork master branch for release,
the assignee and the release manager will coordinate integrating the fix into the release branch.
This usually includes:

1. Rebasing the temporary fork master branch to the project's master branch and testing the merged branch in private CI/CD.
2. Publishing the SA and merging its master branch into the project master branch.
   1. At this point, the vulnerability is considered publicly disclosed, and a new version of the OE SDK packages with the fix should be made available as quickly as possible.
3. Cherry-picking the fix to the release branch.
4. Building and releasing the OE SDK packages with the fix.
5. Updating the published SA with a pointer to the released packages containing the fix.

## Disclosure

The Open Enclave SDK project currently relies on the principles for [Coordinated Vulnerability Disclosure (CVD)](https://www.microsoft.com/en-us/msrc/cvd) put forth by MSRC.
The CVD includes a couple of policies such as:

- acknowledgment of vulnerability reports within 24 hours (via MSRC)
- supporting public disclosure within 90 days as the baseline, and negotiating that with vulnerability reporters and necessary

> - [ ] TODO: Establish a process and acceptance criteria for registering with OE SDK as a _Trusted Stakeholder_.
>   - A Trusted Stakeholder may not be a committer or maintainer of the SDK, but has a vested interest in the security of the OE SDK.
>     - For example, an enterprise with significant production deployments on OE SDK, a TEE-provider, or other software projects with critical integrations with OE SDK.
>   - The goal is to enable OE SDK to disclose issues material to their interests privately and allow them to participate in testing and provide feedback.
>   - We would need to figure out the legal concerns around GDPR and NDAs involved in maintaining such a list.
