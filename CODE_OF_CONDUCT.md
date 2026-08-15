# Code of Conduct

## Our commitment

We want VIGIL to be a project where people can do careful security work without friction from
each other. Everyone participating — contributors, reporters, reviewers, maintainers — is
expected to help keep it that way.

## Expected behaviour

- Assume competence and good faith. Most disagreements in security engineering are about
  threat models, not intelligence.
- Be specific. "This is insecure" is not a review; "an attacker who controls the request body
  can set `verified`" is.
- Accept that being wrong is normal. This project's own history includes a canonicalization
  bug that made two different actions hash differently, an authentication flag that could be
  asserted by the caller it was meant to authenticate, and a detector rule that flagged its
  own project's documentation. Finding those is the work, not a failure of it.
- Respect the effort behind a report or a patch, including when the answer is no.

## Unacceptable behaviour

- Harassment, personal attacks, or demeaning comments about people rather than code.
- Publishing others' private information.
- Sustained disruption of discussions or review.
- Deliberately introducing vulnerabilities, misleading security claims, or misrepresenting
  what a control does. In a security project this is a form of harm, not a prank.

## Security reports

Vulnerability reports follow [SECURITY.md](SECURITY.md), not the public issue tracker.
Reporters acting in good faith will not be penalised for what they find, including when a
finding is embarrassing to the project.

## Scope

Applies in the repository, issue tracker, pull requests, and any project space, plus public
spaces when someone is representing the project.

## Enforcement

Report conduct concerns privately to the maintainers via
[GitHub private reporting](https://github.com/bbrookhart/VIGIL/security/advisories/new), which
is the only confidential channel this project currently operates. Reports are handled
confidentially. Maintainers may warn, remove content, or
ban for repeated or severe behaviour, and will explain the reason where doing so does not
compromise a reporter's privacy.

Maintainers who do not follow this document are subject to it in the same way.

## Attribution

Adapted from the [Contributor Covenant](https://www.contributor-covenant.org), version 2.1.
