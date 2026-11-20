# Security

aftermath reads the local machine. It does not open network connections, and the scanner packages do not import `net`, `net/http`, or `os/exec`.

## Reporting a vulnerability

Please report vulnerabilities privately. Use either:

- GitHub private vulnerability reporting on this repository (Security tab, "Report a vulnerability"), or
- email to info@uc.surf

Include the version, the command you ran, and what you expected. Do not open a public issue for an unfixed vulnerability.

A report that only describes a persistence technique already covered by a public advisory is not, by itself, a vulnerability in aftermath. A vulnerability here is a flaw in this program: for example, reading a file it should not read, printing a secret it should have redacted, or executing something it found.

## Disclosure

We will acknowledge reports sent to info@uc.surf. Fixes land in this repository. This project does not operate a paid bounty.
