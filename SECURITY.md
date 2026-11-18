# Security policy

## Reporting a vulnerability in the probes

Report a security problem in the code of this repository privately, through GitHub
private vulnerability reporting: open the Security tab of the repository and choose
"Report a vulnerability". Do not open a public issue for it.

In scope:

- a way to make a probe run a command, start a program or load code that the person who
  runs it did not ask for, in particular in an elevated session
- a probe that overwrites, deletes or exposes a file or other state that it did not
  create
- a probe that opens a network connection, or makes Windows send credentials to another
  computer
- secrets or personal data in the repository

Out of scope: findings that you make with the probes in other software. Report those to
the vendor of that software.

Please include the probe name, the PowerShell version, the Windows version and the
command line that shows the problem.
