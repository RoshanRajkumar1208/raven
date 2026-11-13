# Security policy

## Use RAVEN responsibly

RAVEN sends real HTTP requests. Only scan APIs that you own or that you have
**written permission** to test. Scanning systems without permission can be illegal
in many countries (for example §202a–c StGB in Germany or the Computer Misuse Act
in the UK).

By default RAVEN only sends read requests (GET, HEAD, OPTIONS, TRACE). Write requests
(POST, PUT, PATCH, DELETE) are sent only with `--unsafe`, and should only be used
against test or staging systems with test data.

## Reporting a vulnerability in RAVEN

If you find a security problem in RAVEN itself (for example, the HTML report
failing to escape content from a scanned API), please do not open a public issue.
Use GitHub's **Report a vulnerability** button in the Security tab of this
repository, or email roshanrajkumar1208@gmail.com.

I aim to reply within 7 days.
