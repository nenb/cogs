# Contributing

Cogs is implemented in staged security gates. Read `COGS.md`, `SECRET-INJECTION.md`, `DESIGN.md`, and `IMPLEMENTATION.md` in that order before changing architecture.

- Work through pull requests; `main` is protected.
- Add positive and negative tests for security-sensitive behavior.
- Never weaken a mandatory invariant to make a test pass.
- Pause for the ADR boundaries in `IMPLEMENTATION.md` section 47.
- Do not commit credentials, prompts, source captured from users, or raw session exports.
- Development containers and macOS VMs carry no authoritative security claim.

Nick Byrne (`@nenb`) is the initial code, security, ADR, and future AWS campaign reviewer.
