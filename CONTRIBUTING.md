# Contributing

Read the [experiment protocol](docs/RESEARCH.md#experiment-protocol) before
proposing a lab or changing a result. State the question, controlled variables,
expected and observed outcomes, limitations, and root-cause repair. Preserve
raw capture integrity and link a portable evidence export where available.
Never commit VM images, binaries, credentials, or host-specific capture paths.

Run `./scripts/validate.sh` from the repository root before opening a pull
request. Describe the relevant environment and any checks you could not run.
Keep changes focused and update the lab README and results when behavior or
interpretation changes. See [SECURITY.md](SECURITY.md) for private reporting of
vulnerabilities in the repository tooling.
