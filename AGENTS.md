# Repository Guidelines

## Project Structure & Module Organization

This repository ships two Python packages. The SDK lives in
`keepersdk-package/src/keepersdk/`; its unit tests are in
`keepersdk-package/unit_tests/` and credential-dependent checks are in
`keepersdk-package/manual_tests/`. The command-line client lives in
`keepercli-package/src/keepercli/`, with its tests under
`keepercli-package/unit_tests/`. Use `examples/sdk_examples/` and
`examples/cli_examples/` as runnable usage references. Packaging metadata and
dependencies are maintained independently in each package's `setup.cfg`,
`setup.py`, and `requirements.txt`.

## Build, Test, and Development Commands

Work from the repository root with Python 3.10 or newer:

```bash
python -m venv venv && source venv/bin/activate
pip install -e keepersdk-package/
python -m unittest discover -s keepersdk-package/unit_tests/
python -m build --wheel keepersdk-package
python -m build --wheel keepercli-package
```

The editable install makes local SDK changes immediately importable. The test
command is the same one used in CI. Install `build` first if needed
(`python -m pip install build`); wheel artifacts are written to each package's
`dist/` directory. To exercise the CLI locally, install its dependencies and
run `python -m keepercli`.

## Coding Style & Naming Conventions

Follow the existing Python style: four-space indentation, `snake_case` for
functions/modules/variables, `PascalCase` for classes, and concise imports at
the file top. Keep modules focused on their domain (for example,
`vault/record_management.py`). Add type annotations where surrounding code
uses them. No repository-wide formatter or linter is configured, so preserve
nearby formatting and avoid unrelated rewrites.

## Testing Guidelines

Use the standard-library `unittest` framework. Name files `test_<feature>.py`,
test classes `*TestCase`, and methods `test_<behavior>`. Put deterministic
coverage in `unit_tests/`; do not add credentials or live-service requirements
there. Run the relevant test file during development and the full SDK discovery
suite before submitting. There is no stated coverage threshold.

## Commit & Pull Request Guidelines

Recent history uses short imperative summaries, such as `Handle throttle api
response with retry mechanism`; include a PR number when applicable. Keep each
commit narrowly scoped. PRs should explain the behavior change, identify any
linked issue, include tests run, and call out package/version or configuration
effects. Provide CLI output or screenshots only when they clarify a user-facing
change.
