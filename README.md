simple-detect-secrets
=====================

`simple-detect-secrets` tries to find secrets (passwords, auth tokens) in a codebase.

In git repositories, `simple-detect-secrets` only scans checked-in files.
Otherwise it scans all files.

Diagnostics go to stderr, with the scan mode and file count on one line:
`No git repository detected: Scanning all files (2 files)` or
`Detected git repository: Scanning only Git-tracked files (2 files)`.
Empty scans report `No files detected (0 files)`.

Running
-------

Simply run

    uvx simple-detect-secrets

in a directory to search for possible secrets.

Findings go to stdout in `filename:lineno:full source line` format, like grep.
Each matching line appears once, preserving its indentation and spacing.

Exclude files or directories with repeatable, quoted glob patterns:

```bash
uvx simple-detect-secrets --exclude '*.log' --exclude 'vendor/*' --exclude '.venv'
```

Developing
----------

```bash
uv sync --locked
uv run simple-detect-secrets
uv run pytest tests
```

Build the source distribution and wheel with `uv build`. Install the optional
word-list support with `uv sync --extra word_list`.

### Profiling
Use `uvx simple-detect-secrets --profile` to report elapsed seconds spent in
each enabled detector, summed across files and listed slowest first. The report
goes to stderr. Timings include each detector's file reading and parsing, but
exclude file discovery, detector initialization, and result formatting.
Profiling also works with `--string` and `--update`.

Caveats
-------

This is not meant to be a sure-fire solution to prevent secrets from entering
the codebase. Only proper developer education can truly do that. This pre-commit
hook merely implements several heuristics to try and prevent obvious cases of
committing secrets.

Things that won't be prevented
------------------------------

- Multi-line secrets
- Default passwords that don't trigger the `KeywordDetector` (e.g. `login = "hunter2"`)

Notes
-----

This is an old fork of Yelp's [detect-secrets](https://github.com/Yelp/detect-secrets).

This is a command line tool:

- never calls the network
- doesn't obfuscate/hash the secrets that it finds
- doesn't have plugins
