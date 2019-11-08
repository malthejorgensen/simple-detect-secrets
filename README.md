# simple-detect-secrets

## About

`simple-detect-secrets` tries to find secrets (passwords, auth tokens) in a
code base.

It is a fork of [detect-secrets](https://github.com/Yelp/detect-secrets), that
doesn't obfuscate/hash the secrets that it finds, doesn't have plugins, and
never calls the network!

## Example Usage

```
$ simple-detect-secrets scan
```

## Installation

```
$ pip install simple-detect-secrets
```

## Caveats

This is not meant to be a sure-fire solution to prevent secrets from entering
the codebase. Only proper developer education can truly do that. This pre-commit
hook merely implements several heuristics to try and prevent obvious cases of
committing secrets.

### Things that won't be prevented

- Multi-line secrets
- Default passwords that don't trigger the `KeywordDetector` (e.g. `login = "hunter2"`)
