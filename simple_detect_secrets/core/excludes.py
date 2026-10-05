import os
import re
from fnmatch import fnmatchcase


def is_excluded(filename, patterns):
    """Match case-sensitive globs against relative paths and their parent directories.

    Patterns without slashes match any path component. String values represent
    legacy baseline regexes; new CLI exclusions are always lists of globs.
    """
    if not patterns:
        return False
    if isinstance(patterns, str):
        return re.search(patterns, os.fspath(filename), re.IGNORECASE) is not None

    path = os.path.relpath(filename).replace(os.sep, '/')
    parts = path.split('/')
    ancestors = ['/'.join(parts[:index]) for index in range(1, len(parts) + 1)]
    for pattern in patterns:
        while pattern.startswith('./'):
            pattern = pattern[2:]
        pattern = pattern.rstrip('/')
        candidates = ancestors if '/' in pattern else parts
        if any(fnmatchcase(candidate, pattern) for candidate in candidates):
            return True
    return False
