import pytest

from simple_detect_secrets.core.excludes import is_excluded


@pytest.mark.parametrize(
    'filename,patterns,expected',
    [
        ('debug.log', ['*.log'], True),
        ('nested/debug.log', ['*.log'], True),
        ('debug.LOG', ['*.log'], False),
        ('src/main.py', ['vendor/*', '*.log'], False),
        ('vendor/nested/main.py', ['vendor/*'], True),
        ('src/vendor/main.py', ['vendor/*'], False),
        ('src/vendor/main.py', ['vendor'], True),
        ('src/.venv/main.py', ['.venv'], True),
        ('vendor/main.py', ['./vendor/'], True),
        ('nested/file1.txt', ['file[12].txt'], True),
        ('nested/file3.txt', ['file[12].txt'], False),
        ('a.py', ['*.log', '*.py'], True),
        ('a.py', [], False),
    ],
)
def test_globs(filename, patterns, expected):
    assert is_excluded(filename, patterns) is expected


def test_legacy_baseline_regex():
    assert is_excluded('legacy/private.py', r'^legacy/.*\.py$')
    assert not is_excluded('other/private.py', r'^legacy/.*\.py$')
