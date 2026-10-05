from io import StringIO

import pytest

from simple_detect_secrets.plugins.aws import AWSKeyDetector
from simple_detect_secrets.plugins.base import BasePlugin


@pytest.mark.parametrize(
    'content, expected', [('AKIAZZZZZZZZZZZZZZZZ', 'True'), ('hello', 'False')]
)
def test_adhoc_scan_reports_detection(content, expected):
    assert AWSKeyDetector().adhoc_scan(content) == expected


def test_file_scan_keeps_detected_secrets_without_verification_metadata():
    results = AWSKeyDetector().analyze(StringIO('AKIAZZZZZZZZZZZZZZZZ\n'), 'credentials')
    assert len(results) == 1
    assert 'is_verified' not in next(iter(results)).json()


@pytest.mark.parametrize(
    'name, expected',
    (
        ('HexHighEntropyString', 'no-hex-high-entropy-string-scan'),
        ('KeywordDetector', 'no-keyword-scan'),
        ('PrivateKeyDetector', 'no-private-key-scan'),
    ),
)
def test_disable_flag_text(name, expected):
    class MockPlugin(BasePlugin):
        @property
        def secret_type(self):  # pragma: no cover
            return ''

    MockPlugin.__name__ = str(name)

    assert MockPlugin.disable_flag_text == expected
