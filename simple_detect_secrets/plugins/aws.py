"""
This plugin searches for AWS key IDs
"""

import re

from .base import RegexBasedDetector, classproperty


class AWSKeyDetector(RegexBasedDetector):
    """Scans for AWS keys."""

    secret_type = 'AWS Access Key'

    denylist = (re.compile(r'(?:AKIA|ASIA)[0-9A-Z]{16}'),)

    @classproperty
    def disable_flag_text(cls):
        return 'no-aws-key-scan'
