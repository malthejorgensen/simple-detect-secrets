import re

from .base import RegexBasedDetector


class SoftlayerDetector(RegexBasedDetector):
    """Scans for Softlayer credentials."""

    secret_type = 'SoftLayer Credentials'

    # opt means optional
    sl = r'(?:softlayer|sl)(?:_|-|)(?:api|)'
    key_or_pass = r'(?:key|pwd|password|pass|token)'
    secret = r'([a-z0-9]{64})'
    denylist = [
        RegexBasedDetector.assign_regex_generator(
            prefix_regex=sl,
            secret_keyword_regex=key_or_pass,
            secret_regex=secret,
        ),
        re.compile(
            r'(?:http|https)://api.softlayer.com/soap/(?:v3|v3.1)/([a-z0-9]{64})',
            flags=re.IGNORECASE,
        ),
    ]
