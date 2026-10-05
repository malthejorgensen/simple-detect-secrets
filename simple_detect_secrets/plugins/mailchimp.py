"""
This plugin searches for Mailchimp keys
"""

import re

from .base import RegexBasedDetector


class MailchimpDetector(RegexBasedDetector):
    """Scans for Mailchimp keys."""

    secret_type = 'Mailchimp Access Key'

    denylist = (re.compile(r'[0-9a-z]{32}-us[0-9]{1,2}'),)
