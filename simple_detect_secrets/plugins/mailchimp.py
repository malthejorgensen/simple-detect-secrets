"""
This plugin searches for Mailchimp keys
"""

import re
from base64 import b64encode

import requests

from ..core.constants import VerifiedResult
from .base import RegexBasedDetector


class MailchimpDetector(RegexBasedDetector):
    """Scans for Mailchimp keys."""

    secret_type = 'Mailchimp Access Key'

    denylist = (re.compile(r'[0-9a-z]{32}-us[0-9]{1,2}'),)

    def verify(self, token, **kwargs):  # pragma: no cover
        _, datacenter_number = token.split('-us')

        response = requests.get(
            f'https://us{datacenter_number}.api.mailchimp.com/3.0/',
            headers={
                'Authorization': b'Basic '
                + b64encode(
                    f'any_user:{token}'.encode(),
                ),
            },
        )
        return (
            VerifiedResult.VERIFIED_TRUE
            if response.status_code == 200
            else VerifiedResult.VERIFIED_FALSE
        )
