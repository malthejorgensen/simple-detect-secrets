import re

from .base import RegexBasedDetector


class CloudantDetector(RegexBasedDetector):
    """Scans for Cloudant credentials."""

    secret_type = 'Cloudant Credentials'

    # opt means optional
    dot = r'\.'
    cl_account = r'[\w\-]+'
    cl = r'(?:cloudant|cl|clou)'
    opt_api = r'(?:api|)'
    cl_key_or_pass = opt_api + r'(?:key|pwd|pw|password|pass|token)'
    cl_pw = r'([0-9a-f]{64})'
    cl_api_key = r'([a-z]{24})'
    colon = r'\:'
    at = r'\@'
    http = r'(?:https?\:\/\/)'
    cloudant_api_url = r'cloudant\.com'
    denylist = [
        RegexBasedDetector.assign_regex_generator(
            prefix_regex=cl,
            secret_keyword_regex=cl_key_or_pass,
            secret_regex=cl_pw,
        ),
        RegexBasedDetector.assign_regex_generator(
            prefix_regex=cl,
            secret_keyword_regex=cl_key_or_pass,
            secret_regex=cl_api_key,
        ),
        re.compile(
            rf'{http}{cl_account}{colon}{cl_pw}{at}{cl_account}{dot}{cloudant_api_url}',
            flags=re.IGNORECASE,
        ),
        re.compile(
            rf'{http}{cl_account}{colon}{cl_api_key}{at}{cl_account}{dot}{cloudant_api_url}',
            flags=re.IGNORECASE,
        ),
    ]
