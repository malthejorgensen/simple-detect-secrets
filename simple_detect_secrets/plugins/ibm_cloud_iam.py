from .base import RegexBasedDetector


class IbmCloudIamDetector(RegexBasedDetector):
    """Scans for IBM Cloud IAM Key."""

    secret_type = 'IBM Cloud IAM Key'

    # opt means optional
    opt_ibm_cloud_iam = (
        r'(?:ibm(?:_|-|)cloud(?:_|-|)iam|cloud(?:_|-|)iam|'
        + r'ibm(?:_|-|)cloud|ibm(?:_|-|)iam|ibm|iam|cloud|)'
    )
    opt_dash_undrscr = r'(?:_|-|)'
    opt_api = r'(?:api|)'
    key_or_pass = r'(?:key|pwd|password|pass|token)'
    secret = r'([a-zA-Z0-9_\-]{44})'
    denylist = [
        RegexBasedDetector.assign_regex_generator(
            prefix_regex=opt_ibm_cloud_iam + opt_dash_undrscr + opt_api,
            secret_keyword_regex=key_or_pass,
            secret_regex=secret,
        ),
    ]
