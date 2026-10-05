import re

from .base import RegexBasedDetector


class StripeDetector(RegexBasedDetector):
    """Scans for Stripe keys."""

    secret_type = 'Stripe Access Key'

    denylist = (
        # Stripe standard keys begin with sk_live and restricted with rk_live
        re.compile(r'(?:r|s)k_live_[0-9a-zA-Z]{24}'),
    )
