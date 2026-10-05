import pytest

from simple_detect_secrets.plugins.cloudant import CloudantDetector

CL_ACCOUNT = 'testy_-test'  # also called user
# only detecting 64 hex CL generated password
CL_PW = 'abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234'

# detecting 24 alpha for CL generated API KEYS
CL_API_KEY = 'abcdefghijabcdefghijabcd'


class TestCloudantDetector:
    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            (
                f'https://{CL_ACCOUNT}:{CL_PW}@{CL_ACCOUNT}.cloudant.com"',
                True,
            ),
            (
                f'https://{CL_ACCOUNT}:{CL_PW}@{CL_ACCOUNT}.cloudant.com/_api/v2/',
                True,
            ),
            (
                f'https://{CL_ACCOUNT}:{CL_PW}@{CL_ACCOUNT}.cloudant.com',
                True,
            ),
            (
                f'https://{CL_ACCOUNT}:{CL_API_KEY}@{CL_ACCOUNT}.cloudant.com',
                True,
            ),
            (
                f'https://{CL_ACCOUNT}:{CL_PW}.cloudant.com',
                False,
            ),
            (f"cloudant_password='{CL_PW}'", True),
            (f"cloudant_pw='{CL_PW}'", True),
            (f'cloudant_pw="{CL_PW}"', True),
            (f'clou_pw = "{CL_PW}"', True),
            (f'cloudant_key = "{CL_API_KEY}"', True),
            ('cloudant_password = "a-fake-tooshort-key"', False),
            ('cl_api_key = "a-fake-api-key"', False),
        ],
    )
    def test_analyze_string(self, payload, should_flag):
        logic = CloudantDetector()
        output = logic.analyze_line(payload, 1, 'mock_filename')

        assert len(output) == (1 if should_flag else 0)
