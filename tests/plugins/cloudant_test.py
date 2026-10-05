
import textwrap

import pytest
import responses

from simple_detect_secrets.core.constants import VerifiedResult
from simple_detect_secrets.plugins.cloudant import CloudantDetector, find_account

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

    @responses.activate
    def test_verify_invalid_secret(self):
        cl_api_url = f'https://{CL_ACCOUNT}:{CL_PW}@{CL_ACCOUNT}.cloudant.com'
        responses.add(
            responses.GET,
            cl_api_url,
            json={'error': 'unauthorized'},
            status=401,
        )

        assert (
            CloudantDetector().verify(
                CL_PW,
                f'cloudant_host={CL_ACCOUNT}',
            )
            == VerifiedResult.VERIFIED_FALSE
        )

    @responses.activate
    def test_verify_valid_secret(self):
        cl_api_url = f'https://{CL_ACCOUNT}:{CL_PW}@{CL_ACCOUNT}.cloudant.com'
        responses.add(
            responses.GET,
            cl_api_url,
            json={'id': 1},
            status=200,
        )
        assert (
            CloudantDetector().verify(
                CL_PW,
                f'cloudant_host={CL_ACCOUNT}',
            )
            == VerifiedResult.VERIFIED_TRUE
        )

    @responses.activate
    def test_verify_unverified_secret(self):
        assert (
            CloudantDetector().verify(
                CL_PW,
                f'cloudant_host={CL_ACCOUNT}',
            )
            == VerifiedResult.UNVERIFIED
        )

    def test_verify_no_secret(self):
        assert (
            CloudantDetector().verify(
                CL_PW,
                f'no_un={CL_ACCOUNT}',
            )
            == VerifiedResult.UNVERIFIED
        )

    @pytest.mark.parametrize(
        'content, expected_output',
        (
            (
                textwrap.dedent("""
                    --cloudant-hostname = {}
                """)[1:-1].format(
                    CL_ACCOUNT,
                ),
                [CL_ACCOUNT],
            ),
            # With quotes
            (
                textwrap.dedent("""
                    cl_account = "{}"
                """)[1:-1].format(
                    CL_ACCOUNT,
                ),
                [CL_ACCOUNT],
            ),
            # multiple candidates
            (
                textwrap.dedent("""
                    cloudant_id = '{}'
                    cl-user = '{}'
                    CLOUDANT_USERID = '{}'
                    cloudant-uname: {}
                """)[1:-1].format(
                    CL_ACCOUNT,
                    'test2_testy_test',
                    'test3-testy-testy',
                    'notanemail',
                ),
                [
                    CL_ACCOUNT,
                    'test2_testy_test',
                    'test3-testy-testy',
                    'notanemail',
                ],
            ),
            # In URL
            (
                f'https://{CL_ACCOUNT}:{CL_API_KEY}@{CL_ACCOUNT}.cloudant.com',
                [CL_ACCOUNT],
            ),
            (
                f'https://{CL_ACCOUNT}.cloudant.com',
                [CL_ACCOUNT],
            ),
        ),
    )
    def test_find_account(self, content, expected_output):
        assert find_account(content) == expected_output
