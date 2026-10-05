import pytest
import responses

from simple_detect_secrets.core.constants import VerifiedResult
from simple_detect_secrets.plugins.ibm_cloud_iam import IbmCloudIamDetector

CLOUD_IAM_KEY = 'abcd1234abcd1234abcd1234ABCD1234ABCD1234--__'
CLOUD_IAM_KEY_BYTES = b'abcd1234abcd1234abcd1234ABCD1234ABCD1234--__'


class TestIBMCloudIamDetector:
    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            (f'ibm-cloud_api_key: {CLOUD_IAM_KEY}', True),
            (f'ibm_cloud_iam-key : {CLOUD_IAM_KEY}', True),
            (f'IBM-API-KEY : "{CLOUD_IAM_KEY}"', True),
            (f'"iam_api_key" : "{CLOUD_IAM_KEY}"', True),
            (f'cloud-api-key: "{CLOUD_IAM_KEY}"', True),
            (f'"iam-password": "{CLOUD_IAM_KEY}"', True),
            (f'CLOUD_IAM_API_KEY:"{CLOUD_IAM_KEY}"', True),
            (f'ibm-cloud-key:{CLOUD_IAM_KEY}', True),
            (f'ibm_key:"{CLOUD_IAM_KEY}"', True),
            (
                f'"ibm_cloud_iam_api_key":"{CLOUD_IAM_KEY}"',
                True,
            ),
            (f'ibm_cloud_iamapikey= {CLOUD_IAM_KEY}', True),
            (f'ibm_cloud_api_key= "{CLOUD_IAM_KEY}"', True),
            (f'IBMCLOUDIAMAPIKEY={CLOUD_IAM_KEY}', True),
            (f'cloud_iam_api_key="{CLOUD_IAM_KEY}"', True),
            (f'ibm_api_key := {CLOUD_IAM_KEY}', True),
            (f'"ibm-iam_key" := "{CLOUD_IAM_KEY}"', True),
            (
                f'"ibm_cloud_iam_api_key":= "{CLOUD_IAM_KEY}"',
                True,
            ),
            (f'ibm-cloud_api_key:={CLOUD_IAM_KEY}', True),
            (f'"cloud_iam_api_key":="{CLOUD_IAM_KEY}"', True),
            (f'ibm_iam_key:= "{CLOUD_IAM_KEY}"', True),
            (f'ibm_api_key:="{CLOUD_IAM_KEY}"', True),
            (f'ibm_password = "{CLOUD_IAM_KEY}"', True),
            (f'ibm-cloud-pwd = {CLOUD_IAM_KEY}', True),
            (f'apikey:{CLOUD_IAM_KEY}', True),
            ('iam_api_key="%s" % IBM_IAM_API_KEY_ENV', False),
            ('CLOUD_APIKEY: "insert_key_here"', False),
            ('cloud-iam-key:=afakekey', False),
            ('fake-cloud-iam-key= "not_long_enough"', False),
        ],
    )
    def test_analyze_string_content(self, payload, should_flag):
        logic = IbmCloudIamDetector()

        output = logic.analyze_string_content(payload, 1, 'mock_filename')
        assert len(output) == (1 if should_flag else 0)

    @responses.activate
    def test_verify_invalid_secret(self):
        responses.add(
            responses.POST,
            'https://iam.cloud.ibm.com/identity/token',
            status=400,
        )

        assert IbmCloudIamDetector().verify(CLOUD_IAM_KEY) == VerifiedResult.VERIFIED_FALSE

    @responses.activate
    def test_verify_valid_secret(self):
        responses.add(
            responses.POST,
            'https://iam.cloud.ibm.com/identity/token',
            status=200,
        )

        assert IbmCloudIamDetector().verify(CLOUD_IAM_KEY) == VerifiedResult.VERIFIED_TRUE

    @responses.activate
    def test_verify_invalid_secret_bytes(self):
        responses.add(
            responses.POST,
            'https://iam.cloud.ibm.com/identity/token',
            status=400,
        )

        assert IbmCloudIamDetector().verify(CLOUD_IAM_KEY_BYTES) == VerifiedResult.VERIFIED_FALSE

    @responses.activate
    def test_verify_valid_secret_byes(self):
        responses.add(
            responses.POST,
            'https://iam.cloud.ibm.com/identity/token',
            status=200,
        )

        assert IbmCloudIamDetector().verify(CLOUD_IAM_KEY_BYTES) == VerifiedResult.VERIFIED_TRUE
