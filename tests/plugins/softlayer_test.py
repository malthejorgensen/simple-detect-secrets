import pytest

from simple_detect_secrets.plugins.softlayer import SoftlayerDetector

SL_TOKEN = 'abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234'


class TestSoftlayerDetector:
    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            (f'--softlayer-api-key "{SL_TOKEN}"', True),
            (f'--softlayer-api-key="{SL_TOKEN}"', True),
            (f'--softlayer-api-key {SL_TOKEN}', True),
            (f'--softlayer-api-key={SL_TOKEN}', True),
            (f'http://api.softlayer.com/soap/v3/{SL_TOKEN}', True),
            (f'http://api.softlayer.com/soap/v3.1/{SL_TOKEN}', True),
            (f'softlayer_api_key: {SL_TOKEN}', True),
            (f'softlayer-key : {SL_TOKEN}', True),
            (f'SOFTLAYER-API-KEY : "{SL_TOKEN}"', True),
            (f'"softlayer_api_key" : "{SL_TOKEN}"', True),
            (f'softlayer-api-key: "{SL_TOKEN}"', True),
            (f'"softlayer_api_key": "{SL_TOKEN}"', True),
            (f'SOFTLAYER_API_KEY:"{SL_TOKEN}"', True),
            (f'softlayer-key:{SL_TOKEN}', True),
            (f'softlayer_key:"{SL_TOKEN}"', True),
            (f'"softlayer_api_key":"{SL_TOKEN}"', True),
            (f'softlayerapikey= {SL_TOKEN}', True),
            (f'softlayer_api_key= "{SL_TOKEN}"', True),
            (f'SOFTLAYERAPIKEY={SL_TOKEN}', True),
            (f'softlayer_api_key="{SL_TOKEN}"', True),
            (f'sl_api_key: {SL_TOKEN}', True),
            (f'SLAPIKEY : {SL_TOKEN}', True),
            (f'sl_apikey : "{SL_TOKEN}"', True),
            (f'"sl_api_key" : "{SL_TOKEN}"', True),
            (f'sl-key: "{SL_TOKEN}"', True),
            (f'"sl_api_key": "{SL_TOKEN}"', True),
            (f'sl_api_key:"{SL_TOKEN}"', True),
            (f'sl_api_key:{SL_TOKEN}', True),
            (f'sl-api-key:"{SL_TOKEN}"', True),
            (f'"sl_api_key":"{SL_TOKEN}"', True),
            (f'sl_key= {SL_TOKEN}', True),
            (f'sl_api_key= "{SL_TOKEN}"', True),
            (f'sl-api-key={SL_TOKEN}', True),
            (f'slapi_key="{SL_TOKEN}"', True),
            (f'slapikey:= {SL_TOKEN}', True),
            (f'softlayer_api_key := {SL_TOKEN}', True),
            (f'sl_api_key := "{SL_TOKEN}"', True),
            (f'"softlayer_key" := "{SL_TOKEN}"', True),
            (f'sl_api_key: "{SL_TOKEN}"', True),
            (f'"softlayer_api_key":= "{SL_TOKEN}"', True),
            (f'sl-api-key:="{SL_TOKEN}"', True),
            (f'softlayer_api_key:={SL_TOKEN}', True),
            (f'slapikey:"{SL_TOKEN}"', True),
            (f'"softlayer_api_key":="{SL_TOKEN}"', True),
            (f'sl-api-key:= {SL_TOKEN}', True),
            (f'softlayer_key:= "{SL_TOKEN}"', True),
            (f'sl_api_key={SL_TOKEN}', True),
            (f'softlayer_api_key:="{SL_TOKEN}"', True),
            (f'softlayer_password = "{SL_TOKEN}"', True),
            (f'sl_pass="{SL_TOKEN}"', True),
            (f'softlayer-pwd = {SL_TOKEN}', True),
            ('softlayer_api_key="%s" % SL_API_KEY_ENV', False),
            ('sl_api_key: "%s" % <softlayer_api_key>', False),
            ('SOFTLAYER_APIKEY: "insert_key_here"', False),
            ('sl-apikey: "insert_key_here"', False),
            ('softlayer-key:=afakekey', False),
            ('fake-softlayer-key= "not_long_enough"', False),
        ],
    )
    def test_analyze_line(self, payload, should_flag):
        logic = SoftlayerDetector()

        output = logic.analyze_line(payload, 1, 'mock_filename')
        assert len(output) == (1 if should_flag else 0)
