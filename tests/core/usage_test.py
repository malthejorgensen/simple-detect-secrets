from __future__ import absolute_import

import pytest

from simple_detect_secrets.core.usage import ParserBuilder
from simple_detect_secrets.plugins.common.util import import_plugins


class TestPluginOptions(object):

    @staticmethod
    def parse_args(argument_string=''):
        # PluginOptions are added in pre-commit hook
        return ParserBuilder()\
            .add_pre_commit_arguments()\
            .parse_args(argument_string.split())

    def test_added_by_default(self):
        # This is what happens with unrecognized arguments
        with pytest.raises(SystemExit):
            self.parse_args('--unrecognized-argument')

        self.parse_args('--no-private-key-scan')

    def test_consolidates_output_basic(self):
        """Everything enabled by default, with default values"""
        args = self.parse_args()

        regex_based_plugins = {
            key: {}
            for key in import_plugins()
        }
        regex_based_plugins.update({
            'HexHighEntropyString': {
                'hex_limit': 3,
            },
            'Base64HighEntropyString': {
                'base64_limit': 4.5,
            },
            'KeywordDetector': {
                'keyword_exclude': None,
            },
        })
        assert not hasattr(args, 'no_private_key_scan')

    def test_consolidates_removes_disabled_plugins(self):
        args = self.parse_args('--no-private-key-scan')

        assert 'PrivateKeyDetector' not in args.plugins

    @pytest.mark.parametrize(
        'argument_string,expected_value',
        [
            ('--hex-limit 5', 5.0),
            ('--hex-limit 2.3', 2.3),
            ('--hex-limit 0', 0),
            ('--hex-limit 8', 8),
            ('--hex-limit -1', None),
            ('--hex-limit 8.1', None),
        ],
    )
    def test_custom_limit(self, argument_string, expected_value):
        if expected_value is not None:
            args = self.parse_args(argument_string)

            assert (
                args.plugins['HexHighEntropyString']['hex_limit']

                == expected_value
            )
        else:
            with pytest.raises(SystemExit):
                self.parse_args(argument_string)
