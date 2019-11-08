from __future__ import absolute_import

import pytest

from simple_detect_secrets.plugins.basic_auth import BasicAuthDetector


class TestBasicAuthDetector(object):

    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            ('https://username:password@yelp.com', True),
            ('http://localhost:5000/<%= @variable %>', False),
            ('"https://url:8000";@something else', False),
            ('\'https://url:8000\';@something else', False),
            ('https://url:8000 @something else', False),
            ('https://url:8000/ @something else', False),
        ],
    )
    def test_analyze_line(self, payload, should_flag):
        logic = BasicAuthDetector()

        output = logic.analyze_line(payload, 1, 'mock_filename')
        assert len(output) == int(should_flag)
