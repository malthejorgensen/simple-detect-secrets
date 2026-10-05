import pytest

from simple_detect_secrets.plugins.jwt import JwtTokenDetector


class TestJwtTokenDetector:
    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            # valid jwt
            (
                'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
                True,
            ),
            # valid jwt - but header contains CR/LF-s
            (
                'eyJ0eXAiOiJKV1QiLA0KImFsZyI6IkhTMjU2In0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ',
                True,
            ),
            # valid jwt - but claims contain bunch of LF newlines
            (
                'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjoiSm9lIiwKInN0YXR1cyI6ImVtcGxveWVlIgp9',
                True,
            ),
            # valid jwt - claims contain strings with unicode accents
            (
                'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IsWww6HFkcOtIMOWxZHDqcOoIiwiaWF0IjoxNTE2MjM5MDIyfQ.k5HibI_uLn_RTuPcaCNkaVaQH2y5q6GvJg8GPpGMRwQ',
                True,
            ),
            # no signature - but still valid
            (
                'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ',
                True,
            ),
            # decoded - invalid
            (
                '{"alg":"HS256","typ":"JWT"}.{"name":"Jon Doe"}.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
                False,
            ),
            # invalid json - invalid (caught by regex)
            (
                'bm90X3ZhbGlkX2pzb25fYXRfYWxs.bm90X3ZhbGlkX2pzb25fYXRfYWxs.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
                False,
            ),
            # missing claims - invalid
            ('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9', False),
            # totally not a jwt
            ('jwt', False),
            # invalid json with random bytes
            (
                'eyJhbasdGciOiJIUaddasdasfsasdasdzI1NiIasdsInR5cCI6IkpXVCasdJasd9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
                False,
            ),
            # invalid json in jwt header - invalid (caught by parsing)
            (
                'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
                False,
            ),
            # good by regex, but otherwise totally not JWT
            ('eyJAAAA.eyJBBB', False),
            ('eyJBB.eyJCC.eyJDDDD', False),
        ],
    )
    def test_analyze_line(self, payload, should_flag):
        logic = JwtTokenDetector()

        output = logic.analyze_line(payload, 1, 'mock_filename')
        assert len(output) == int(should_flag)
