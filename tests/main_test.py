from contextlib import contextmanager
from unittest import mock

import pytest

from simple_detect_secrets import VERSION
from simple_detect_secrets import main as main_module
from simple_detect_secrets.main import main
from simple_detect_secrets.plugins.common.util import import_plugins
from testing.factories import secrets_collection_factory
from testing.mocks import Any, mock_printer
from testing.util import uncolor


def get_list_of_plugins(include=None, exclude=None):
    """
    :type include: List[Dict[str, Any]]
    :type exclude: Iterable[str]
    :rtype: List[Dict[str, Any]]
    """
    included_plugins = []
    if include:
        included_plugins = [config['name'] for config in include]

    output = []
    for name, plugin in import_plugins().items():
        if name in included_plugins or exclude and name in exclude:
            continue

        payload = {
            'name': name,
        }
        payload.update(plugin.default_options)

        output.append(payload)

    if include:
        output.extend(include)

    return sorted(output, key=lambda x: x['name'])


def get_plugin_report(extra=None):
    """
    :type extra: Dict[str, str]
    """
    if not extra:  # pragma: no cover
        extra = {}

    longest_name_length = max([len(name) for name in import_plugins()])

    return (
        '\n'.join(
            sorted(
                [
                    '{name}: {result}'.format(
                        name=name + ' ' * (longest_name_length - len(name)),
                        result=extra.get(name, 'False'),
                    )
                    for name in import_plugins()
                ]
            ),
        )
        + '\n'
    )


class TestMain:
    """These are smoke tests for the console usage of simple_detect_secrets.
    Most of the functional test cases should be within their own module tests.
    """

    def test_scan_basic(self, mock_baseline_initialize):
        with mock_stdin():
            assert main([]) == 0

        mock_baseline_initialize.assert_called_once_with(
            plugins=Any(tuple),
            exclude_patterns=[],
            exclude_lines_regex=None,
            path=['.'],
            should_scan_all_files=False,
            word_list_file=None,
            word_list_hash=None,
        )

    def test_scan_with_rootdir(self, mock_baseline_initialize):
        with mock_stdin():
            assert main(['test_data']) == 0

        mock_baseline_initialize.assert_called_once_with(
            plugins=Any(tuple),
            exclude_patterns=[],
            exclude_lines_regex=None,
            path=['test_data'],
            should_scan_all_files=False,
            word_list_file=None,
            word_list_hash=None,
        )

    def test_update_writes_fresh_scan(self, mock_baseline_initialize):
        with mock.patch.object(main_module, 'write_baseline_to_file') as writer:
            assert main(['--update', 'output.json', '--hex-limit', '5']) == 0

        writer.assert_called_once()
        assert writer.call_args.kwargs['filename'] == 'output.json'
        payload = writer.call_args.kwargs['data']
        assert payload['results'] == {}
        assert payload['version'] == VERSION
        assert (
            next(
                plugin
                for plugin in payload['plugins_used']
                if plugin['name'] == 'HexHighEntropyString'
            )['hex_limit']
            == 5
        )

    def test_scan_with_exclude_args(self, mock_baseline_initialize):
        with mock_stdin():
            assert (
                main(
                    [
                        '--exclude',
                        'some_pattern_here',
                        '--exclude-lines',
                        'other_patt',
                    ],
                )
                == 0
            )

        mock_baseline_initialize.assert_called_once_with(
            plugins=Any(tuple),
            exclude_patterns=['some_pattern_here'],
            exclude_lines_regex='other_patt',
            path=['.'],
            should_scan_all_files=False,
            word_list_file=None,
            word_list_hash=None,
        )

    @pytest.mark.parametrize(
        'string, expected_base64_result, expected_hex_result',
        [
            (
                '012345678ab',
                'False (3.459)',
                'True  (3.459)',
            ),
            (
                'Benign',
                'False (2.252)',
                'False',
            ),
        ],
    )
    def test_scan_string_basic(
        self,
        mock_baseline_initialize,
        string,
        expected_base64_result,
        expected_hex_result,
    ):
        with (
            mock_stdin(
                string,
            ),
            mock_printer(
                main_module,
            ) as printer_shim,
        ):
            assert main(['--string']) == 0
            assert uncolor(printer_shim.message) == get_plugin_report(
                {
                    'Base64HighEntropyString': expected_base64_result,
                    'HexHighEntropyString': expected_hex_result,
                }
            )

        mock_baseline_initialize.assert_not_called()

    def test_scan_string_cli_overrides_stdin(self):
        with (
            mock_stdin(
                '012345678ab',
            ),
            mock_printer(
                main_module,
            ) as printer_shim,
        ):
            assert main(['--string', '012345']) == 0
            assert uncolor(printer_shim.message) == get_plugin_report(
                {
                    'Base64HighEntropyString': 'False (2.585)',
                    'HexHighEntropyString': 'False (2.121)',
                }
            )

    def test_scan_with_all_files_flag(self, mock_baseline_initialize):
        with mock_stdin():
            assert main(['--all-files']) == 0

        mock_baseline_initialize.assert_called_once_with(
            plugins=Any(tuple),
            exclude_patterns=[],
            exclude_lines_regex=None,
            path=['.'],
            should_scan_all_files=True,
            word_list_file=None,
            word_list_hash=None,
        )


@contextmanager
def mock_stdin(response=None):
    if not response:
        with mock.patch('simple_detect_secrets.main.sys') as m:
            m.stdin.isatty.return_value = True
            yield

    else:
        with mock.patch('simple_detect_secrets.main.sys') as m:
            m.stdin.isatty.return_value = False
            m.stdin.read.return_value = response
            yield


@pytest.fixture
def mock_baseline_initialize():
    def mock_initialize_function(plugins, exclude_patterns, *args, **kwargs):
        return secrets_collection_factory(
            plugins=plugins,
            exclude_files_regex=exclude_patterns,
        )

    with mock.patch(
        'simple_detect_secrets.main.baseline.initialize',
        side_effect=mock_initialize_function,
    ) as mock_initialize:
        yield mock_initialize
