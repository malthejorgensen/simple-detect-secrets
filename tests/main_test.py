import shlex
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
                        result='False' if name not in extra else extra[name],
                    )
                    for name in import_plugins()
                ]
            ),
        )
        + '\n'
    )


class TestMain:
    """These are smoke tests for the console usage of detect_secrets.
    Most of the functional test cases should be within their own module tests.
    """

    def test_scan_basic(self, mock_baseline_initialize):
        with mock_stdin():
            assert main(['scan']) == 0

        mock_baseline_initialize.assert_called_once_with(
            plugins=Any(tuple),
            exclude_files_regex=None,
            exclude_lines_regex=None,
            path='.',
            should_scan_all_files=False,
            word_list_file=None,
            word_list_hash=None,
        )

    def test_scan_with_rootdir(self, mock_baseline_initialize):
        with mock_stdin():
            assert main(['scan', 'test_data']) == 0

        mock_baseline_initialize.assert_called_once_with(
            plugins=Any(tuple),
            exclude_files_regex=None,
            exclude_lines_regex=None,
            path=['test_data'],
            should_scan_all_files=False,
            word_list_file=None,
            word_list_hash=None,
        )

    def test_scan_with_exclude_args(self, mock_baseline_initialize):
        with mock_stdin():
            assert (
                main(
                    ['scan', '--exclude-files', 'some_pattern_here', '--exclude-lines', 'other_patt'],
                )
                == 0
            )

        mock_baseline_initialize.assert_called_once_with(
            plugins=Any(tuple),
            exclude_files_regex='some_pattern_here',
            exclude_lines_regex='other_patt',
            path='.',
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
            assert main(['scan', '--string']) == 0
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
            assert main(['scan', '--string', '012345']) == 0
            assert uncolor(printer_shim.message) == get_plugin_report(
                {
                    'Base64HighEntropyString': 'False (2.585)',
                    'HexHighEntropyString': 'False (2.121)',
                }
            )

    def test_scan_with_all_files_flag(self, mock_baseline_initialize):
        with mock_stdin():
            assert main(['scan', '--all-files']) == 0

        mock_baseline_initialize.assert_called_once_with(
            plugins=Any(tuple),
            exclude_files_regex=None,
            exclude_lines_regex=None,
            path='.',
            should_scan_all_files=True,
            word_list_file=None,
            word_list_hash=None,
        )

    @pytest.mark.parametrize(
        'exclude_files_arg, expected_regex',
        [
            (
                '',
                '^old_baseline_file$',
            ),
            (
                '--exclude-files "secrets/.*"',
                'secrets/.*|^old_baseline_file$',
            ),
            (
                '--exclude-files "^old_baseline_file$"',
                '^old_baseline_file$',
            ),
        ],
    )
    def test_old_baseline_ignored_with_update_flag(
        self,
        mock_baseline_initialize,
        exclude_files_arg,
        expected_regex,
    ):
        with (
            mock_stdin(),
            mock.patch(
                'detect_secrets.main._read_from_file',
                return_value={},
            ),
            mock.patch(
                # We don't want to be creating a file during test
                'detect_secrets.main.write_baseline_to_file',
            ) as file_writer,
        ):
            assert (
                main(
                    shlex.split(
                        f'scan --update old_baseline_file {exclude_files_arg}',
                    ),
                )
                == 0
            )

            assert file_writer.call_args[1]['data']['exclude']['files'] == expected_regex

    @pytest.mark.parametrize(
        'plugins_used, plugins_overwriten, plugins_wrote',
        [
            (  # Remove some plugins from baseline
                [
                    {
                        'base64_limit': 4.5,
                        'name': 'Base64HighEntropyString',
                    },
                    {
                        'name': 'PrivateKeyDetector',
                    },
                ],
                '--no-base64-string-scan --no-keyword-scan',
                [
                    {
                        'name': 'PrivateKeyDetector',
                    },
                ],
            ),
            (  # All plugins
                [
                    {
                        'base64_limit': 1.5,
                        'name': 'Base64HighEntropyString',
                    },
                ],
                '--use-all-plugins',
                get_list_of_plugins(
                    include=[
                        {
                            'base64_limit': 1.5,
                            'name': 'Base64HighEntropyString',
                        },
                    ],
                ),
            ),
            (  # Remove some plugins from all plugins
                [
                    {
                        'base64_limit': 4.5,
                        'name': 'Base64HighEntropyString',
                    },
                ],
                '--use-all-plugins --no-base64-string-scan --no-private-key-scan',
                get_list_of_plugins(
                    exclude=(
                        'Base64HighEntropyString',
                        'PrivateKeyDetector',
                    ),
                ),
            ),
            (  # Use same plugin list from baseline
                [
                    {
                        'base64_limit': 3.5,
                        'name': 'Base64HighEntropyString',
                    },
                    {
                        'name': 'PrivateKeyDetector',
                    },
                ],
                '',
                [
                    {
                        'base64_limit': 3.5,
                        'name': 'Base64HighEntropyString',
                    },
                    {
                        'name': 'PrivateKeyDetector',
                    },
                ],
            ),
            (  # Overwrite base limit from CLI
                [
                    {
                        'base64_limit': 3.5,
                        'name': 'Base64HighEntropyString',
                    },
                    {
                        'name': 'PrivateKeyDetector',
                    },
                ],
                '--base64-limit=5.5',
                [
                    {
                        'base64_limit': 5.5,
                        'name': 'Base64HighEntropyString',
                    },
                    {
                        'name': 'PrivateKeyDetector',
                    },
                ],
            ),
            (  # Does not overwrite base limit from CLI if baseline not using the plugin
                [
                    {
                        'name': 'PrivateKeyDetector',
                    },
                ],
                '--base64-limit=4.5',
                [
                    {
                        'name': 'PrivateKeyDetector',
                    },
                ],
            ),
            (  # Use overwriten option from CLI only when using --use-all-plugins
                [
                    {
                        'base64_limit': 3.5,
                        'name': 'Base64HighEntropyString',
                    },
                    {
                        'name': 'PrivateKeyDetector',
                    },
                ],
                '--use-all-plugins --base64-limit=5.5 --no-hex-string-scan --no-keyword-scan',
                get_list_of_plugins(
                    include=[
                        {
                            'base64_limit': 5.5,
                            'name': 'Base64HighEntropyString',
                        },
                    ],
                    exclude=(
                        'HexHighEntropyString',
                        'KeywordDetector',
                    ),
                ),
            ),
            (  # Use plugin limit from baseline when using --use-all-plugins and no input limit
                [
                    {
                        'base64_limit': 2.5,
                        'name': 'Base64HighEntropyString',
                    },
                    {
                        'name': 'PrivateKeyDetector',
                    },
                ],
                '--use-all-plugins --no-hex-string-scan --no-keyword-scan',
                get_list_of_plugins(
                    include=[
                        {
                            'base64_limit': 2.5,
                            'name': 'Base64HighEntropyString',
                        },
                    ],
                    exclude=(
                        'HexHighEntropyString',
                        'KeywordDetector',
                    ),
                ),
            ),
        ],
    )
    def test_plugin_from_old_baseline_respected_with_update_flag(
        self,
        mock_baseline_initialize,
        plugins_used,
        plugins_overwriten,
        plugins_wrote,
    ):
        with (
            mock_stdin(),
            mock.patch(
                'detect_secrets.main._read_from_file',
                return_value={
                    'plugins_used': plugins_used,
                    'results': {},
                    'version': VERSION,
                    'exclude': {
                        'files': '',
                        'lines': '',
                    },
                },
            ),
            mock.patch(
                # We don't want to be creating a file during test
                'detect_secrets.main.write_baseline_to_file',
            ) as file_writer,
        ):
            assert (
                main(
                    shlex.split(
                        f'scan --update old_baseline_file {plugins_overwriten}',
                    ),
                )
                == 0
            )

            assert file_writer.call_args[1]['data']['plugins_used'] == plugins_wrote


@contextmanager
def mock_stdin(response=None):
    if not response:
        with mock.patch('detect_secrets.main.sys') as m:
            m.stdin.isatty.return_value = True
            yield

    else:
        with mock.patch('detect_secrets.main.sys') as m:
            m.stdin.isatty.return_value = False
            m.stdin.read.return_value = response
            yield


@pytest.fixture
def mock_baseline_initialize():
    def mock_initialize_function(plugins, exclude_files_regex, *args, **kwargs):
        return secrets_collection_factory(
            plugins=plugins,
            exclude_files_regex=exclude_files_regex,
        )

    with mock.patch(
        'detect_secrets.main.baseline.initialize',
        side_effect=mock_initialize_function,
    ) as mock_initialize:
        yield mock_initialize
