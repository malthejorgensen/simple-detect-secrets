import argparse

from .. import VERSION
from ..plugins.common.util import import_plugins


def entropy_limit(value):
    value = float(value)
    if not 0 <= value <= 8:
        raise argparse.ArgumentTypeError('Entropy limits must be between 0.0 and 8.0.')
    return value


def create_parser(*, pre_commit=False):
    parser = argparse.ArgumentParser(
        prog='simple-detect-secrets-hook' if pre_commit else 'simple-detect-secrets',
        description='Find potential secrets in files. Scanning is the default action.',
    )
    parser.add_argument('--version', action='version', version=VERSION)
    parser.add_argument('-v', '--verbose', action='count', default=0)
    parser.add_argument('--exclude-lines', help='Ignore lines matching this regular expression.')
    parser.add_argument('--word-list', dest='word_list_file', help='Ignore words from this file.')
    parser.add_argument('--use-all-plugins', action='store_true', help='Use all detectors.')
    parser.add_argument(
        '-n',
        '--no-verify',
        action='store_true',
        default=True,
        help='Retained for compatibility; scans always run without network verification.',
    )
    if pre_commit:
        parser.add_argument('filenames', nargs='*', help='Files to check.')
        parser.add_argument('--baseline', default='', help='Baseline containing ignored secrets.')
    else:
        parser.add_argument(
            'path', nargs='*', default=['.'], help='Files or directories (default: .).'
        )
        parser.add_argument(
            '--exclude-files', help='Ignore paths matching this regular expression.'
        )
        parser.add_argument(
            '--update', dest='import_filename', metavar='FILE', help='Write scan results to FILE.'
        )
        parser.add_argument(
            '--all-files',
            action='store_true',
            help='Include untracked and ignored files in Git repositories.',
        )
        parser.add_argument(
            '--string', nargs='?', const=True, help='Scan a string, or read one from stdin.'
        )

    group = parser.add_argument_group(
        'detectors', 'All detectors are enabled unless explicitly disabled.'
    )
    group.add_argument(
        '--base64-limit', type=entropy_limit, help='Base64 entropy threshold (default: 4.5).'
    )
    group.add_argument(
        '--hex-limit', type=entropy_limit, help='Hex entropy threshold (default: 3.0).'
    )
    group.add_argument(
        '--keyword-exclude', help='Ignore keyword matches matching this regular expression.'
    )
    for plugin in import_plugins().values():
        group.add_argument(
            '--' + plugin.disable_flag_text,
            action='store_true',
            help='Disable ' + plugin.secret_type + ' detection.',
        )
    return parser


def parse_args(argv=None, *, pre_commit=False):
    args = create_parser(pre_commit=pre_commit).parse_args(argv)
    args.plugins = {}
    args.is_using_default_value = {}
    for name, plugin in import_plugins().items():
        disabled = vars(args).pop(plugin.disable_flag_text.replace('-', '_'))
        if disabled:
            continue
        options = {}
        for option, default in plugin.default_options.items():
            value = vars(args).pop(option)
            options[option] = default if value is None else value
            args.is_using_default_value[option] = value is None
        args.plugins[name] = options
    return args
