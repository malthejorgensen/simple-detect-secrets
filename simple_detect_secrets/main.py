#!/usr/bin/env -S uv run --script

import json
import sys

from .core import baseline
from .core.common import write_baseline_to_file
from .core.log import log
from .core.profiling import PluginProfiler
from .core.secrets_collection import SecretsCollection
from .core.usage import parse_args
from .plugins.common import initialize
from .util import build_automaton


def main(argv=None):

    args = parse_args(argv)
    if args.verbose:  # pragma: no cover
        log.set_debug_level(args.verbose)

    automaton = None
    word_list_hash = None
    if args.word_list_file:
        automaton, word_list_hash = build_automaton(args.word_list_file)

    # Plugins are *always* rescanned with fresh settings, because
    # we want to get the latest updates.
    plugins = initialize.from_config(
        args.plugins,
        exclude_lines_regex=args.exclude_lines,
        automaton=automaton,
    )
    profiler = PluginProfiler(plugins) if args.profile else None
    if args.string:
        line = args.string

        if isinstance(args.string, bool):
            line = sys.stdin.read().splitlines()[0]

        _scan_string(line, plugins, profiler)

    else:
        baseline_dict = _perform_scan(
            args,
            plugins,
            automaton,
            word_list_hash,
            profiler,
        )

        if args.import_filename:
            write_baseline_to_file(
                filename=args.import_filename,
                data=baseline_dict,
            )
        else:
            if not baseline_dict['results']:
                print('No secrets found.', file=sys.stderr)
            else:
                print(baseline.format_baseline_for_output(baseline_dict))

    if profiler is not None:
        sys.stdout.flush()
        profiler.report()

    return 0


def _get_plugins_from_baseline(old_baseline):
    plugins = []
    if old_baseline and 'plugins_used' in old_baseline:
        secrets_collection = SecretsCollection.load_baseline_from_dict(old_baseline)
        plugins = secrets_collection.plugins
    return plugins


def _scan_string(line, plugins, profiler=None):
    longest_plugin_name_length = max(
        (len(x.__class__.__name__) for x in plugins),
    )

    output = [
        ('{:%d}: {}' % longest_plugin_name_length).format(
            plugin.__class__.__name__,
            (
                plugin.adhoc_scan(line)
                if profiler is None
                else profiler.call(plugin, plugin.adhoc_scan, line)
            ),
        )
        for plugin in plugins
    ]

    print('\n'.join(sorted(output)))


def _perform_scan(args, plugins, automaton, word_list_hash, profiler=None):
    """
    :param args: output of `argparse.ArgumentParser.parse_args`
    :param plugins: tuple of initialized plugins

    :type automaton: ahocorasick.Automaton|None
    :param automaton: optional automaton for ignoring certain words.

    :type word_list_hash: str|None
    :param word_list_hash: optional iterated sha1 hash of the words in the word list.

    :rtype: dict
    """
    profiling_options = {'profiler': profiler} if profiler is not None else {}
    new_baseline = baseline.initialize(
        plugins=plugins,
        exclude_patterns=args.exclude,
        exclude_lines_regex=args.exclude_lines,
        word_list_file=args.word_list_file,
        word_list_hash=word_list_hash,
        path=args.path,
        should_scan_all_files=args.all_files,
        **profiling_options,
    ).format_for_baseline_output()

    return new_baseline


def _read_from_file(filename):  # pragma: no cover
    """Used for mocking."""
    with open(filename) as f:
        return json.loads(f.read())


if __name__ == '__main__':
    sys.exit(main())
